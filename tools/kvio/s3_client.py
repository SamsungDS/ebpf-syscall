#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""S3 operations: capture them at the SDK, replay them at an endpoint.

The ``s3`` calls of ``kvio.workload.v3`` are the object API as an
application sees it: PUT, GET (whole or ranged), HEAD, LIST with a prefix,
DELETE, and the multipart lifecycle (create, part, complete, abort).

* :class:`RecordingS3` wraps a boto3 client for an application under our
  control: every call is performed by the real SDK and recorded with the
  logical operation, the key's synthetic name, sizes, the outcome the SDK
  reported and the timestamps.  A GET is complete when its body has been
  consumed, not when headers arrived.  Multipart parts keep their upload
  as a parent; the upload id the endpoint returned is recorded as opaque
  and never replayed: replay rebinds it to what the target returns.
  Source keys never appear; a private mapping keeps them.
* :class:`S3Backend` replays against a configured endpoint through a
  pinned SDK.  The SDK's transfer helper is not used, so one call is one
  request; retries are the SDK's own and are reported as attempts.
* :class:`FakeS3` is an in-memory bucket for contract tests.

Outcomes: ``NoSuchKey``/404 is ``miss``, 403 is ``denied``, a timeout with
an unknown server outcome is ``timeout`` and stays unknown rather than
being retried into a different truth; every other client error is
``error``.  ``CompleteMultipartUpload`` can carry an error inside a 200
response, so its body, not its status, decides.
"""
from __future__ import annotations

import errno
import hashlib
import json
import time

import content_profile
import workload3


def sdk_revision():
    try:
        import boto3, botocore
        return f"boto3 {boto3.__version__} botocore {botocore.__version__}"
    except ImportError:
        return "boto3 not installed"


class Result:
    __slots__ = ("outcome", "code", "bytes", "meta", "upload")

    def __init__(self, outcome, code="", nbytes=0, meta=None, upload=None):
        self.outcome, self.code, self.bytes, self.meta, self.upload = outcome, code, nbytes, meta or {}, upload

    def as_dict(self):
        return {"outcome": self.outcome, "code": self.code, "bytes": self.bytes, "meta": self.meta, "upload": self.upload}


def _outcome_of_client_error(e):
    code = e.response.get("Error", {}).get("Code", "")
    status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    if code in ("NoSuchKey", "NotFound", "NoSuchUpload", "404") or status == 404:
        return "miss", code or str(status)
    if code in ("AccessDenied", "403") or status == 403:
        return "denied", code or str(status)
    if code in ("SlowDown", "RequestTimeout", "503"):
        return "timeout", code
    return "error", code or str(status)


# --------------------------------------------------------------- capture
class RecordingS3:
    """Perform S3 calls through a real boto3 client and record them."""

    def __init__(self, client, bucket, events_path, *, stream="app", clock=time.monotonic_ns):
        self.c = client
        self.bucket = bucket
        self.stream = stream
        self.clock = clock
        self._fh = open(events_path, "w", encoding="utf-8")
        self._seq = 0
        self._keys = {}          # real key -> synthetic key
        self._uploads = {}       # real upload id -> synthetic upload id
        self.mapping = {"keys": self._keys, "uploads": self._uploads}
        self._put({"ev": "start", "schema": "kvio.s3-capture.v1", "stream": stream,
                   "sdk": sdk_revision(), "bucket_digest": hashlib.sha256(bucket.encode()).hexdigest(),
                   "clock": {"domain": "CLOCK_MONOTONIC", "unit": "ns"}})

    def _key(self, real):
        """Synthetic key with one synthetic component per real component, so
        prefix structure and listing locality survive while names do not.
        A prefix ending in "/" keeps its trailing slash and names no entry."""
        if real not in self._keys:
            trailing = real.endswith("/")
            parts = [p for p in real.split("/") if p]
            syn = []
            for i, part in enumerate(parts):
                prefix = "/".join(parts[:i])
                table = self.mapping.setdefault("components", {}).setdefault(prefix, {})
                if part not in table:
                    table[part] = f"k{len(table)}"
                syn.append(table[part])
            self._keys[real] = "/".join(syn) + ("/" if trailing else "")
        return self._keys[real]

    def _upload(self, real):
        if real not in self._uploads:
            self._uploads[real] = f"u{len(self._uploads)}"
        return self._uploads[real]

    def _put(self, rec):
        self._seq += 1
        rec["producer_seq"] = self._seq
        self._fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def _record(self, call, args, begin, res):
        self._put({"ev": "op", "call": call, "args": args, "begin_ns": begin, "end_ns": self.clock(),
                   "result": res.as_dict(), "stream": self.stream})
        return res

    def _call(self, call, args, fn):
        from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError
        begin = self.clock()
        try:
            return self._record(call, args, begin, fn())
        except ClientError as e:
            oc, code = _outcome_of_client_error(e)
            self._record(call, args, begin, Result(oc, code)); raise
        except (EndpointConnectionError, ReadTimeoutError) as e:
            self._record(call, args, begin, Result("timeout", type(e).__name__)); raise

    def put(self, key, body):
        def fn():
            self.c.put_object(Bucket=self.bucket, Key=key, Body=body)
            return Result("success", "200", len(body))
        return self._call("put", {"key": self._key(key), "size": len(body)}, fn)

    def get(self, key, offset=None, length=None):
        args = {"key": self._key(key)}
        if offset is not None:
            args["offset"], args["length"] = offset, length
        out = []
        def fn():
            kw = {"Bucket": self.bucket, "Key": key}
            if offset is not None:
                kw["Range"] = f"bytes={offset}-{offset + length - 1}"
            r = self.c.get_object(**kw)
            data = r["Body"].read()               # complete when the body is consumed
            out.append(data)
            return Result("success", str(r["ResponseMetadata"]["HTTPStatusCode"]), len(data))
        self._call("get", args, fn)
        return out[0]

    def head(self, key):
        def fn():
            r = self.c.head_object(Bucket=self.bucket, Key=key)
            return Result("success", "200", 0, {"size": r["ContentLength"]})
        return self._call("head", {"key": self._key(key)}, fn)

    def list(self, prefix):
        def fn():
            n, pages, token = 0, 0, None
            while True:
                kw = {"Bucket": self.bucket, "Prefix": prefix}
                if token:
                    kw["ContinuationToken"] = token
                r = self.c.list_objects_v2(**kw)
                pages += 1
                n += r.get("KeyCount", len(r.get("Contents", [])))
                if not r.get("IsTruncated"):
                    break
                token = r["NextContinuationToken"]
            return Result("success", "200", 0, {"count": n, "pages": pages})
        return self._call("list", {"prefix": self._key(prefix) if prefix else ""}, fn)

    def delete(self, key):
        def fn():
            self.c.delete_object(Bucket=self.bucket, Key=key)
            return Result("success", "204")
        return self._call("delete", {"key": self._key(key)}, fn)

    def mpu_create(self, key):
        out = []
        def fn():
            r = self.c.create_multipart_upload(Bucket=self.bucket, Key=key)
            out.append(r["UploadId"])
            return Result("success", "200", 0, {}, self._upload(r["UploadId"]))
        self._call("mpu_create", {"key": self._key(key), "upload": None}, fn)
        # bind the synthetic upload id into the recorded args after the fact
        return out[0]

    def mpu_part(self, key, upload_id, part, body):
        out = []
        def fn():
            r = self.c.upload_part(Bucket=self.bucket, Key=key, UploadId=upload_id, PartNumber=part, Body=body)
            out.append(r["ETag"])
            return Result("success", "200", len(body))
        self._call("mpu_part", {"key": self._key(key), "upload": self._upload(upload_id), "part": part, "size": len(body)}, fn)
        return out[0]

    def mpu_complete(self, key, upload_id, parts):
        def fn():
            r = self.c.complete_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id,
                                                 MultipartUpload={"Parts": [{"PartNumber": p, "ETag": e} for p, e in parts]})
            if "Error" in r:                          # an error can ride inside HTTP 200
                return Result("error", r["Error"].get("Code", "InBody"))
            return Result("success", "200")
        return self._call("mpu_complete", {"key": self._key(key), "upload": self._upload(upload_id)}, fn)

    def mpu_abort(self, key, upload_id):
        def fn():
            self.c.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)
            return Result("success", "204")
        return self._call("mpu_abort", {"key": self._key(key), "upload": self._upload(upload_id)}, fn)

    def close_capture(self):
        self._put({"ev": "end"})
        self._fh.close()
        return {"events": self._seq}


def normalize_s3_capture(events_path, *, engine=None):
    events = [json.loads(l) for l in open(events_path, encoding="utf-8") if l.strip()]
    if not events or events[0].get("ev") != "start":
        raise workload3.Workload3Error("capture must begin with a start event")
    start = events[0]
    notes = [] if any(e.get("ev") == "end" for e in events) else ["no end marker"]
    wl = workload3.new_workload(capture_level="api", mapping_method="declared", timing_model="captured",
                                release_provenance="observed_submission",
                                engine=engine or {"family": "s3", "name": "application-sdk", "revision": start.get("sdk", "unknown")},
                                completeness="complete" if not notes else "partial", notes=notes,
                                source={"schema": start.get("schema"), "bucket_digest": start.get("bucket_digest")})
    sidecar, prev, n = [], {}, 0
    creates = {}     # synthetic upload -> op_id of its create, for parent edges
    for e in events:
        if e.get("ev") != "op":
            continue
        n += 1
        op_id = f"s{n}"
        args = dict(e["args"])
        res = e["result"]
        if e["call"] == "mpu_create":
            args["upload"] = res.get("upload") or f"failed-{op_id}"
            creates[args["upload"]] = op_id
        deps = [{"op": prev[e["stream"]], "kind": "program"}] if e["stream"] in prev else []
        if e["call"] in ("mpu_part", "mpu_complete", "mpu_abort") and args.get("upload") in creates \
                and creates[args["upload"]] != (prev.get(e["stream"])):
            deps.append({"op": creates[args["upload"]], "kind": "sync"})
        exp = {"outcome": res["outcome"]}
        if res.get("bytes"):
            exp["bytes"] = res["bytes"]
        for k in ("size", "count"):
            if k in res.get("meta", {}):
                exp[k] = res["meta"][k]
        workload3.add_op(wl, op_id=op_id, family="s3", call=e["call"], stream=e["stream"], deps=deps,
                         release_ns=e["begin_ns"], expected=exp, **args)
        prev[e["stream"]] = op_id
        sidecar.append({"op_id": op_id, "begin_ns": e["begin_ns"], "end_ns": e["end_ns"],
                        "outcome": res["outcome"], "code": res.get("code", ""), "bytes": res.get("bytes", 0)})
    side = "".join(json.dumps(s, sort_keys=True) + "\n" for s in sidecar).encode()
    wl["timing"] = {"sidecar": "timing.jsonl", "sidecar_sha256": hashlib.sha256(side).hexdigest()}
    wl["health"] = {"events": len(events), "operations": n}
    workload3.validate_workload(wl)
    return wl, side


# ---------------------------------------------------------------- replay
class S3Backend:
    """Replay s3 calls at an endpoint through a pinned boto3 client."""

    provenance_modules = ("boto3", "botocore")

    def __init__(self, cfg, *, profile="incompressible"):
        import boto3
        from botocore.config import Config
        self.cfg = dict(cfg)
        self.bucket = cfg["bucket"]
        self.prefix = cfg.get("prefix", "kvio/")
        self.profile = content_profile.parse_profile(profile) if isinstance(profile, str) else profile
        self.uploads = {}       # synthetic upload id -> real upload id
        self.etags = {}         # (synthetic upload, part) -> etag
        self.c = boto3.client("s3", endpoint_url=cfg.get("endpoint"), region_name=cfg.get("region", "us-east-1"),
                              aws_access_key_id=cfg.get("access_key"), aws_secret_access_key=cfg.get("secret_key"),
                              config=Config(retries={"max_attempts": int(cfg.get("max_attempts", 3)), "mode": "standard"},
                                            s3={"addressing_style": cfg.get("addressing", "path")},
                                            connect_timeout=int(cfg.get("connect_timeout", 5)),
                                            read_timeout=int(cfg.get("read_timeout", 60))))

    @classmethod
    def probe(cls):
        import boto3  # noqa: F401
        return cls.__new__(cls)

    def doctor(self):
        return "ok (needs endpoint, bucket and credentials in the target config)"

    def describe(self):
        return {"endpoint": self.cfg.get("endpoint"), "bucket_digest": hashlib.sha256(self.bucket.encode()).hexdigest(),
                "prefix": self.prefix, "addressing": self.cfg.get("addressing", "path"),
                "max_attempts": self.cfg.get("max_attempts", 3)}

    def _k(self, key):
        return self.prefix + key

    def initialize(self, workload):
        ns = workload["namespace"]
        for e in ns["entries"]:
            node = ns["nodes"][e["node"]]
            if node["kind"] == "object":
                self.c.put_object(Bucket=self.bucket, Key=self._k(e["path"]),
                                  Body=content_profile.content(self.profile, e["node"], 0, node.get("size", 0)))

    def content(self, key, offset, length):
        return content_profile.content(self.profile, key, offset, length)

    def perform(self, op, ctx=None):
        from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError
        a = op["args"]; call = op["call"]
        try:
            if call == "put":
                self.c.put_object(Bucket=self.bucket, Key=self._k(a["key"]), Body=self.content(a["key"], 0, a["size"]))
                return Result("success", "200", a["size"])
            if call == "get":
                kw = {"Bucket": self.bucket, "Key": self._k(a["key"])}
                off = a.get("offset")
                if off is not None:
                    kw["Range"] = f"bytes={off}-{off + a['length'] - 1}"
                data = self.c.get_object(**kw)["Body"].read()
                if data != self.content(a["key"], off or 0, len(data)):
                    return Result("error", "content", len(data), {"detail": "content mismatch"})
                return Result("success", "200", len(data))
            if call == "head":
                r = self.c.head_object(Bucket=self.bucket, Key=self._k(a["key"]))
                return Result("success", "200", 0, {"size": r["ContentLength"]})
            if call == "list":
                n, pages, token = 0, 0, None
                while True:
                    kw = {"Bucket": self.bucket, "Prefix": self._k(a["prefix"])}
                    if token:
                        kw["ContinuationToken"] = token
                    r = self.c.list_objects_v2(**kw); pages += 1
                    n += r.get("KeyCount", len(r.get("Contents", [])))
                    if not r.get("IsTruncated"):
                        break
                    token = r["NextContinuationToken"]
                return Result("success", "200", 0, {"count": n, "pages": pages})
            if call == "delete":
                self.c.delete_object(Bucket=self.bucket, Key=self._k(a["key"])); return Result("success", "204")
            if call == "mpu_create":
                r = self.c.create_multipart_upload(Bucket=self.bucket, Key=self._k(a["key"]))
                self.uploads[a["upload"]] = r["UploadId"]        # rebound, never copied from the source
                return Result("success", "200", 0, {}, a["upload"])
            if call == "mpu_part":
                up = self.uploads[a["upload"]]
                body = self.content(f"{a['key']}#{a['part']}", 0, a["size"])
                r = self.c.upload_part(Bucket=self.bucket, Key=self._k(a["key"]), UploadId=up, PartNumber=a["part"], Body=body)
                self.etags[(a["upload"], a["part"])] = r["ETag"]
                return Result("success", "200", a["size"])
            if call == "mpu_complete":
                up = self.uploads[a["upload"]]
                parts = sorted((p, e) for (u, p), e in self.etags.items() if u == a["upload"])
                r = self.c.complete_multipart_upload(Bucket=self.bucket, Key=self._k(a["key"]), UploadId=up,
                                                     MultipartUpload={"Parts": [{"PartNumber": p, "ETag": e} for p, e in parts]})
                if "Error" in r:
                    return Result("error", r["Error"].get("Code", "InBody"))
                return Result("success", "200")
            if call == "mpu_abort":
                self.c.abort_multipart_upload(Bucket=self.bucket, Key=self._k(a["key"]), UploadId=self.uploads[a["upload"]])
                return Result("success", "204")
        except ClientError as e:
            oc, code = _outcome_of_client_error(e)
            return Result(oc, code)
        except (EndpointConnectionError, ReadTimeoutError) as e:
            return Result("timeout", type(e).__name__)
        except KeyError as e:
            return Result("error", "unbound", 0, {"detail": f"no target binding for {e}"})
        return Result("error", "unsupported", 0, {"detail": f"unsupported call {call}"})

    def final_state(self):
        keys = []
        token = None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": self.prefix}
            if token:
                kw["ContinuationToken"] = token
            r = self.c.list_objects_v2(**kw)
            keys += [(o["Key"][len(self.prefix):], o["Size"]) for o in r.get("Contents", [])]
            if not r.get("IsTruncated"):
                break
            token = r["NextContinuationToken"]
        keys.sort()
        return {"entries": keys, "sha256": hashlib.sha256(json.dumps(keys).encode()).hexdigest()}

    def cleanup(self):
        """Remove only what this run put under its prefix."""
        for key, _ in self.final_state()["entries"]:
            self.c.delete_object(Bucket=self.bucket, Key=self._k(key))

    def close(self):
        pass


class FakeS3(S3Backend):
    """In-memory bucket with the same call set, for contract tests."""

    provenance_modules = ()

    def __init__(self, *, profile="incompressible", fail=None, page=1000):
        self.profile = content_profile.parse_profile(profile)
        self.fail = fail or {}
        self.objects = {}
        self.mpu = {}          # synthetic upload -> {part: bytes}
        self.page = page
        self.uploads = {}

    def doctor(self):
        return "ok"

    def describe(self):
        return {"endpoint": "memory"}

    def initialize(self, workload):
        ns = workload["namespace"]
        for e in ns["entries"]:
            node = ns["nodes"][e["node"]]
            if node["kind"] == "object":
                self.objects[e["path"]] = content_profile.content(self.profile, e["node"], 0, node.get("size", 0))

    def perform(self, op, ctx=None):
        forced = self.fail.get(op["op_id"])
        if forced:
            return Result(forced, "injected", 0, {"detail": "injected"})
        a = op["args"]; call = op["call"]
        if call == "put":
            self.objects[a["key"]] = self.content(a["key"], 0, a["size"]); return Result("success", "200", a["size"])
        if call == "get":
            if a["key"] not in self.objects:
                return Result("miss", "NoSuchKey")
            data = self.objects[a["key"]]
            off = a.get("offset")
            if off is not None:
                data = data[off:off + a["length"]]
            if data != self.content(a["key"], off or 0, len(data)):
                return Result("error", "content", len(data), {"detail": "content mismatch"})
            return Result("success", "200", len(data))
        if call == "head":
            if a["key"] not in self.objects:
                return Result("miss", "NotFound")
            return Result("success", "200", 0, {"size": len(self.objects[a["key"]])})
        if call == "list":
            keys = sorted(k for k in self.objects if k.startswith(a["prefix"]))
            return Result("success", "200", 0, {"count": len(keys), "pages": max(1, -(-len(keys) // self.page))})
        if call == "delete":
            self.objects.pop(a["key"], None); return Result("success", "204")     # S3 delete of a missing key succeeds
        if call == "mpu_create":
            self.mpu[a["upload"]] = {}; self.uploads[a["upload"]] = a["upload"]; return Result("success", "200", 0, {}, a["upload"])
        if call == "mpu_part":
            if a["upload"] not in self.mpu:
                return Result("miss", "NoSuchUpload")
            self.mpu[a["upload"]][a["part"]] = self.content(f"{a['key']}#{a['part']}", 0, a["size"]); return Result("success", "200", a["size"])
        if call == "mpu_complete":
            parts = self.mpu.pop(a["upload"], None)
            if parts is None:
                return Result("miss", "NoSuchUpload")
            self.objects[a["key"]] = b"".join(parts[p] for p in sorted(parts)); return Result("success", "200")
        if call == "mpu_abort":
            if self.mpu.pop(a["upload"], None) is None:
                return Result("miss", "NoSuchUpload")
            return Result("success", "204")
        return Result("error", "unsupported", 0, {"detail": f"unsupported call {call}"})

    def final_state(self):
        keys = sorted((k, len(v)) for k, v in self.objects.items())
        return {"entries": keys, "sha256": hashlib.sha256(json.dumps(keys).encode()).hexdigest()}

    def cleanup(self):
        self.objects.clear()

    def close(self):
        pass
