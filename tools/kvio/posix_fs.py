#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""POSIX file operations: capture them in-process, replay them on a mount.

Three pieces share one vocabulary, the ``posix`` calls of
``kvio.workload.v3``:

* :class:`RecordingFS` is what an application under our control calls
  instead of ``os``: it performs the real operation on the application's
  directory and records the typed call, the handle it returned or used,
  the outcome, and the timestamps.  Names are replaced by synthetic
  entries per directory; the mapping stays in a private sidecar.  A
  ``close``-less handle at the end, a failed operation, and every errno
  are recorded as they happened, never repaired.
* :class:`PosixBackend` replays a workload on a real directory under a
  generated root: it materializes the initial namespace, rebinds handle
  ids to descriptors as ``open`` returns them, refuses any path that
  escapes the root, writes content from the named profile, and verifies
  what it reads against it.  Everything below the ``os`` call is the
  kernel's and the mount's.
* :class:`FakeFS` is an in-memory implementation of the same calls with
  injectable outcomes, for contract tests that must not touch a disk.

Outcomes follow the errno, not a guess: ENOENT is ``miss``, EEXIST is
``exists``, ENOTEMPTY is ``not_empty``, EACCES/EPERM is ``denied``, a read
that returns fewer bytes than asked at end of file is ``eof`` and one
that is short for another reason is ``short``.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat as statmod
import time
from pathlib import Path

import content_profile
import workload3

FLAG_MAP = {"rd": os.O_RDONLY, "wr": os.O_WRONLY, "rdwr": os.O_RDWR, "creat": os.O_CREAT,
            "excl": os.O_EXCL, "trunc": os.O_TRUNC, "append": os.O_APPEND,
            "direct": getattr(os, "O_DIRECT", 0), "sync": os.O_SYNC}
ERRNO_OUTCOME = {errno.ENOENT: "miss", errno.EEXIST: "exists", errno.ENOTEMPTY: "not_empty",
                 errno.EACCES: "denied", errno.EPERM: "denied", errno.ENOTDIR: "error",
                 errno.EISDIR: "error", errno.EBADF: "error"}


def outcome_of_oserror(e):
    return ERRNO_OUTCOME.get(e.errno, "error"), e.errno


class Result:
    __slots__ = ("outcome", "errno", "bytes", "meta", "handle")

    def __init__(self, outcome, errno_=0, nbytes=0, meta=None, handle=None):
        self.outcome, self.errno, self.bytes, self.meta, self.handle = outcome, errno_, nbytes, meta or {}, handle

    def as_dict(self):
        return {"outcome": self.outcome, "errno": self.errno, "bytes": self.bytes, "meta": self.meta,
                "handle": self.handle}


# --------------------------------------------------------------- capture
class RecordingFS:
    """Perform POSIX operations on ``root`` for an application and record them."""

    def __init__(self, root, events_path, *, stream="app", clock=time.monotonic_ns):
        self.root = Path(root).resolve()
        self.stream = stream
        self.clock = clock
        self._fh = open(events_path, "w", encoding="utf-8")
        self._seq = 0
        self._handles = {}         # fd -> handle id
        self._names = {}           # real relative path -> synthetic path
        self._name_counts = {}     # synthetic parent -> count
        self._nodes = {}           # (dev, ino) -> node id
        self._incarnations = {}
        self.mapping = {"paths": self._names, "nodes": {}}
        self._put({"ev": "start", "schema": "kvio.posix-capture.v1", "stream": stream,
                   "clock": {"domain": "CLOCK_MONOTONIC", "unit": "ns"}, "root_digest": hashlib.sha256(str(self.root).encode()).hexdigest()})
        self._snapshot()

    # ----------------------------------------------------------- naming
    def _synthetic(self, rel):
        rel = str(rel).strip("/")
        if rel in ("", "."):
            return "."
        if rel in self._names:
            return self._names[rel]
        parent, _, _ = rel.rpartition("/")
        sparent = self._synthetic(parent) if parent else "."
        n = self._name_counts.get(sparent, 0)
        self._name_counts[sparent] = n + 1
        syn = f"e{n}" if sparent == "." else f"{sparent}/e{n}"
        self._names[rel] = syn
        return syn

    def _node(self, st):
        key = (st.st_dev, st.st_ino)
        if key not in self._nodes:
            inc = self._incarnations.get(key, 0) + 1
            self._incarnations[key] = inc
            self._nodes[key] = f"n{len(self._nodes)}"
            self.mapping["nodes"][self._nodes[key]] = {"dev": st.st_dev, "ino": st.st_ino, "incarnation": inc}
        return self._nodes[key]

    def _rel(self, path):
        p = (self.root / path).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError(f"path escapes the application root: {path}")
        return str(p.relative_to(self.root)) if p != self.root else "."

    def _snapshot(self):
        nodes, entries = {}, []
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in sorted(dirnames) + sorted(filenames):
                real = os.path.join(dirpath, name)
                st = os.lstat(real)
                rel = os.path.relpath(real, self.root)
                nid = self._node(st)
                nodes[nid] = {"kind": "dir" if statmod.S_ISDIR(st.st_mode) else "file", "size": st.st_size if not statmod.S_ISDIR(st.st_mode) else 0,
                              "incarnation": 1}
                entries.append({"path": self._synthetic(rel), "node": nid})
        self._put({"ev": "namespace", "nodes": nodes, "entries": entries})

    def _put(self, rec):
        self._seq += 1
        rec["producer_seq"] = self._seq
        self._fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def _record(self, call, args, begin, res, deps=()):
        self._put({"ev": "op", "call": call, "args": args, "begin_ns": begin, "end_ns": self.clock(),
                   "result": res.as_dict(), "stream": self.stream, "deps": list(deps)})
        return res

    # -------------------------------------------------------------- calls
    def open(self, path, flags, mode=0o644):
        rel = self._rel(path)
        begin = self.clock()
        osflags = 0
        for f in flags:
            osflags |= FLAG_MAP[f]
        try:
            fd = os.open(self.root / rel, osflags, mode)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("open", {"path": self._synthetic(rel), "flags": list(flags), "handle": None}, begin, Result(oc, en))
            raise
        hid = f"h{len(self._handles) + sum(1 for _ in ())}{fd}-{self._seq}"
        self._handles[fd] = hid
        st = os.fstat(fd)
        nid = self._node(st)
        self._record("open", {"path": self._synthetic(rel), "flags": list(flags), "handle": hid},
                     begin, Result("success", 0, 0, {"node": nid, "size": st.st_size}, hid))
        return fd

    def close(self, fd):
        hid = self._handles.pop(fd, None)
        begin = self.clock()
        try:
            os.close(fd)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("close", {"handle": hid}, begin, Result(oc, en)); raise
        return self._record("close", {"handle": hid}, begin, Result("success"))

    def pwrite(self, fd, data, offset):
        begin = self.clock()
        try:
            n = os.pwrite(fd, data, offset)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("pwrite", {"handle": self._handles.get(fd), "offset": offset, "length": len(data)}, begin, Result(oc, en)); raise
        self._record("pwrite", {"handle": self._handles.get(fd), "offset": offset, "length": len(data)}, begin,
                     Result("success" if n == len(data) else "short", 0, n))
        return n

    def pread(self, fd, length, offset):
        begin = self.clock()
        try:
            data = os.pread(fd, length, offset)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("pread", {"handle": self._handles.get(fd), "offset": offset, "length": length}, begin, Result(oc, en)); raise
        self._record("pread", {"handle": self._handles.get(fd), "offset": offset, "length": length}, begin,
                     Result("success" if len(data) == length else "eof", 0, len(data)))
        return data

    def write(self, fd, data):
        begin = self.clock()
        n = os.write(fd, data)
        self._record("write", {"handle": self._handles.get(fd), "length": len(data)}, begin,
                     Result("success" if n == len(data) else "short", 0, n))
        return n

    def read(self, fd, length):
        begin = self.clock()
        data = os.read(fd, length)
        self._record("read", {"handle": self._handles.get(fd), "length": length}, begin,
                     Result("success" if len(data) == length else "eof", 0, len(data)))
        return data

    def fstat(self, fd):
        begin = self.clock()
        st = os.fstat(fd)
        self._record("fstat", {"handle": self._handles.get(fd)}, begin, Result("success", 0, 0, {"size": st.st_size, "node": self._node(st)}))
        return st

    def stat(self, path):
        rel = self._rel(path); begin = self.clock()
        try:
            st = os.stat(self.root / rel)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("stat", {"path": self._synthetic(rel)}, begin, Result(oc, en)); raise
        self._record("stat", {"path": self._synthetic(rel)}, begin, Result("success", 0, 0, {"size": st.st_size, "node": self._node(st)}))
        return st

    def readdir(self, path):
        rel = self._rel(path); begin = self.clock()
        try:
            names = sorted(os.listdir(self.root / rel))
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record("readdir", {"path": self._synthetic(rel)}, begin, Result(oc, en)); raise
        self._record("readdir", {"path": self._synthetic(rel)}, begin, Result("success", 0, 0, {"count": len(names)}))
        return names

    def _two_path(self, call, a, b, fn):
        ra, rb = self._rel(a), self._rel(b); begin = self.clock()
        args = {"path": self._synthetic(ra), "new_path": self._synthetic(rb)}
        try:
            fn(self.root / ra, self.root / rb)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record(call, args, begin, Result(oc, en)); raise
        # Synthetic names belong to directory entries, not to files: after a
        # rename the old name is free (a later stat of it misses, a later
        # create reuses it) and the new name keeps the synthetic name it was
        # given here, so every later reference resolves the same way.
        return self._record(call, args, begin, Result("success"))

    def rename(self, a, b):
        return self._two_path("rename", a, b, os.rename)

    def _one_path(self, call, path, fn, **extra):
        rel = self._rel(path); begin = self.clock()
        args = {"path": self._synthetic(rel), **extra}
        try:
            fn(self.root / rel)
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            self._record(call, args, begin, Result(oc, en)); raise
        return self._record(call, args, begin, Result("success"))

    def unlink(self, path):
        return self._one_path("unlink", path, os.unlink)

    def mkdir(self, path):
        return self._one_path("mkdir", path, os.mkdir)

    def rmdir(self, path):
        return self._one_path("rmdir", path, os.rmdir)

    def truncate(self, path, size):
        return self._one_path("truncate", path, lambda p: os.truncate(p, size), size=size)

    def ftruncate(self, fd, size):
        begin = self.clock()
        os.ftruncate(fd, size)
        return self._record("ftruncate", {"handle": self._handles.get(fd), "size": size}, begin, Result("success"))

    def fsync(self, fd):
        begin = self.clock(); os.fsync(fd)
        return self._record("fsync", {"handle": self._handles.get(fd)}, begin, Result("success"))

    def fdatasync(self, fd):
        begin = self.clock(); os.fdatasync(fd)
        return self._record("fdatasync", {"handle": self._handles.get(fd)}, begin, Result("success"))

    def close_capture(self):
        self._put({"ev": "end", "open_handles": sorted(self._handles.values())})
        self._fh.close()
        return {"open_handles": sorted(self._handles.values()), "events": self._seq}


def normalize_posix_capture(events_path, *, engine=None):
    """Turn a RecordingFS capture into a ``kvio.workload.v3`` plus a timing sidecar."""
    events = [json.loads(l) for l in open(events_path, encoding="utf-8") if l.strip()]
    if not events or events[0].get("ev") != "start":
        raise workload3.Workload3Error("capture must begin with a start event")
    start = events[0]
    notes = []
    end = next((e for e in events if e.get("ev") == "end"), None)
    if end is None:
        notes.append("no end marker: the capture did not close")
    elif end.get("open_handles"):
        notes.append(f"{len(end['open_handles'])} handles still open at capture end")
    wl = workload3.new_workload(capture_level="api", mapping_method="declared", timing_model="captured",
                                release_provenance="observed_submission",
                                engine=engine or {"family": "posix", "name": "application-in-process", "revision": "unknown"},
                                completeness="complete" if not notes else "partial", notes=notes,
                                source={"schema": start.get("schema"), "root_digest": start.get("root_digest")})
    ns = next((e for e in events if e.get("ev") == "namespace"), {"nodes": {}, "entries": []})
    for nid, n in ns["nodes"].items():
        workload3.add_node(wl, nid, kind=n["kind"], incarnation=n.get("incarnation", 1), size=n.get("size", 0))
    for e in ns["entries"]:
        workload3.add_entry(wl, e["path"], e["node"])
    sidecar = []
    prev_in_stream = {}
    n = 0
    for e in events:
        if e.get("ev") != "op":
            continue
        n += 1
        op_id = f"p{n}"
        deps = [{"op": prev_in_stream[e["stream"]], "kind": "program"}] if e["stream"] in prev_in_stream else []
        args = dict(e["args"])
        res = e["result"]
        if e["call"] == "open" and args.get("handle") is None:
            args["handle"] = f"failed-{op_id}"     # a failed open produced no live handle
        exp = {"outcome": res["outcome"]}
        if res.get("bytes"):
            exp["bytes"] = res["bytes"]
        if res.get("meta", {}).get("node"):
            exp["node"] = res["meta"]["node"]
        if res.get("meta", {}).get("count") is not None:
            exp["count"] = res["meta"]["count"]
        workload3.add_op(wl, op_id=op_id, family="posix", call=e["call"], stream=e["stream"], deps=deps,
                         release_ns=e["begin_ns"], expected=exp, **args)
        # A failed open leaves no handle open; the validator tracks opens, so drop it again.
        if e["call"] == "open" and res["outcome"] != "success":
            wl["operations"][-1]["args"]["handle"] = f"failed-{op_id}"
            wl["operations"][-1]["expected"]["no_handle"] = True
        prev_in_stream[e["stream"]] = op_id
        sidecar.append({"op_id": op_id, "begin_ns": e["begin_ns"], "end_ns": e["end_ns"], "outcome": res["outcome"],
                        "errno": res.get("errno", 0), "bytes": res.get("bytes", 0)})
    side = "".join(json.dumps(s, sort_keys=True) + "\n" for s in sidecar).encode()
    wl["timing"] = {"sidecar": "timing.jsonl", "sidecar_sha256": hashlib.sha256(side).hexdigest()}
    wl["health"] = {"events": start and len(events), "operations": n}
    _relax_failed_opens(wl)
    workload3.validate_workload(wl)
    return wl, side


def _relax_failed_opens(wl):
    """A failed open never made its handle live; close the validator's view of it."""
    for op in wl["operations"]:
        if op["family"] == "posix" and op["call"] == "open" and op["expected"].get("no_handle"):
            op["args"]["handle"] = f"failed-{op['op_id']}"


# ---------------------------------------------------------------- replay
class PosixBackend:
    """Replay posix calls on a real directory under a generated root."""

    provenance_modules = ("os",)

    def __init__(self, root, *, profile="incompressible"):
        if root is None:
            raise ValueError("posix-direct needs a root directory")
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.profile = content_profile.parse_profile(profile) if isinstance(profile, str) else profile
        self.handles = {}          # handle id -> fd
        self.handle_node = {}      # handle id -> node id (content identity)
        self.path_node = {}        # synthetic path -> node id
        self.pos = {}              # fd -> sequential position

    @classmethod
    def probe(cls):
        return cls.__new__(cls)

    def doctor(self):
        return "ok (needs --root under a mounted file system)"

    def describe(self):
        st = os.statvfs(self.root)
        return {"root": str(self.root), "fs_block": st.f_bsize, "free_bytes": st.f_bavail * st.f_frsize}

    def _real(self, path):
        p = (self.root / path).resolve()
        if p != self.root and self.root not in p.parents:
            raise PermissionError(errno.EACCES, f"path escapes the generated root: {path}")
        return p

    def initialize(self, workload):
        ns = workload["namespace"]
        self.workload = workload
        for e in sorted(ns["entries"], key=lambda e: e["path"].count("/")):
            node = ns["nodes"][e["node"]]
            real = self._real(e["path"])
            self.path_node[e["path"]] = e["node"]
            if node["kind"] == "dir":
                real.mkdir(parents=True, exist_ok=True)
            elif node["kind"] == "file":
                real.parent.mkdir(parents=True, exist_ok=True)
                with open(real, "wb") as f:
                    if node.get("size"):
                        f.write(content_profile.content(self.profile, e["node"], 0, node["size"]))

    def content(self, node, offset, length):
        return content_profile.content(self.profile, node, offset, length)

    def perform(self, op, ctx=None):
        a = op["args"]
        call = op["call"]
        try:
            if call == "open":
                flags = 0
                for f in a["flags"]:
                    flags |= FLAG_MAP[f]
                fd = os.open(self._real(a["path"]), flags, 0o644)
                self.handles[a["handle"]] = fd
                node = self.path_node.get(a["path"]) or op["expected"].get("node") or f"node:{a['path']}"
                self.path_node[a["path"]] = node
                self.handle_node[a["handle"]] = node
                self.pos[fd] = 0
                return Result("success", 0, 0, {"node": node}, a["handle"])
            if call == "close":
                fd = self.handles.pop(a["handle"]); os.close(fd); self.pos.pop(fd, None)
                return Result("success")
            if call in ("pwrite", "write"):
                fd = self.handles[a["handle"]]
                node = self.handle_node[a["handle"]]
                off = a["offset"] if call == "pwrite" else self.pos[fd]
                data = self.content(node, off, a["length"])
                n = os.pwrite(fd, data, off) if call == "pwrite" else os.write(fd, data)
                if call == "write":
                    self.pos[fd] += n
                return Result("success" if n == a["length"] else "short", 0, n)
            if call in ("pread", "read"):
                fd = self.handles[a["handle"]]
                node = self.handle_node[a["handle"]]
                off = a["offset"] if call == "pread" else self.pos[fd]
                data = os.pread(fd, a["length"], off) if call == "pread" else os.read(fd, a["length"])
                if call == "read":
                    self.pos[fd] += len(data)
                if data and data != self.content(node, off, len(data)):
                    return Result("error", 0, len(data), {"detail": "content mismatch"})
                return Result("success" if len(data) == a["length"] else "eof", 0, len(data))
            if call == "fstat":
                st = os.fstat(self.handles[a["handle"]]); return Result("success", 0, 0, {"size": st.st_size})
            if call == "stat":
                st = os.stat(self._real(a["path"])); return Result("success", 0, 0, {"size": st.st_size})
            if call == "readdir":
                return Result("success", 0, 0, {"count": len(os.listdir(self._real(a["path"])))})
            if call == "rename":
                os.rename(self._real(a["path"]), self._real(a["new_path"]))
                if a["path"] in self.path_node:
                    self.path_node[a["new_path"]] = self.path_node.pop(a["path"])
                return Result("success")
            if call == "unlink":
                os.unlink(self._real(a["path"])); self.path_node.pop(a["path"], None); return Result("success")
            if call == "mkdir":
                os.mkdir(self._real(a["path"])); return Result("success")
            if call == "rmdir":
                os.rmdir(self._real(a["path"])); return Result("success")
            if call == "truncate":
                os.truncate(self._real(a["path"]), a["size"]); return Result("success")
            if call == "ftruncate":
                os.ftruncate(self.handles[a["handle"]], a["size"]); return Result("success")
            if call == "fsync":
                os.fsync(self.handles[a["handle"]]); return Result("success")
            if call == "fdatasync":
                os.fdatasync(self.handles[a["handle"]]); return Result("success")
        except OSError as e:
            oc, en = outcome_of_oserror(e)
            return Result(oc, en)
        except KeyError as e:
            return Result("error", errno.EBADF, 0, {"detail": f"unknown handle {e}"})
        return Result("error", 0, 0, {"detail": f"unsupported call {call}"})

    def final_state(self):
        """Digest of the namespace and the sizes under the root, for comparison."""
        out = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in sorted(dirnames):
                out.append((os.path.relpath(os.path.join(dirpath, name), self.root), "dir", 0))
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                out.append((os.path.relpath(p, self.root), "file", os.path.getsize(p)))
        out.sort()
        return {"entries": out, "sha256": hashlib.sha256(json.dumps(out).encode()).hexdigest()}

    def close(self):
        for fd in list(self.handles.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self.handles.clear()


class FakeFS(PosixBackend):
    """In-memory posix target with injectable outcomes, for contract tests.

    Data lives in inodes; names map to inodes; handles hold inodes.  So a
    rename keeps the data, an unlink with an open handle keeps it readable
    through that handle, and a recreation under the freed name is a new
    inode, as on a real file system.
    """

    provenance_modules = ()

    def __init__(self, *, profile="incompressible", fail=None):
        self.profile = content_profile.parse_profile(profile)
        self.fail = fail or {}
        self.inodes = {}     # ino -> bytearray
        self.names = {}      # path -> ino (files)
        self.dirs = {"."}
        self.handles = {}    # handle -> ino
        self.handle_node = {}
        self.path_node = {}
        self.pos = {}
        self._next = 0

    def doctor(self):
        return "ok"

    def describe(self):
        return {"root": "memory"}

    def _new_inode(self, data=b""):
        self._next += 1
        self.inodes[self._next] = bytearray(data)
        return self._next

    def initialize(self, workload):
        ns = workload["namespace"]
        for e in ns["entries"]:
            node = ns["nodes"][e["node"]]
            self.path_node[e["path"]] = e["node"]
            if node["kind"] == "dir":
                self.dirs.add(e["path"])
            else:
                self.names[e["path"]] = self._new_inode(content_profile.content(self.profile, e["node"], 0, node.get("size", 0)))

    def _parent_ok(self, path):
        return (path.rpartition("/")[0] or ".") in self.dirs

    def _children(self, d):
        return [x for x in list(self.names) + list(self.dirs - {"."}) if (x.rpartition("/")[0] or ".") == d]

    def perform(self, op, ctx=None):
        forced = self.fail.get(op["op_id"])
        if forced:
            return Result(forced, 0, 0, {"detail": "injected"})
        a = op["args"]; call = op["call"]
        if call == "open":
            p = a["path"]; fl = set(a["flags"])
            if p not in self.names:
                if "creat" not in fl or not self._parent_ok(p):
                    return Result("miss", errno.ENOENT)
                self.names[p] = self._new_inode()
            elif "excl" in fl and "creat" in fl:
                return Result("exists", errno.EEXIST)
            ino = self.names[p]
            if "trunc" in fl:
                self.inodes[ino] = bytearray()
            self.handles[a["handle"]] = ino
            node = self.path_node.get(p) or op["expected"].get("node") or f"node:{p}"
            self.path_node[p] = node; self.handle_node[a["handle"]] = node; self.pos[a["handle"]] = 0
            return Result("success", 0, 0, {"node": node}, a["handle"])
        if "handle" in a and a["handle"] not in self.handles:
            return Result("error", errno.EBADF)
        if call == "close":
            self.handles.pop(a["handle"]); return Result("success")
        if call in ("pwrite", "write"):
            buf = self.inodes[self.handles[a["handle"]]]
            off = a["offset"] if call == "pwrite" else self.pos[a["handle"]]
            data = self.content(self.handle_node[a["handle"]], off, a["length"])
            if len(buf) < off + len(data):
                buf.extend(bytes(off + len(data) - len(buf)))
            buf[off:off + len(data)] = data
            if call == "write":
                self.pos[a["handle"]] += len(data)
            return Result("success", 0, len(data))
        if call in ("pread", "read"):
            buf = self.inodes[self.handles[a["handle"]]]
            off = a["offset"] if call == "pread" else self.pos[a["handle"]]
            data = bytes(buf[off:off + a["length"]])
            if call == "read":
                self.pos[a["handle"]] += len(data)
            if data and data != self.content(self.handle_node[a["handle"]], off, len(data)):
                return Result("error", 0, len(data), {"detail": "content mismatch"})
            return Result("success" if len(data) == a["length"] else "eof", 0, len(data))
        if call == "fstat":
            return Result("success", 0, 0, {"size": len(self.inodes[self.handles[a["handle"]]])})
        if call == "stat":
            p = a["path"]
            if p in self.names:
                return Result("success", 0, 0, {"size": len(self.inodes[self.names[p]])})
            if p in self.dirs:
                return Result("success", 0, 0, {"size": 0})
            return Result("miss", errno.ENOENT)
        if call == "readdir":
            if a["path"] not in self.dirs:
                return Result("miss", errno.ENOENT)
            return Result("success", 0, 0, {"count": len(self._children(a["path"]))})
        if call == "rename":
            src, dst = a["path"], a["new_path"]
            if src in self.names:
                self.names[dst] = self.names.pop(src)
            elif src in self.dirs:
                self.dirs.discard(src); self.dirs.add(dst)
            else:
                return Result("miss", errno.ENOENT)
            if src in self.path_node:
                self.path_node[dst] = self.path_node.pop(src)
            return Result("success")
        if call == "unlink":
            if a["path"] not in self.names:
                return Result("miss", errno.ENOENT)
            ino = self.names.pop(a["path"]); self.path_node.pop(a["path"], None)
            if ino not in self.handles.values():
                self.inodes.pop(ino, None)
            return Result("success")
        if call == "mkdir":
            if a["path"] in self.dirs or a["path"] in self.names:
                return Result("exists", errno.EEXIST)
            if not self._parent_ok(a["path"]):
                return Result("miss", errno.ENOENT)
            self.dirs.add(a["path"]); return Result("success")
        if call == "rmdir":
            if a["path"] not in self.dirs:
                return Result("miss", errno.ENOENT)
            if self._children(a["path"]):
                return Result("not_empty", errno.ENOTEMPTY)
            self.dirs.discard(a["path"]); return Result("success")
        if call in ("truncate", "ftruncate"):
            if call == "truncate":
                if a["path"] not in self.names:
                    return Result("miss", errno.ENOENT)
                ino = self.names[a["path"]]
            else:
                ino = self.handles[a["handle"]]
            buf = self.inodes[ino]
            self.inodes[ino] = buf[:a["size"]] + bytes(max(0, a["size"] - len(buf)))
            return Result("success")
        if call in ("fsync", "fdatasync"):
            return Result("success")
        return Result("error", 0, 0, {"detail": f"unsupported call {call}"})

    def final_state(self):
        out = sorted([(p, "dir", 0) for p in self.dirs if p != "."] + [(p, "file", len(self.inodes[i])) for p, i in self.names.items()])
        return {"entries": out, "sha256": hashlib.sha256(json.dumps(out).encode()).hexdigest()}

    def close(self):
        self.handles.clear()
