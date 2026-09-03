# SPDX-License-Identifier: Apache-2.0
"""Compile agent request traces into an evidence-labeled KV-cache IO plan.

The input trace is application evidence, not a device trace.  This compiler
preserves request order, relative timing, and session boundaries, then maps
complete prompt chunks to logical L2 loads, stores, and evictions under an
explicit cache policy.  Running the plan through ``kvio workload`` produces
real storage IO; recording that run is what produces a device trace.

Supported schemas:

* ``lmcache-agent``: LMCache's public agent traces.  These contain prompt text,
  so an explicitly pinned tokenizer can derive content-addressed chunks.
* ``tracelab``: TraceLab's sanitized coding-agent rounds.  These intentionally
  omit prompt text but retain token and provider-cache accounting.  The plan
  therefore uses the observed prefix-token count and session-relative logical
  chunk positions; it does not claim content-derived chunk identity.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Iterable


PLAN_KIND = "kvio.agent-cache-plan"
PLAN_VERSION = 1


class TraceError(ValueError):
    """The source trace cannot be interpreted without guessing."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _input_files(path: str) -> list[Path]:
    source = Path(path)
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise TraceError(f"trace input does not exist: {path}")
    files = sorted(
        p for p in source.rglob("*")
        if p.is_file() and (p.suffix == ".jsonl" or p.name.endswith(".jsonl.gz"))
    )
    if not files:
        raise TraceError(f"trace directory contains no .jsonl files: {path}")
    return files


def read_records(path: str, *, max_requests: int | None = None) -> tuple[list[dict], list[dict]]:
    """Read strict JSONL and return records plus per-file provenance."""
    records: list[dict] = []
    provenance: list[dict] = []
    ingest_count = 0
    for file_path in _input_files(path):
        seen = selected = 0
        opener = gzip.open if file_path.name.endswith(".gz") else open
        with opener(file_path, "rt", encoding="utf-8") as source:
            for line_no, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise TraceError(f"{file_path}:{line_no}: invalid JSON: {error.msg}") from error
                if not isinstance(value, dict):
                    raise TraceError(f"{file_path}:{line_no}: expected a JSON object")
                seen += 1
                if max_requests is None or len(records) < max_requests:
                    value = dict(value)
                    value["_kvio_file"] = str(file_path)
                    value["_kvio_line"] = line_no
                    value["_kvio_ingest"] = ingest_count
                    records.append(value)
                    selected += 1
                ingest_count += 1
        provenance.append({
            "path": str(file_path),
            "sha256": _sha256_file(file_path),
            "records_seen": seen,
            "records_selected": selected,
        })
    if not records:
        raise TraceError(f"trace contains no JSON records: {path}")
    return records, provenance


def detect_format(record: dict) -> str:
    if isinstance(record.get("input"), str) and "session_id" in record:
        return "lmcache-agent"
    required = {"provider", "session_id", "input_tokens_total", "prefix_tokens"}
    if required.issubset(record):
        return "tracelab"
    raise TraceError(
        "cannot detect trace schema; select --format and verify that required fields are present"
    )


def normalize_timestamp(value: Any, where: str) -> float:
    """Return Unix seconds from ISO-8601 or seconds/ms/us numeric timestamps."""
    if isinstance(value, bool):
        raise TraceError(f"{where}: timestamp is boolean")
    if isinstance(value, (int, float)):
        stamp = float(value)
        magnitude = abs(stamp)
        if magnitude >= 1e14:
            stamp /= 1_000_000.0
        elif magnitude >= 1e11:
            stamp /= 1_000.0
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise TraceError(f"{where}: empty timestamp")
        try:
            stamp = dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError as error:
            raise TraceError(f"{where}: invalid ISO-8601 timestamp {value!r}") from error
    else:
        raise TraceError(f"{where}: timestamp must be numeric or ISO-8601")
    year = dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).year
    if year < 2000 or year > 2100:
        raise TraceError(f"{where}: normalized timestamp has implausible year {year}")
    return stamp


def _record_timestamp(record: dict, trace_format: str) -> float:
    where = f"{record['_kvio_file']}:{record['_kvio_line']}"
    if trace_format == "lmcache-agent":
        if "timestamp" not in record:
            raise TraceError(f"{where}: missing timestamp")
        return normalize_timestamp(record["timestamp"], where)
    events = record.get("timing_events")
    if not isinstance(events, list) or not events:
        raise TraceError(f"{where}: TraceLab round has no timing_events")
    for event in events:
        if isinstance(event, dict) and event.get("timestamp") is not None:
            return normalize_timestamp(event["timestamp"], where)
    raise TraceError(f"{where}: TraceLab round has no timestamped timing event")


def _positive_int(value: Any, field: str, where: str, *, allow_zero: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TraceError(f"{where}: {field} must be numeric")
    integer = int(value)
    if integer != value or integer < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise TraceError(f"{where}: {field} must be a {qualifier} integer")
    return integer


def _session_digest(parts: Iterable[Any]) -> str:
    raw = json.dumps([str(part or "") for part in parts], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _chunk_digest(token_ids: list[int], predecessor: str | None) -> str:
    digest = hashlib.sha256()
    if predecessor is not None:
        digest.update(bytes.fromhex(predecessor))
    for token_id in token_ids:
        if token_id < 0:
            raise TraceError(f"tokenizer returned a negative token id: {token_id}")
        digest.update(int(token_id).to_bytes(8, "big"))
    return digest.hexdigest()


def _base_plan(trace_format: str, files: list[dict], chunk_tokens: int,
               source: dict | None) -> dict:
    return {
        "schema_version": PLAN_VERSION,
        "kind": PLAN_KIND,
        "evidence": {
            "kind": "trace-derived",
            "statement": (
                "Application requests and timing come from the source trace. Storage operations "
                "are derived under the recorded assumptions and are not observed device IO."
            ),
        },
        "source": {"format": trace_format, "files": files, **(source or {})},
        "chunk_tokens": chunk_tokens,
        "warm_keys": [],
        "requests": [],
    }


def compile_lmcache_agent(
    records: list[dict],
    files: list[dict],
    *,
    encode: Callable[[str], list[int]],
    tokenizer: dict,
    chunk_tokens: int = 256,
    policy: str = "prefix",
    capacity_chunks: int = 0,
    session_scope: str = "file",
    source: dict | None = None,
) -> dict:
    if chunk_tokens <= 0:
        raise TraceError("chunk_tokens must be positive")
    if policy not in ("prefix", "substring"):
        raise TraceError("policy must be prefix or substring")
    if capacity_chunks < 0:
        raise TraceError("capacity_chunks must be non-negative")
    if session_scope not in ("file", "field"):
        raise TraceError("session_scope must be file or field")

    enriched: list[tuple[float, dict]] = []
    for record in records:
        where = f"{record['_kvio_file']}:{record['_kvio_line']}"
        if not isinstance(record.get("input"), str):
            raise TraceError(f"{where}: lmcache-agent record has no string input")
        if session_scope == "field" and not str(record.get("session_id", "")):
            raise TraceError(f"{where}: --session-scope=field needs a non-empty session_id")
        enriched.append((_record_timestamp(record, "lmcache-agent"), record))
    enriched.sort(key=lambda pair: (pair[0], pair[1]["_kvio_ingest"]))
    start = enriched[0][0]

    plan = _base_plan("lmcache-agent", files, chunk_tokens, source)
    plan["tokenizer"] = tokenizer
    plan["assumptions"] = {
        "cache_policy": policy,
        "capacity_chunks": capacity_chunks,
        "session_scope": session_scope,
        "tail_policy": "ignore incomplete final chunks",
        "arrival_policy": "stable global timestamp order",
        "execution_policy": (
            "requests execute serially; timing-scale schedules starts but does not recreate concurrency"
        ),
        "tier_model": "each derived hit loads from L2; each new complete chunk stores to L2",
    }

    resident: OrderedDict[str, None] = OrderedDict()
    stores = loads = evictions = token_total = ignored_tail = 0
    max_resident = 0
    for request_index, (timestamp, record) in enumerate(enriched):
        token_ids = list(encode(record["input"]))
        if not all(isinstance(token_id, int) and not isinstance(token_id, bool)
                   for token_id in token_ids):
            raise TraceError("tokenizer must return integer token ids")
        token_total += len(token_ids)
        ignored_tail += len(token_ids) % chunk_tokens
        chunks = [token_ids[index:index + chunk_tokens]
                  for index in range(0, len(token_ids) - chunk_tokens + 1, chunk_tokens)]
        keys: list[str] = []
        predecessor = None
        for chunk in chunks:
            key = _chunk_digest(chunk, predecessor if policy == "prefix" else None)
            keys.append(key)
            predecessor = key

        preexisting = set(resident)
        new_in_request: set[str] = set()
        ops: list[dict] = []
        misses: list[tuple[int, str]] = []
        for chunk_index, key in enumerate(keys):
            if key in preexisting:
                ops.append({"op": "load", "chunk_key": key, "chunk_index": chunk_index})
                loads += 1
                resident.move_to_end(key)
                continue
            if key in new_in_request:
                continue
            new_in_request.add(key)
            misses.append((chunk_index, key))
        # All hits are against cache state at request arrival. Apply insertions
        # only after those loads so an eviction cannot invalidate a later hit
        # from the same request.
        for chunk_index, key in misses:
            if capacity_chunks and len(resident) >= capacity_chunks:
                old_key, _ = resident.popitem(last=False)
                ops.append({"op": "delete", "chunk_key": old_key})
                evictions += 1
            ops.append({"op": "store", "chunk_key": key, "chunk_index": chunk_index})
            stores += 1
            resident[key] = None
        max_resident = max(max_resident, len(resident))

        if session_scope == "file":
            effective = _session_digest((record["_kvio_file"],))
        else:
            effective = _session_digest((record.get("session_id"),))
        plan["requests"].append({
            "request_index": request_index,
            "session": effective,
            "source_session": _session_digest((record.get("session_id"),)),
            "source_file": record["_kvio_file"],
            "source_line": record["_kvio_line"],
            "timestamp_unix_s": timestamp,
            "offset_s": timestamp - start,
            "input_tokens": len(token_ids),
            "complete_chunks": len(chunks),
            "ignored_tail_tokens": len(token_ids) % chunk_tokens,
            "operations": ops,
        })

    plan["summary"] = {
        "requests": len(enriched), "sessions": len({r["session"] for r in plan["requests"]}),
        "input_tokens": token_total, "ignored_tail_tokens": ignored_tail,
        "loads": loads, "stores": stores, "evictions": evictions,
        "max_resident_chunks": max_resident,
        "duration_s": enriched[-1][0] - start,
    }
    return plan


def compile_tracelab(
    records: list[dict],
    files: list[dict],
    *,
    chunk_tokens: int = 256,
    provider: str | None = None,
    source: dict | None = None,
) -> dict:
    if chunk_tokens <= 0:
        raise TraceError("chunk_tokens must be positive")
    selected: list[tuple[float, dict]] = []
    for record in records:
        if provider and record.get("provider") != provider:
            continue
        where = f"{record['_kvio_file']}:{record['_kvio_line']}"
        for field in ("provider", "session_id", "input_tokens_total", "prefix_tokens"):
            if record.get(field) is None:
                raise TraceError(f"{where}: TraceLab round is missing {field}")
        selected.append((_record_timestamp(record, "tracelab"), record))
    if not selected:
        raise TraceError("no TraceLab rounds remain after filtering")
    selected.sort(key=lambda pair: (pair[0], pair[1]["_kvio_ingest"]))
    start = selected[0][0]

    plan = _base_plan("tracelab", files, chunk_tokens, source)
    plan["assumptions"] = {
        "cache_policy": "observed prefix-token accounting",
        "chunk_identity": (
            "session-relative prefix position; TraceLab omits prompt text for privacy"
        ),
        "tail_policy": "ignore incomplete chunk boundaries",
        "arrival_policy": "stable global timestamp order",
        "execution_policy": (
            "requests execute serially; timing-scale schedules starts but does not recreate concurrency"
        ),
        "tier_model": "provider prefix hits are modeled as L2 loads; newly complete chunks store",
        "capacity_chunks": "not simulated because the source already reports cache outcomes",
    }

    known: set[str] = set()
    warm: set[str] = set()
    stores = loads = input_total = prefix_total = 0
    for request_index, (timestamp, record) in enumerate(selected):
        where = f"{record['_kvio_file']}:{record['_kvio_line']}"
        total = _positive_int(record["input_tokens_total"], "input_tokens_total", where)
        prefix = _positive_int(record["prefix_tokens"], "prefix_tokens", where)
        if prefix > total:
            raise TraceError(f"{where}: prefix_tokens exceeds input_tokens_total")
        session = _session_digest((record.get("provider"), record.get("project"),
                                   record.get("session_file"), record.get("session_id")))
        prefix_chunks = prefix // chunk_tokens
        total_chunks = total // chunk_tokens
        ops: list[dict] = []
        for chunk_index in range(prefix_chunks):
            key = hashlib.sha256(f"tracelab:{session}:{chunk_index}".encode()).hexdigest()
            if key not in known:
                warm.add(key)
                known.add(key)
            ops.append({"op": "load", "chunk_key": key, "chunk_index": chunk_index})
            loads += 1
        for chunk_index in range(prefix_chunks, total_chunks):
            key = hashlib.sha256(f"tracelab:{session}:{chunk_index}".encode()).hexdigest()
            if key in known:
                continue
            known.add(key)
            ops.append({"op": "store", "chunk_key": key, "chunk_index": chunk_index})
            stores += 1
        input_total += total
        prefix_total += prefix
        plan["requests"].append({
            "request_index": request_index,
            "session": session,
            "provider": record.get("provider"),
            "model": record.get("model"),
            "round_index": record.get("round_index"),
            "source_file": record["_kvio_file"],
            "source_line": record["_kvio_line"],
            "timestamp_unix_s": timestamp,
            "offset_s": timestamp - start,
            "input_tokens": total,
            "observed_prefix_tokens": prefix,
            "complete_chunks": total_chunks,
            "ignored_tail_tokens": total % chunk_tokens,
            "operations": ops,
        })
    plan["warm_keys"] = sorted(warm)
    plan["summary"] = {
        "requests": len(selected), "sessions": len({r["session"] for r in plan["requests"]}),
        "input_tokens": input_total, "observed_prefix_tokens": prefix_total,
        "loads": loads, "stores": stores, "evictions": 0,
        "warm_chunks": len(warm), "max_resident_chunks": len(known),
        "duration_s": selected[-1][0] - start,
    }
    return plan


def validate_plan(plan: dict) -> None:
    if plan.get("schema_version") != PLAN_VERSION or plan.get("kind") != PLAN_KIND:
        raise TraceError("unsupported agent plan schema")
    if not isinstance(plan.get("chunk_tokens"), int) or plan["chunk_tokens"] <= 0:
        raise TraceError("agent plan has invalid chunk_tokens")
    if not isinstance(plan.get("requests"), list) or not plan["requests"]:
        raise TraceError("agent plan contains no requests")
    valid_ops = {"load", "store", "delete"}
    for key in plan.get("warm_keys", []):
        if not isinstance(key, str) or len(key) != 64:
            raise TraceError("agent plan warm key is not a SHA-256 hex digest")
        try:
            bytes.fromhex(key)
        except ValueError as error:
            raise TraceError("agent plan warm key is not hexadecimal") from error
    for request in plan["requests"]:
        if not isinstance(request.get("operations"), list):
            raise TraceError("agent plan request has no operations list")
        for operation in request["operations"]:
            if operation.get("op") not in valid_ops:
                raise TraceError(f"agent plan contains invalid operation: {operation.get('op')!r}")
            key = operation.get("chunk_key")
            if not isinstance(key, str) or len(key) != 64:
                raise TraceError("agent plan chunk key is not a SHA-256 hex digest")
            try:
                bytes.fromhex(key)
            except ValueError as error:
                raise TraceError("agent plan chunk key is not hexadecimal") from error


def _load_tokenizer(name: str, revision: str, trust_remote_code: bool):
    if name.startswith("tiktoken:"):
        try:
            import tiktoken
        except ImportError as error:
            raise SystemExit("this tokenizer requires tiktoken: pip install tiktoken") from error
        valid_revisions = {tiktoken.__version__, f"tiktoken-{tiktoken.__version__}"}
        if revision not in valid_revisions:
            raise SystemExit(
                f"--tokenizer-revision {revision!r} does not match installed "
                f"tiktoken {tiktoken.__version__}")
        selector = name.removeprefix("tiktoken:")
        if selector.startswith("encoding:"):
            tokenizer = tiktoken.get_encoding(selector.removeprefix("encoding:"))
        else:
            tokenizer = tiktoken.encoding_for_model(selector)

        def encode(text: str) -> list[int]:
            return list(tokenizer.encode(text, disallowed_special=()))

        identity = {
            "name": name, "revision": revision, "add_special_tokens": False,
            "tiktoken_version": tiktoken.__version__,
            "resolved_encoding": tokenizer.name,
        }
        return encode, identity
    try:
        import transformers
        from transformers import AutoTokenizer
    except ImportError as error:
        raise SystemExit("lmcache-agent traces require transformers: pip install transformers") from error
    tokenizer = AutoTokenizer.from_pretrained(
        name, revision=None if revision == "local" else revision,
        trust_remote_code=trust_remote_code,
    )

    def encode(text: str) -> list[int]:
        return list(tokenizer.encode(text, add_special_tokens=False))

    identity = {
        "name": name, "revision": revision, "add_special_tokens": False,
        "transformers_version": transformers.__version__,
    }
    return encode, identity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="JSONL file, .jsonl.gz file, or directory")
    parser.add_argument("--out", required=True, help="output plan JSON")
    parser.add_argument("--format", choices=("auto", "lmcache-agent", "tracelab"), default="auto")
    parser.add_argument("--chunk-tokens", type=int, default=256)
    parser.add_argument("--max-requests", type=int,
                        help="compile only the first N source records (for bounded experiments)")
    parser.add_argument("--provider", choices=("claude", "codex"),
                        help="TraceLab provider filter")
    parser.add_argument("--policy", choices=("prefix", "substring"), default="prefix",
                        help="lmcache-agent content-reuse policy")
    parser.add_argument("--capacity-chunks", type=int, default=0,
                        help="lmcache-agent LRU capacity; 0 means unbounded")
    parser.add_argument("--session-scope", choices=("file", "field"), default="file",
                        help="lmcache-agent effective session boundary")
    parser.add_argument("--tokenizer",
                        help="HF name/path or tiktoken:MODEL / tiktoken:encoding:NAME")
    parser.add_argument("--tokenizer-revision",
                        help="pinned HF revision, or 'local' for a local tokenizer")
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--source-url")
    parser.add_argument("--source-revision")
    parser.add_argument("--source-license")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    records, files = read_records(args.input, max_requests=args.max_requests)
    trace_format = detect_format(records[0]) if args.format == "auto" else args.format
    source = {key: value for key, value in {
        "url": args.source_url, "revision": args.source_revision,
        "license": args.source_license,
    }.items() if value}
    if trace_format == "lmcache-agent":
        if not args.tokenizer or not args.tokenizer_revision:
            raise SystemExit(
                "lmcache-agent requires --tokenizer and --tokenizer-revision; "
                "token counts must not be guessed"
            )
        encode, identity = _load_tokenizer(
            args.tokenizer, args.tokenizer_revision, args.trust_remote_code)
        plan = compile_lmcache_agent(
            records, files, encode=encode, tokenizer=identity,
            chunk_tokens=args.chunk_tokens, policy=args.policy,
            capacity_chunks=args.capacity_chunks, session_scope=args.session_scope,
            source=source,
        )
    else:
        plan = compile_tracelab(
            records, files, chunk_tokens=args.chunk_tokens,
            provider=args.provider, source=source,
        )
    validate_plan(plan)
    with open(args.out, "w", encoding="utf-8") as output:
        json.dump(plan, output, indent=2, sort_keys=True)
        output.write("\n")
    summary = plan["summary"]
    print(f"wrote {args.out}: {summary['requests']} requests, "
          f"{summary['loads']} loads, {summary['stores']} stores, "
          f"{summary['evictions']} evictions")
    print(plan["evidence"]["statement"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
