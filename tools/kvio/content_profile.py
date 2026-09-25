#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Named content profiles for replay payloads, and what each one is for.

A replay that writes zeros measures a compressing or deduplicating target
as if it stored nothing; one that writes a unique hash stream measures it
as if nothing ever repeats.  Neither is a workload, so both are kept only
as **named controls**, and a third family of profiles has independent
knobs for the things that decide reduction on a real tier: runs of zeros,
repeated patterns, incompressible regions, and duplicate classes shared
across objects, versions or ranges.

Content is a pure function of (profile, content identity, offset, length):
ranged reads agree with full reads, a partial overwrite keeps the bytes it
did not touch, and objects that are meant to share content share a
content identity independent of their names.  A profile reports the
compression ratio it *achieved* under a named algorithm where that
library is present (zstd and LZ4, at stated levels and block sizes),
which is a portable calibration figure and not a claim about any target's
own compression or deduplication.

    python3 content_profile.py report --profile mixed:zero=0.3,pattern=0.2 --bytes 4194304
"""
from __future__ import annotations

import hashlib
import json
import zlib

CONTROLS = ("zeros", "incompressible")
BLOCK = 4096


def parse_profile(spec):
    """``zeros`` | ``incompressible`` | ``mixed:zero=F,pattern=F,pattern_len=N,dup_classes=N``."""
    name, _, rest = spec.partition(":")
    knobs = {"zero": 0.0, "pattern": 0.0, "pattern_len": 64, "dup_classes": 0, "block": BLOCK}
    if name in CONTROLS:
        if rest:
            raise ValueError(f"{name} takes no knobs")
        return {"name": name, **({"zero": 1.0} if name == "zeros" else {})}
    if name != "mixed":
        raise ValueError(f"unknown profile {name!r}")
    for kv in filter(None, rest.split(",")):
        k, _, v = kv.partition("=")
        if k not in knobs:
            raise ValueError(f"unknown knob {k!r}")
        knobs[k] = type(knobs[k])(float(v)) if isinstance(knobs[k], float) else int(v)
    if knobs["zero"] + knobs["pattern"] > 1.0:
        raise ValueError("zero + pattern fractions exceed 1")
    return {"name": "mixed", **knobs}


def _block_bytes(profile, identity, block_index, length):
    """Content of one block: its class decided by a hash of (identity, block)."""
    if profile["name"] == "zeros":
        return bytes(length)
    if profile["name"] == "incompressible":
        return _hash_stream(identity, block_index, length)
    r = int.from_bytes(hashlib.blake2b(f"{identity}:{block_index}:class".encode(), digest_size=8).digest(), "big") / 2**64
    if r < profile["zero"]:
        return bytes(length)
    if r < profile["zero"] + profile["pattern"]:
        pat = hashlib.blake2b(f"{identity}:{block_index}:pat".encode(), digest_size=max(1, min(64, profile["pattern_len"]))).digest()
        return (pat * (length // len(pat) + 1))[:length]
    if profile["dup_classes"]:
        # The block is one of N shared blocks: identical across objects.
        cls = int.from_bytes(hashlib.blake2b(f"{identity}:{block_index}:dup".encode(), digest_size=4).digest(), "big") % profile["dup_classes"]
        return _hash_stream(f"dup-class-{cls}", 0, length)
    return _hash_stream(identity, block_index, length)


def _hash_stream(identity, block_index, length):
    out = bytearray()
    n = 0
    while len(out) < length:
        out += hashlib.blake2b(f"{identity}:{block_index}:{n}".encode(), digest_size=64).digest()
        n += 1
    return bytes(out[:length])


def content(profile, identity, offset, length):
    """Bytes of ``identity`` at ``[offset, offset+length)`` under ``profile``."""
    if isinstance(profile, str):
        profile = parse_profile(profile)
    block = profile.get("block", BLOCK)
    out = bytearray()
    pos = offset
    end = offset + length
    while pos < end:
        bi, off = divmod(pos, block)
        take = min(block - off, end - pos)
        out += _block_bytes(profile, identity, bi, block)[off:off + take]
        pos += take
    return bytes(out)


def achieved(profile, identity, nbytes, *, sample=1 << 20):
    """Compression ratios actually reached on a sample, under named algorithms."""
    data = content(profile, identity, 0, min(nbytes, sample))
    res = {"sample_bytes": len(data), "algorithms": {}}
    res["algorithms"]["zlib-6"] = round(len(data) / max(1, len(zlib.compress(data, 6))), 3)
    try:
        import zstandard
        c = zstandard.ZstdCompressor(level=3).compress(data)
        res["algorithms"]["zstd-3"] = round(len(data) / max(1, len(c)), 3)
    except ImportError:
        res["algorithms"]["zstd-3"] = None
    try:
        import lz4.frame
        c = lz4.frame.compress(data)
        res["algorithms"]["lz4-frame"] = round(len(data) / max(1, len(c)), 3)
    except ImportError:
        res["algorithms"]["lz4-frame"] = None
    blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    res["distinct_4k_blocks"] = len({hashlib.sha256(b).digest() for b in blocks})
    res["blocks"] = len(blocks)
    return res


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report"); r.add_argument("--profile", required=True); r.add_argument("--bytes", type=int, default=1 << 20)
    r.add_argument("--identity", default="probe")
    args = ap.parse_args(argv)
    p = parse_profile(args.profile)
    print(json.dumps({"profile": p, "achieved": achieved(p, args.identity, args.bytes)}, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
