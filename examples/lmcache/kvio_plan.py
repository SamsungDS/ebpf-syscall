#!/usr/bin/env python3
"""kvio plan — GPU-free projection of LMCache KV-cache-offload storage I/O.

Given a model's hyperparameters (or a payload size) plus a storage config,
project the device I/O a single KV store/load produces: device ops, NVMe command
count, per-command sizes, total device bytes, and the fragmentation factor vs the
drive MDTS. No GPU, no inference, no vLLM.

The geometry mirrors LMCache's raw-block engine, calibrated/validated against the
eBPF + semantic-record join (see kvio_validate.py):
  - a store writes a fixed-size header op + the payload op;
  - a load reads the payload op only;
  - each logical op is split into ceil(bytes / xfer) NVMe commands, where
    xfer = min(max_data_transfer_size, MDTS).
"""
import argparse
import json
import math

# name: (num_layers, num_kv_heads, head_dim, dtype_bytes)
MODELS = {
    "Llama-3.2-1B": (16, 8, 64, 2),
    "Llama-3.2-3B": (28, 8, 128, 2),
    "Llama-3.1-8B": (32, 8, 128, 2),
}


def per_token_kv(layers, kv_heads, head_dim, dtype_bytes):
    """KV-cache bytes per token (K and V), the model-dependent unit."""
    return 2 * layers * kv_heads * head_dim * dtype_bytes


def split_commands(nbytes, xfer):
    """A logical transfer of nbytes -> ceil(nbytes/xfer) NVMe commands."""
    if nbytes <= 0:
        return []
    n = math.ceil(nbytes / xfer)
    return [xfer] * (n - 1) + [nbytes - xfer * (n - 1)]


def project(payload_bytes, op, header_bytes=4096, max_xfer=0, mdts_bytes=128 * 1024):
    """Project the device I/O geometry of one KV store/load."""
    xfer = min(max_xfer, mdts_bytes) if max_xfer else mdts_bytes
    cmds = []
    if op == "store":
        cmds += split_commands(header_bytes, xfer)   # header op
    cmds += split_commands(payload_bytes, xfer)       # payload op
    return {
        "op": op,
        "payload_bytes": payload_bytes,
        "xfer": xfer,
        "device_ops": 2 if op == "store" else 1,
        "nvme_commands": len(cmds),
        "command_sizes": cmds,
        "total_device_bytes": sum(cmds),
        "fragmentation": len(cmds),  # NVMe commands per logical KV op
    }


def payload_for_model(name, chunk_tokens):
    layers, kv, hd, db = MODELS[name]
    return per_token_kv(layers, kv, hd, db) * chunk_tokens


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(MODELS))
    ap.add_argument("--layers", type=int)
    ap.add_argument("--kv-heads", type=int)
    ap.add_argument("--head-dim", type=int)
    ap.add_argument("--dtype-bytes", type=int, default=2)
    ap.add_argument("--chunk-tokens", type=int, default=256)
    ap.add_argument("--payload-bytes", type=int, help="override model-derived payload")
    ap.add_argument("--op", choices=["store", "load"], default="store")
    ap.add_argument("--header-bytes", type=int, default=4096)
    ap.add_argument("--max-xfer", type=int, default=0,
                    help="LMCache max_data_transfer_size (0 = use MDTS)")
    ap.add_argument("--mdts-bytes", type=int, default=128 * 1024)
    ap.add_argument("--all-models", action="store_true")
    args = ap.parse_args()

    if args.all_models:
        print(f"# chunk={args.chunk_tokens} tok, MDTS={args.mdts_bytes // 1024} KiB, "
              f"max_xfer={args.max_xfer or 'MDTS'}")
        for name in MODELS:
            for op in ("store", "load"):
                p = project(payload_for_model(name, args.chunk_tokens), op,
                            args.header_bytes, args.max_xfer, args.mdts_bytes)
                print(f"  {name:14s} {op:5s}: payload={p['payload_bytes'] // 1024:>6} KiB "
                      f"-> {p['nvme_commands']:>4} NVMe cmds, "
                      f"{p['total_device_bytes']} B (frag {p['fragmentation']}x)")
        return

    if args.payload_bytes is not None:
        payload = args.payload_bytes
    elif args.model:
        payload = payload_for_model(args.model, args.chunk_tokens)
    else:
        payload = per_token_kv(args.layers, args.kv_heads, args.head_dim,
                               args.dtype_bytes) * args.chunk_tokens
    print(json.dumps(
        project(payload, args.op, args.header_bytes, args.max_xfer, args.mdts_bytes),
        indent=2))


if __name__ == "__main__":
    main()
