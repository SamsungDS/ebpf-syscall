#!/usr/bin/env python3
"""Compute LMCache KV-cache I/O sizes from a model architecture.

The unit of I/O for a KV-cache offload backend is model-dependent. Per token the
KV cache is:

    per_token_kv = 2 (K and V) * num_layers * num_kv_heads * head_dim * dtype_bytes

For a stored "chunk" of T tokens, the natural logical KV object is
`per_token_kv * T` (all layers); a per-layer slab is `per_token_kv * T /
num_layers`. These logical I/O sizes are what an application *intends*; anything
larger than the device's MDTS must be split into multiple commands BEFORE it
reaches the drive -- by the kernel block layer on the block path, or by the
application itself on NVMe passthrough (a drive never splits: it rejects
oversized commands). ebpf-syscall captures the intent; the NVMe layer only
shows the fragments.

Usage: kv_io_size.py --layers 32 --kv-heads 8 --head-dim 128 [--dtype-bytes 2]
                     [--chunk-tokens 256]
"""
import argparse, json


def sizes(layers, kv_heads, head_dim, dtype_bytes, chunk_tokens):
    per_token = 2 * layers * kv_heads * head_dim * dtype_bytes
    full_chunk = per_token * chunk_tokens
    per_layer_chunk = 2 * kv_heads * head_dim * dtype_bytes * chunk_tokens
    return {
        "per_token_bytes": per_token,
        "per_token_KiB": per_token / 1024,
        "chunk_tokens": chunk_tokens,
        "full_chunk_bytes": full_chunk,
        "full_chunk_MiB": full_chunk / (1 << 20),
        "per_layer_chunk_bytes": per_layer_chunk,
        "per_layer_chunk_KiB": per_layer_chunk / 1024,
    }


MODELS = {
    # name: (layers, kv_heads, head_dim, dtype_bytes)
    "Llama-3.2-1B": (16, 8, 64, 2),
    "Llama-3.2-3B": (28, 8, 128, 2),
    "Llama-3.1-8B": (32, 8, 128, 2),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(MODELS))
    ap.add_argument("--layers", type=int)
    ap.add_argument("--kv-heads", type=int)
    ap.add_argument("--head-dim", type=int)
    ap.add_argument("--dtype-bytes", type=int, default=2)
    ap.add_argument("--chunk-tokens", type=int, default=256)
    ap.add_argument("--all", action="store_true", help="print table for all known models")
    args = ap.parse_args()

    if args.all:
        for name, (l, kv, hd, db) in MODELS.items():
            s = sizes(l, kv, hd, db, args.chunk_tokens)
            print(f"{name:14s} per_token={s['per_token_KiB']:.0f} KiB  "
                  f"full_chunk({args.chunk_tokens}tok)={s['full_chunk_MiB']:.1f} MiB  "
                  f"per_layer_chunk={s['per_layer_chunk_KiB']:.0f} KiB")
        return

    if args.model:
        l, kv, hd, db = MODELS[args.model]
    else:
        l, kv, hd, db = args.layers, args.kv_heads, args.head_dim, args.dtype_bytes
    print(json.dumps(sizes(l, kv, hd, db, args.chunk_tokens), indent=2))


if __name__ == "__main__":
    main()
