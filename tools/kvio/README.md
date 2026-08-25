# kvio — KV-cache storage IO: project, drive, record, attribute, replay

`kvio` is a user tool of this tree, built like the tracers are. It answers, end
to end, "what storage IO does a KV cache issue, and can I reproduce it?":

- **project** the NVMe command stream a *GPU model × KV-cache config* would
  issue — GPU-free, no model, no serving stack (`kvio plan`);
- **drive** a real device with that IO using **LMCache's actual raw_block
  engine** — the real thing, vendored and built in this tree, not a mimic
  (`kvio workload`, `kvio sweep`);
- **record** what the device really received (`kvio record`, the
  `nvme_tp_monitor` eBPF tracer);
- **attribute** each device command to the KV object that caused it — the
  offset-join: device offset + time window, zero engine cookies
  (`kvio perfetto`);
- **replay** the exact command stream through fio and grade it
  (`kvio iolog`, `kvio compare`).

## Build and run

```
make            # the tracers (kvio record needs nvme_tp_monitor)
make kvio       # the engine: builds the vendored Rust crate -> ./kvio appears
./kvio doctor   # verifies the build, python deps, tracers
./kvio --help   # the command list
```

`make kvio` needs **cargo** (https://rustup.rs) and python3. The engine-driving
commands also need the Python deps listed in `vendor/lmcache/PROVENANCE.md`
(torch's **CPU wheel is fine** — kvio is GPU-free, which is not the same as
torch-free: the vendored LMCache modules import torch at module level). Build on
a real machine, not a laptop-class box.

A typical loop on a box with a free NVMe namespace:

```
./kvio plan --model Llama-3.1-8B --chunk-tokens 256 --op store  # IO to expect
sudo ./kvio record --disk nvme0n1 --jsonl dev.jsonl &      # watch the device
sudo ./kvio workload --model meta-llama/Llama-3.2-1B-Instruct --tp 1 \
     --device /dev/ng0n1 --engine uring_cmd --odirect \
     --num-requests 200 --sem-out sem.jsonl                # drive it for real
./kvio perfetto --join-by-offset --ebpf dev.jsonl --sem sem.jsonl \
     --out kv.pftrace                                      # attribute
./kvio iolog dev.jsonl nvme0n1 > dev.iolog                 # device-exact replay
fio --read_iolog=dev.iolog --direct=1 ... && ./kvio compare ...    # grade it
```

(Flags above are real — see each subcommand's `--help`; `kvio plan` uses
built-in model geometry names, `kvio workload` takes a curated-catalog
name (tools/kvio/modelconfig.json) or any HF model id; `--engine uring_cmd`
wants the /dev/ngXnY char device. The
semantic JSONL comes from the tool itself: the engine's public
`entry_offset()` tells it where each object landed, so no engine tracing
hook is needed — the offset-join's zero-engine-change promise, kept.)

## Why the LMCache engine is vendored here (the standalone decision)

kvio *uses* LMCache's raw_block engine so its IO is byte-identical to real
KV-offload traffic — that is the tool's credibility. It used to require an
LMCache checkout/install; that coupling was re-evaluated (2026-08-25) and cut
down to a vendored, periodically-synced surface, for three measured reasons:

1. **The deep coupling is already gone.** Attribution once required patching
   LMCache's engine (a `trace_id` io_uring `user_data` cookie); the
   **offset-join** replaced it — attribute by device offset + time window,
   validated at 100% parity (111,435/111,435 commands) — so kvio needs **zero
   LMCache modifications**. What remains is plain *use* of upstream code.
2. **The surface kvio uses is small and slow-moving.** The runtime import
   closure of the modules kvio touches is ~110 Python files (the raw_block
   wrapper + ObjectKey + memory management + the dynamically-selected
   platform/device layer) plus two native modules. Measured against live
   upstream: those paths see **~2–5 commits/month each**, while LMCache
   overall moves **~150 commits/month**. Forking LMCache would be a
   treadmill; vendoring the closure is a monthly chore.
3. **The engine is native code and must be built** — twice. `RawBlockCore`'s
   data path is the Rust pyo3 module `lmcache_rust_raw_block_io`
   (`rust/raw_block`), and the device-ops layer underneath it needs
   `lmcache.lmcache_native`, a torch C++ extension (`csrc/lmcache_native`).
   `make kvio` builds both (cargo for the Rust crate; `build_native.py`
   replicates upstream's exact CppExtension spec). That is why kvio is a
   *built* tool, not a script — and why you build it with the same python
   you will run it with (both extensions link that interpreter's ABI/torch).

The sync mechanism is `sync-lmcache.sh`: it **computes the runtime import
closure from the pinned upstream ref itself** (so upstream refactors change the
vendored set instead of silently breaking it), vendors those files + the Rust
crate, records `vendor/lmcache/PROVENANCE.md` (exact commit, file list, Python
deps), and **fails loudly if a public symbol kvio calls disappeared upstream**
— an API break, the only sync event that actually needs a human. Run it monthly:

```
LMCACHE=~/devel/lmcache REF=upstream/dev tools/kvio/sync-lmcache.sh
make kvio    # rebuild the engine if rust/raw_block changed
```

`vendor/lmcache/` is machine-managed — never hand-edit it. Upstream is
https://github.com/LMCache/LMCache (Apache-2.0), pinned in PROVENANCE.md.

## What lives where

- `kvio` (this dir) — the CLI; dispatches subcommands.
- `workload.py`, `run_kv_offload_io.py`, `kv_geometry.py` — the engine-driving
  workload generators (serving-shaped request mix; single-request generator;
  model KV geometry).
- `../../examples/lmcache/kvio_*.py`, `../../examples/replay/*` — projection,
  validation, attribution, conversion, and replay-grading, reached via the CLI.
- `vendor/lmcache/` — the vendored LMCache surface (Python closure + Rust
  crate); `build/` — the compiled engine module (`make kvio`).
