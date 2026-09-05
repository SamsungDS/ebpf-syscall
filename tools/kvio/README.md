# kvio — KV-cache storage IO: project, record, replay, benchmark

`kvio` is a user tool of this tree, built like the tracers are. It answers, end
to end, "what storage IO does a KV cache issue, can I reproduce it, and can the
storage tier sustain it?":

- **project** the NVMe command stream a *GPU model × KV-cache config* would
  issue — GPU-free, no model, no serving stack (`kvio plan`);
- **drive** a real device with that IO using **LMCache's actual raw_block
  engine** — the real thing, vendored and built in this tree, not a mimic
  (`kvio workload`, `kvio sweep`);
- **compile real agent traces** into chunk-level cache plans with explicit
  evidence and assumptions (`kvio trace`, then `kvio workload --agent-plan`);
- **record** what the device really received (`kvio record`, the
  `nvme_tp_monitor` eBPF tracer);
- **attribute** each device command to the KV object that caused it — the
  offset-join: device offset + time window, zero engine cookies
  (`kvio perfetto`);
- **export** the exact requested command stream to fio and grade the
  re-recorded device result (`kvio iolog`, `kvio compare`);
- **benchmark** sustained restore, prefix, interference, and eviction pressure
  for storage and kernel A/B tests (`kvio bench`, `kvio bench-compare`).

## Build and run

```
make            # the tracers (kvio record needs nvme_tp_monitor)
make kvio-ir    # the independent Rust fio-bundle verifier
make kvio       # the engine: builds the vendored Rust crate -> ./kvio appears
./kvio doctor   # verifies the build, python deps, tracers
./kvio --help   # the command list

# optional system installation after both builds succeed
sudo make install
man kvio
```

The install honors `prefix`, `bindir`, `libexecdir`, `mandir`, and `DESTDIR`.
It installs the supported tracers and replay tools as well as `kvio`. The
optional NVMe smoke generators remain development tests and are not installed.

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
./kvio iolog dev.jsonl /dev/source --bundle-dir replay     # certified fio export
KVIO_TARGET=/dev/nvmeXnY fio replay/replay-block.fio       # issue the requests
./kvio compare run:dev.jsonl:replay.jsonl                  # grade device result
```

(Flags above are real — see each subcommand's `--help`; `kvio plan` uses
built-in model geometry names, `kvio workload` takes a curated-catalog
name (tools/kvio/modelconfig.json) or any HF model id; `--engine uring_cmd`
wants the /dev/ngXnY char device. The
semantic JSONL comes from the tool itself: the engine's public
`entry_offset()` tells it where each object landed, so no engine tracing
hook is needed — the offset-join's zero-engine-change promise, kept.)

## Which command answers which question?

The commands form two different workflows. Capture and replay preserve an
observed request stream. Benchmarking applies controlled sustained pressure;
it does not recreate a capture.

| Command | Input | Result | Device access |
|---|---|---|---|
| `kvio plan` | Model and cache geometry | Predict command sizes and counts; no application timing or reuse | No |
| `kvio trace` | An application-level agent trace | Compile observed requests into a cache load/store plan | No |
| `kvio workload` | Model settings or an agent plan | Issue cache loads and stores through LMCache's real storage engine | Yes; may write |
| `kvio record` | A selected NVMe namespace | Observe the commands that actually reach the NVMe driver | Read-only observation |
| `kvio perfetto` | Semantic records plus a device capture | Attribute device commands to cache objects and make a timeline | No |
| `kvio iolog` | A device capture | Export the captured requested stream as a fio replay bundle | No |
| `kvio fio-certify` | A fio replay bundle | Check that the bundle still describes the captured requested stream | No |
| `kvio compare` | Original and replay device captures | Report what fio and the storage stack actually preserved | No |
| `kvio release-build` | A bounded result draft | Build a two-file results-only candidate with no source trace | No |
| `kvio release-example` | No input | Print the canonical result draft | No |
| `kvio release-verify` | A results-only candidate | Check its closed grammar, inventory, and payload hash | No |
| `kvio bench` | An evidence-labeled stress profile | Run sustained storage pressure without claiming capture fidelity | Yes, including writes |
| `kvio bench-compare` | Results from repeated benchmark runs | Compare the median results of two configurations | No |

The exact-replay path is therefore `record` → `iolog` → `fio-certify` → run
fio while recording again → `compare`. The agent path begins one level above
that: `trace` → `workload`, with `record` running alongside it. `bench` and
`bench-compare` are a separate controlled-load path.

## Build a results-only candidate

`kvio release-build` is the first narrow release boundary. It accepts only a
closed set of storage questions, metrics, coarse ratio bands, evidence labels,
and residual-disclosure labels. It rejects free text, exact numerical results,
paths, source hashes, unknown fields, duplicate keys, and non-draft status.

```bash
./kvio release-example > result.json
# Edit only values allowed by the example's closed enumerations.
./kvio release-build result.json candidate
./kvio release-verify candidate
```

The candidate contains only `result.json` and `manifest.json`. The verifier
rejects extra files, symlinks, changed bytes, unsupported schemas, and malformed
inventory. The 64 KiB input ceiling is more than 100 times the 617-byte example
while still bounding parser memory for this deliberately small format.
The reported ratio is candidate divided by baseline; `PRIVACY.md` defines the
bucket endpoints and explains that they are disclosure boundaries, not
statistical or service-level thresholds.

Successful verification reports `bundle_conformance: pass`, but also reports
`internal_evidence: not_checked`, `release_authorization: not_checked`, and
`export_allowed: false`. The command does not inspect the confidential source,
run privacy attacks, authenticate reviewers, or authorize transfer. Connect
those decisions to the organization's existing review and signing systems
before any candidate leaves its boundary.

## Privacy and fidelity boundary

`kvio record` uses `nvme_tp_monitor`, which records device-request metadata
without recording payload bytes, prompts, tensors, feature values, graph
contents, or KV keys. `kvio iolog` reduces that to operation, exact byte
offset, length, and relative time. This is payload-free and data-minimized,
not automatically anonymous: offsets expose locality and address range, timing
exposes cadence, and a distinctive pattern can identify a workload. The
separate `nvme_uring_cmd_monitor --kv` path records `key_hex` and requires an
additional privacy review before sharing.

There are three separate artifacts and decisions:

1. A **capture** is confidential source evidence. It includes device scope,
   exact placement, issue timing, queue metadata, and completion observations.
2. A **fio replay bundle** is a confidential fidelity artifact. It preserves
   exact placement and timing, and its current certificate contains a digest of
   the source capture. `fio-certify` checks translation, not release safety.
3. An **external release** needs an allowlisted format and approval process.
   kvio implements a bounded results-only draft and format checker, but not
   evidence authentication or release authorization. Do not export a current
   capture or replay bundle merely because it contains no payload bytes.

New capture schema v1 files begin with one `capture_meta` record, bind the
stream to one `--disk` scope, and end with exactly one `drops` record. The
replay tools reject duplicate JSON keys, unknown schema versions, mixed
device/namespace commands, and a non-terminal drops record. Old unversioned
captures require `--allow-legacy-capture`; that option permits inspection but
cannot add the missing scope guarantee.

Fidelity has two gates. `kvio iolog` and the independent Rust
`kvio fio-certify` check the finite requested stream before execution. Run fio
under a second `kvio record` capture and use `kvio compare` to check the
ordered operation/offset/length tuples actually issued by the runtime. The
comparison also reports rebased issue-time errors and completion-latency
distributions. It does not yet pair original and replay completions one by one,
and it does not measure application end-to-end latency.

The DGraphFin example in `../../docs/gnn-readamp.rst` shows the method: a
page-aware GNN access pattern reduced `RA_signal` from 431× to 8.6× without the
published trace carrying graph or feature contents. The remaining sanitizer,
hardware replay, pacing, concurrency, and latency work is tracked explicitly
in [`TODO.md`](TODO.md). [`PRIVACY.md`](PRIVACY.md) defines the bank-local
release strategy, threat model, and language the project can defend. The
installed `kvio(1)` manual summarizes all three.

## Compile captured agent requests

`kvio trace` closes the gap between a synthetic hit-rate and a real agent
trajectory. LMCache agent traces contain prompts, so kvio uses a pinned
tokenizer and content hashes to derive prefix or shifted-chunk reuse. TraceLab
removes prompts for privacy, so kvio consumes its observed token/cache split
and records that logical chunk identity is modeled. Both preserve timestamps
and sessions in the plan; neither is mislabeled as captured device IO.

```
./kvio trace lmcache-agent-trace/opencode/gpt-5-mini-task1.jsonl \
  --out opencode.json --format lmcache-agent \
  --tokenizer tiktoken:gpt-5-mini \
  --tokenizer-revision tiktoken-0.12.0 \
  --source-revision 780bcc2979715150d8b9fd4737e026e625444cc9
sudo ./kvio workload --agent-plan opencode.json \
  --model Qwen/Qwen2.5-Coder-32B-Instruct --chunk-tokens 256 \
  --device /dev/ngXnY --engine uring_cmd --sem-out sem.jsonl
```

The plan uses complete chunks only. `--policy prefix` models ordinary
prefix-key lookup, `--policy substring` recognizes exact complete chunks after
a shift, and `--capacity-chunks` enables LRU eviction. The latter is a simple
content-reuse policy, not a claim that kvio implements CacheBlend.

## fio interchange and the exact claim

`kvio iolog` converts a measured NVMe capture to fio v3 microsecond timestamps,
preserves equal-timestamp order, requires a versioned single-scope capture and
its LBA size, and rejects drops or unsupported commands. `--bundle-dir` emits
the iolog, block and
NVMe-passthrough job files, normalized IR, checksums, and a translation
certificate. The certificate establishes that reparsing the fio artifact gives
the same ordered operation/offset/length sequence. It does not establish that
fio, Linux, or the controller executes that request stream unchanged, and it
does not claim equal performance. Re-record the fio run and use `kvio compare`
for those runtime facts.

Build the independent Rust validator and run it against the bundle:

```bash
make kvio-ir
./kvio fio-certify replay
```

`kvio-ir` reads `workload.json`, `commands.iolog`, and `certificate.json`.
It checks their hashes and command counts, validates contiguous sequence
numbers, nondecreasing timestamps, block alignment, checked byte ranges, and
the exact fio parse/emit result. Optional `--region-bytes` and
`--max-transfer-bytes` arguments also check that each command stays within a
declared device region and transfer limit. This is exhaustive validation of
one finite bundle; it is not a claim about fio or device runtime behavior.

For example, suppose the capture contains this command:

```text
read 4096 bytes starting at byte offset 4096
```

The offset is counted from zero, so this reads the second 4096-byte block. The
matching fio line is:

```text
0 /dev/source read 4096 4096
```

If the exported line instead says `0 /dev/source read 8192 4096`, fio will
accept it because the syntax and alignment are valid. But it will read the
third block, not the second block recorded in the capture. That is a valid fio
command but an invalid translation: the replay now targets a different device
region, changes the spatial access pattern, and can map to a different KV-cache
object. `kvio fio-certify` rejects that mismatch before fio runs.

The crate also owns checked alignment and gap-free transfer splitting. Run
ordinary and property tests with `make kvio-ir-test`. Bounded Kani proof
harnesses cover timestamp rounding, logical-block multiplication, alignment
overflow, and split coverage; run them with `make kvio-ir-kani`. A bundle is
not Kani-verified merely because the harnesses exist: the Kani target must
finish successfully. Rust string formatting and parsing are covered by
generated round-trip tests and the exhaustive check of each bundle, not by
Kani.

This export path is inspired by and interoperates with the pending fio
[`iolog-device-record`](https://github.com/mcgrof/fio/tree/iolog-device-record)
branch, including its single-stream and object-sharded replay modes.

## Benchmark sustained storage pressure

`kvio bench` runs controlled fio load against a raw namespace. It complements
capture and replay: use the benchmark to compare sustained headroom and
same-device interference; use an iolog replay when observed timing, offsets,
and command order must be preserved.

```
./kvio bench --list-profiles
sudo ./kvio bench /dev/nvmeXnY \
  --yes-really-use-device --size 8GiB --reps 3 \
  --output-dir results/baseline
./kvio bench-compare results/baseline/results.jsonl \
                     results/candidate/results.jsonl
```

The command preconditions its test region and includes a write workload. Use
only a verified-empty, disposable, unmounted namespace. It refuses mounts,
partitions, holders, undersized targets, and disk signatures unless signatures
receive a separate acknowledgement.

Every built-in is labeled `measured` or `synthetic`. Only
`restore-calibrated` comes from a recorded KV-cache setup; its 7 MiB object size
is specific to Qwen2.5-1.5B-Instruct at TP1, bf16, and 256-token chunks. The
other built-ins are controlled stress shapes, not captured production traffic.
Use `--profile FILE` to add another sustained workload with its evidence source,
or use capture plus iolog replay for a certified requested stream, then
re-record it before claiming device-level equality.

Davidlohr Bueso's standalone
[`kvspill`](https://github.com/davidlohr/kvspill) prototype supplied the initial
workload shapes, preconditioning, result parsing, and A/B comparison. They now
live only in the `kvio bench` interface, with his authorship retained. The
[kvspill hostname](https://kvspill.kvcache.io/) records that lineage; current
usage belongs here and on [kvio.kvcache.io](https://kvio.kvcache.io/#bench).

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
