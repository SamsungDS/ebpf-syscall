# KV-offload I/O: what object size and command size do to an NVMe drive

This recipe records the NVMe I/O an inference engine produces when it offloads a
KV cache to storage, and lets you replay any capture on your own drive. It
answers: **for a real model's KV geometry, how does the size of the offloaded
object, and the size of one device command, change what the drive is asked to
do and how fast it goes?**

## What an "object" is here

PagedAttention keeps the KV cache in fixed-size token blocks that are not
contiguous in GPU memory. To offload, an engine first gathers those scattered
blocks into one contiguous storage object. `--chunk-tokens` is how many tokens
go into one such object; LMCache's default is 256.

The size that produces is not a guess. For Llama-3.1-8B at 256 tokens,
`kv_geometry.py` computes 32 MiB, and LMCache's own chunk-size calculation
(`LocalCPUBackend.get_full_chunk_size_bytes()`, from `kv_shape`, the chunk size
and the dtype) computes the same 32 MiB. Two K/V planes, 32 layers, 256 tokens,
8 key/value heads of 128, two bytes each.

The gather kernel itself runs on the GPU and never appears in a device trace, so
the device sees only the object. That is why this recipe needs no GPU and no
model weights: real model *dimensions* with fake *content* reproduce the real
offload I/O pattern, since the geometry depends on the KV dimensions and the
device's transfer limits, not on tensor values.

**What this does NOT show.** Sweeping `--chunk-tokens` does not tell you whether
one serving stack offloads better than another. Different engines pick different
object sizes, but the device-side difference between them is object size and
nothing else, and every other term in that comparison (cache hit rate, gather
cost, eviction policy) is GPU-side and absent from this capture. Earlier versions
of this recipe labelled the sizes with engine-family names and invited exactly
that reading; they do not appear here.

## What it measures

For each `(model, chunk-tokens, mdts-bytes)` the tool issues the store/load
workload against a real NVMe namespace through LMCache's `raw_block` io_uring_cmd
engine and reports:

- **commands per object** = `ceil(object_bytes / mdts_bytes)` — how the
  object fragments at a given per-command transfer size;
- **real store and load throughput** (MB/s), measured on the device.

`--mdts-bytes` is the engine's per-command split size (≤ the device's MDTS). On a
`/dev/ng` character device (io_uring_cmd passthrough) it is **not** subject to the
128 KiB block-layer dma_opt clamp — but it is subject to two kernel caps: the
namespace's `max_hw_sectors_kb`, and, for buffers on ordinary 4 KiB pages, one
segment per page, so nothing above `max_segments × 4 KiB` (~508 KiB on a stock
kernel) can be mapped: the passthrough rejects it with EINVAL and the drive never
sees it. `--mdts-bytes 0` resolves that cap; `--hugepage` (THP-backed buffers,
`HUGEPAGE=1` for `sweep.sh`) lifts the segment part and leaves `max_hw_sectors_kb`
as the wall. The tool warns up front when a size cannot be mapped, checks every
store and load, excludes failures from its numbers and exits 2 if any failed;
`parse.py` blanks such rows.

## Reproduce

Needs: a raw, writable NVMe namespace character device (`/dev/ngXnY`), root, and a
built kvio engine (`make kvio` from the repo root — needs cargo, torch CPU wheel,
ninja, numba; see `tools/kvio/README.md`). **The namespace is written to — use an
empty spare, never a mounted one.**

```sh
# from the repo root, after `make kvio`
DEV=/dev/ng1n1 bash tools/reproduce/kv-offload-io/sweep.sh   # an EMPTY spare namespace
python3 tools/reproduce/kv-offload-io/parse.py kvio_sweep.txt > results.csv
python3 tools/reproduce/kv-offload-io/plot.py results.csv mdts_effect.png
```

`sweep.sh` loops five models x four object sizes × the per-command
sizes in `MDTS` (default: 128 KiB and the kernel's cap). Each run prints the
geometry, then the measured device throughput with its ok/failed counts.

## Worked example (measured 2026-09-11, Latitude m4-metal-medium, Samsung PM9A3)

`example_results.csv` + `example_mdts_effect.png` are one full run: five models
x four object sizes x 128 KiB, 256 KiB, 512 KiB, 1 MiB and 2 MiB
per command (the drive's MDTS), THP buffers (`HUGEPAGE=1`), kernel 7.0 booted
with `iommu=pt` (`max_hw_sectors_kb=2048`, `max_segments=256`), every store and
load checked. 98 of 100 runs completed every operation; the two blanked rows are
2 MiB commands over buffers the kernel could not map in 256 segments (a THP
shortfall on a 7.9 MiB object; the engine's 4 KiB-page bounce buffer for a
1,124,352 B object that is not a multiple of the block size). Evidence label:
**measured** on the device throughput, **trace-derived** on the KV content (fake
bytes). Llama-3.1-8B, 256-token chunk (32 MiB object):

| per command | commands/object | store MB/s | load MB/s |
|---|---|---|---|
| 128 KiB | 257 | 4191 | 1372 |
| 512 KiB | 65 | 4283 | 2561 |
| 2 MiB | 17 | 4292 | 3584 |

- Restore (load) rises 2.6× (2.0–2.95× across models and both chunk sizes)
  from the 128 KiB clamp to the drive's 2 MiB MDTS and is still rising there.
  Store sits at 4.05–4.39 GB/s at every size: the engine batches an object's
  writes (ring depth 8, one wait), so the drive is at its write ceiling from
  128 KiB up.
- The engine's load path issues one command at a time and waits for each (its
  store path batches), so for restores command size stands in for queue depth;
  the same drive at QD8 is saturated from 256 KiB (the C-tool second witness is
  in the study). LMCache PR #4697 batches those reads; the vendored engine is
  pinned to a ref that predates it, so this example is the pre-#4697 load path.
  Device-side queue depth is not recorded by this recipe — wrap the run in
  `nvme_tp_monitor --disk <ns> --jsonl` to record it.
- 16-token block objects (0.5–8 MiB) gain 1.3–2.1×; at ≤ 1 MiB per object a
  ~1 ms per-object engine floor dominates whatever the command size.

## Queue depth: concurrent streams with the device's depth recorded

`--concurrency N` runs N streams (threads with their own objects and
buffers) that store, then load, at the same time — N requests restoring at
once, or N tensor-parallel ranks. The tool prints each phase's window on
CLOCK_MONOTONIC, the clock `nvme_tp_monitor` stamps commands with, so a
capture taken during the run gives the outstanding-command count the NVMe
driver saw, per phase:

```sh
sudo ./nvme_tp_monitor --disk nvme2n1 --jsonl qd.jsonl --dur 900 &
sudo -E python3 tools/kvio/run_kv_offload_io.py --model meta-llama/Llama-3.1-8B-Instruct \
    --chunk-tokens 256 --num-chunks 8 --device /dev/ng2n1 --engine uring_cmd \
    --mdts-bytes 262144 --hugepage --capacity-gb 64 --concurrency 4 > run.txt
sudo kill -INT %1
python3 tools/reproduce/kv-offload-io/qdepth.py qd.jsonl run.txt --disk nvme2n1
```

`--load-parallelism` and `--ring-depth` pass through to an engine that has
them (LMCache PR #4697); the tool prints which read path the engine has.

`example_qdepth.csv` is one such sweep (2026-09-13, same box class and drive
as above): Llama-3.1-8B × {16, 64, 256}-token objects × {256 KiB, 2 MiB} ×
N ∈ {1, 4, 8, 32} × {the vendored pre-#4697 engine, PR #4697 with
load_parallelism 1 and 4}, 72 runs, every operation completed, depth from the
tracer, on a stock kernel (per-command DMA mapping; the engine does not draw
from the premap pool). Read it as:

- With one command at a time per object, the device depth is exactly N. With
  batched reads it is min(N × chunks, ring 256): one request restoring a
  32 MiB object at 256 KiB runs at a mean depth of 51 and 5.96 GB/s (17.2 →
  5.3 ms), and 256 KiB commands then beat 2 MiB ones.
- Eight one-at-a-time streams saturate the drive at 256 KiB (four at 2 MiB);
  above that the read path no longer moves aggregate throughput.
- Stores are batched by both engines at 3.2–4.4 GB/s; the pre-#4697 write path
  runs to 2637 mean / 4085 max outstanding commands at N = 32 (ring 256), the
  PR caps at 256.
- At 32 threads the marginal host cost is 0.66–0.85 Ginsn/GiB for the
  one-at-a-time engine at either command size, and 1.2–2.2 for the batched one,
  whose `wait_iouring` polls every 10 µs.

## The dma-buf arm: map the staging buffer once

The sweep above drives NVMe passthrough, where the kernel maps every command
for DMA at submission time. Behind a translating IOMMU that mapping, not the
drive, is what bounds a command, and on ordinary pages the segment count bounds
it further. `--hugepage` raises the segment bound; it does not remove the
per-command mapping.

`--dmabuf KIND` removes it. The staging buffer is allocated as memory that is
also a dma-buf, registered with io_uring once, and each fixed read or write is
then issued from that mapping, so one command can be as large as the ceiling
the drive publishes in `max_hw_dmabuf_sectors_kb`. KIND is `udmabuf` (a memfd,
2 MiB hugetlb folios when `--hugepage` is also given), `system_heap`,
`cma_heap`, or any name under `/dev/dma_heap`.

This needs `--engine io_uring` on the block device, because NVMe passthrough
cannot import a dma-buf registration, so it is a separate script:

```sh
DEV=/dev/nvme1n1 bash tools/reproduce/kv-offload-io/sweep_dmabuf.sh
```

It runs each point with no dma-buf and with each exporter, so the comparison is
against the classic path on the same drive in the same session. It needs a
kernel carrying io_uring dma-buf registered buffers and the dma-buf size
ceiling; without them the engine reports the registration refused and falls
back, which shows up as the classic arm's numbers under a dma-buf label.

### Portable logical intent before a device run

`--intent-out` writes `kvio.intent.v1`: the logical KV objects, raw-block's
fixed store metadata, and store/load phase ordering before a drive, DMA
exporter, physical slot, MDTS, or NVMe command split enters the picture. It is
deliberately separate from a device capture. `--intent-only` makes this
artifact on a CPU-only machine without opening a storage device:

```sh
python3 tools/kvio/run_kv_offload_io.py \
    --model meta-llama/Llama-3.1-8B-Instruct --chunk-tokens 256 \
    --num-chunks 4 --intent-out llama.intent.json --intent-only
./kvio intent validate llama.intent.json
./kvio intent plan llama.intent.json --mdts-bytes $((8 * 1024 * 1024)) \
    --dma-ceiling-bytes $((8 * 1024 * 1024)) --out target-8m.plan.json
```

The target plan's logical-component-relative command fragments are **modeled**, not a
claim about that system. Run the intent through the real engine and capture the
result with `nvme_tp_monitor` before claiming what the target drive got. When
performing the dma-buf sweep, set `INTENT_DIR` to preserve one intent artifact
per logical model/chunk workload:

```sh
DEV=/dev/nvme1n1 INTENT_DIR=artifacts/intent \
    bash tools/reproduce/kv-offload-io/sweep_dmabuf.sh
```

No reference run is shipped for this arm yet.

## Three representations of one chunk: BF16 K/V, complete K16/V8, V8-only

LMCache can store the same 256-token chunk three ways: the plain BF16 K/V
object raw_block writes today; a complete K16/V8 object, where V is FP8 with
per-object scales and a codec header; or V8-only split-tier, where only the
encoded V goes to storage and the exact K stays in host memory. They are
different objects with different byte counts, and comparing them is honest
only when every one is derived from the same geometry by the arithmetic the
engine's codec uses.

`kvio representations` derives one `kvio.intent.v1` per representation from
the model's KV dimensions and LMCache's merged asymmetric codec layout (76-byte
fixed header, scale shape, three payload lengths, a hash string table, a CRC,
then `K || V || scales`), plus a manifest binding the intents by digest and
carrying what an intent cannot say: which planes were stored, in what dtype,
what stays in host memory and has to come back over the bus on a restore.
For Llama-3.1-8B at 256 tokens with per-tensor scales:

| representation | stored object | ratio to BF16 | host retained per restore |
|---|---:|---:|---:|
| `bf16_kv` | 33,554,432 B | 1.0000 | 0 |
| `k16_v8` | 25,166,073 B | 0.7500 | 0 |
| `v8_only` | 8,388,857 B | 0.2500 | 16,777,216 B (K) |

Every number is labelled derived. The header depends on strings the codec
writes at runtime (`--codec-hash KEY=VALUE` supplies them; unsupplied hashes
are written empty, as the codec does), MLA models are refused because their
latent cache has no separable K and V, and the manifest records the padding
and alignment it charges. Whether the engine writes exactly these bytes is a
question for a GPU host with the real serde.

`sweep_representations.sh` replays all three on one raw namespace with the
device's command stream recorded around each timed phase, and
`parse_representations.py` joins the intent, the engine's manifest and the
capture into one row per cell, ending with the bytes the device actually
moved against the bytes the intent said it would:

```sh
DEV=/dev/disk/by-id/nvme-eui.<id> OUTROOT=out ADVERTISED_MDTS_BYTES=<bytes> \
    STREAMS="1 4 8" SIZES="524288 1048576 2097152" REPEATS=3 PAD=0 \
    bash tools/reproduce/kv-offload-io/sweep_representations.sh
python3 tools/reproduce/kv-offload-io/parse_representations.py out > cells.csv
```

Two things the first runs of this arm showed, both worth knowing before
reading any number from it:

- **An encoded object is a few hundred bytes past a block boundary**, because
  of its header and scales, and an O_DIRECT engine then has an unaligned tail.
  raw_block moves that through a bounce buffer and, since a dma-buf-registered
  slot is refused the bounce, the whole object silently leaves the map-once
  path and lands on per-command mapping at the 128 KiB clamp, while the tool's
  own projection still reports the map-once command count. `PAD=1` rounds the
  stored object up to the block size, charged as `padding` in the manifest,
  which is what an engine has to do to keep the registration. Run both.
- **A drive's limits are what it has been seen to accept.** Pick `SIZES` at
  or below command sizes the drive has completed cleanly in a prior run, and
  treat anything larger as a separate failure probe with a hard timeout and
  the capture running, so a request the controller refuses stops that cell
  rather than the sweep.

### Worked example (measured 2026-09-20, udmabuf)

`example_representations_unpadded.csv` and `example_representations_padded.csv`
are two full runs of the sweep above on one raw NVMe namespace (4 KiB LBA,
128 KiB per-command clamp on the regular path, commands of up to 2 MiB on the
dma-buf path). Three
representations x {128 KiB classic control, 512 KiB, 1 MiB, 2 MiB udmabuf} x
streams {1, 4, 8} x 3 repetitions, 8 chunks per stream, 3 timed passes after
one warm-up; every cell's device stream captured, zero drops, zero non-zero
NVMe status, and the device's bytes within 0.1 per cent of the intent's in
every one of the 216 cells (the difference is the 4 KiB store metadata and
the tail). `summarize_representations.py` produces the tables; at 8 streams
and 2 MiB commands:

| representation | padded | device read commands | store MB/s | load MB/s |
|---|---|---|---:|---:|
| `bf16_kv` | n/a (already aligned) | 3,072 x 2 MiB | 6,870 | 14,147 |
| `k16_v8` | no | 36,864 x 128 KiB | 2,706 | 2,744 |
| `k16_v8` | yes | 2,304 x 2 MiB | 6,885 | 14,184 |
| `v8_only` | no | 12,288 x 128 KiB | 3,517 | 3,971 |
| `v8_only` | yes | 768 x 2 MiB | 7,065 | 13,504 |

Read it as three statements, each of which the capture supports directly:

- **The byte ratios are physical.** 0.75x and 0.25x of the BF16 object is
  what the drive wrote and read, header, scales and tail charged.
- **Unpadded, every encoded object ran at the 128 KiB clamp** regardless of
  the requested command size and the successful map-once registration, at
  roughly 2.5 to 4x lower throughput than the aligned BF16 object on the same
  path. Padded to the physical block, all three representations run at the requested
  command size and reach the same drive ceiling, about 7 GB/s store and
  14 GB/s load at 4 or more streams.
- **No representation moves faster than another once aligned.** At equal
  offered load the drive is the ceiling for all three; V8-only's value is the
  bytes it does not move and the host writes it does not incur, not a higher
  storage-leg rate. At one stream its smaller objects sit closer to the
  per-object latency floor and load at about 6 GB/s against 11 GB/s for the
  32 MiB object.

The raw per-cell tree of device captures, 2.3 GB, is not shipped; the CSVs
here are the parsed rows.

## Replay

A device capture (`kvio record`, i.e. `nvme_tp_monitor`) of any of these runs
turns into a certified fio v3 iolog with `kvio iolog`
(`examples/replay/mk_dev_iolog.py`), and `kvio compare` checks a re-recorded
replay against it (operation, offset, length, order, timing reported separately).
The replay claim is exact-request translation, not that fio/Linux/controller
execute an identical device stream — see the repo `CLAUDE.md` and
`tools/kvio/PRIVACY.md` for the exact boundary.

## Limits of this recipe

- **Content-free.** It reproduces I/O *geometry and device throughput*, not cache
  hit-rate, GPU-gather cost, or model quality. The other half of the object-size
  trade-off, that a smaller object raises the cache hit rate, is a GPU-side
  effect this recipe does not measure.
- **The GPU gather is off-trace.** The device sees the gathered object; the
  kernel that produced it is not in this capture.
- **Write throughput** here is a single-namespace, QD-modest raw_block figure, not
  a tuned drive-saturation number.
- **The command size here is a request, not an outcome.** `--mdts-bytes` asks
  the engine to split at a size; what the drive gets is bounded by the kernel
  caps above and, on a translating IOMMU, by the per-command DMA mapping. The
  dma-buf arm below is what lifts that bound.
- Full study and projections: `~/reports/kv-offload-io-study-20260910/`.
