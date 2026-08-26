# CLAUDE.md

Guidance for AI agents (Claude Code, Codex, Gemini) working in this
repository. Human contributors: this is also the map of how the tracing,
visualization, and replay pieces fit together.

## What this repository is

ebpf-syscall is the **tooling and the value showcase** for observing real
storage IO at the layer where it actually happens — syscalls, io_uring,
mmap page faults, and NVMe device commands — and turning those captures
into things you can *look at* (Perfetto timelines) and *reproduce*
(fio replays). The recurring idea across every tool here is the
**two-witness join**: the application knows *intent* (what it asked for),
the kernel/device knows *mechanism* (what actually moved), and the
interesting number is always the gap between them.

## The two trees, and what goes where

There are two repositories. Keep the boundary sharp:

- **ebpf-syscall (this tree)** — the tracers, the converters, the replay
  tools, and the **value showcase**: the `docs/*.html` case studies that
  explain *what a capture reveals and why it matters*. When the work is
  "here is a capability of ebpf-syscall and here is the story it tells,"
  it lives here, as a `docs/` page plus a `tools/reproduce/<effort>/`
  recipe. **The showcase of ebpf-syscall's value lives in ebpf-syscall.**

- **kvio-perfetto-gallery** (`github.com/mcgrof/kvio-perfetto-gallery`) —
  a *data* repository: ready-to-view `traces/*.pftrace.gz` demo traces
  plus their screenshots and machine-readable reports. **Upload demo
  traces there; do not add tooling there.** Each trace gets a README
  section (what it shows, on what hardware, with which tool commit) and
  its sha1 in the checksum table. A gallery trace should link back to the
  ebpf-syscall `docs/` page that tells its full story.

Rule of thumb: a *trace* is a demo artifact → gallery. The *explanation
of why the trace matters*, and the *tools that made it* → here.

## The tracers (mechanism witnesses)

Each is a `*.bpf.c` + userspace loader, built by the `Makefile`. All
attach via BTF (`fentry`/`tp_btf`), so the running kernel needs
`CONFIG_DEBUG_INFO_BTF=y` and `/sys/kernel/btf/vmlinux`.

- `syscall_monitor` — read/write/pread/pwrite etc., correlated
  enter+exit with `{fd, offset, count, ret}`. The intent at the syscall
  layer.
- `iouring_monitor` — io_uring submission/completion intent.
- `mmap_readamp` — demand faults via `filemap_fault`, attributed to
  `(dev, inode, pgoff)`; `--stream` records every fault for replay. The
  page-fault read-amplification witness.
- `nvme_uring_cmd_monitor` — `io_uring_cmd` NVMe passthrough on
  `/dev/ng*`, carrying LMCache's `trace_id` in `user_data` (the kvio
  path). Device commands *with* a semantic join key.
- `nvme_tp_monitor` — driver-level NVMe commands via the nvme
  tracepoints (`--disk`, `--jsonl`): every `read`/`write` the device
  sees, with `slba`/`bytes`/`ts` and completion `lat_ns`. This is the
  ground truth for O_DIRECT / block-layer IO that carries no `user_data`
  (plain `pread`, fio, a GNN feature store). Same JSONL schema the replay
  tools consume.

## The Perfetto workflow: capture → convert → visualize → replay

Perfetto's stock ingestion does not see `io_uring_cmd` passthrough or the
semantic layer, so the converters are the only way in. All emit a
`.pftrace` you drag onto <https://ui.perfetto.dev> (local WASM; nothing
uploads). `pip install perfetto`.

1. **Capture** with the tracer that matches the layer (above), to JSONL.
2. **Convert** with the matching converter in `examples/`:
   - `examples/lmcache/kvio2perfetto.py` — the kvio stack: LMCache
     semantic object ops + `nvme_uring_cmd_monitor` device commands +
     serving spans, joined by `trace_id`; A/B arms via `--merge`.
     `kvio_tp_report.py` runs SQL metrics over the result.
   - `examples/lmcache/mmap2perfetto.py` — an `mmap_readamp --stream`
     fault log: one track per mmap'd file, faults as slices, read-amp and
     major-fault counters.
   - `examples/replay/readamp2perfetto.py` — a device read-amplification
     A/B from `nvme_tp_monitor` captures plus a driver's intent markers:
     each arm's *useful MB* (intent) laid under its *device MB*
     (mechanism), the gap being the amplification, plus the LBA-scatter
     access-pattern axis.
3. **Visualize**: drag the `.pftrace` onto ui.perfetto.dev; or render a
   static A/B PNG straight from the capture (see the reproduce recipes).
4. **Replay** (device layer): `examples/replay/mk_dev_iolog.py` turns an
   `nvme_tp_monitor` capture into a fio v3 iolog — op/offset/length/time
   and nothing else — and `fio --read_iolog --direct=1` reissues the
   exact command stream. `compare_streams.py` grades replay vs capture at
   the NVMe layer (the layer that matters: a *perfect* file-level log can
   still produce an 8× different device stream — see
   `examples/replay/README.md`).

### Why the replay path is the privacy story

Because a device capture and its iolog carry only IO *shape* — no bytes,
no keys, no features — a third party can run a **confidential** workload
(a financial-fraud GNN, a private KV cache), capture it with these
tracers, and hand back a trace or iolog we can replay and visualize
without ever seeing their data. `tools/reproduce/gnn-readamp/` is the
worked example: a GNN reading node features off an SSD at 431× read
amplification, captured, charted A/B against the page-aware fix, and
replayed from a data-free iolog at +0.0% command inflation.

## Reproduce recipes

Every showcase effort gets its own `tools/reproduce/<effort>/` with a
README and the scripts to regenerate its capture, trace, and figures
from scratch. Do not wedge a new effort into an existing recipe dir.

## Git commit practices

- **Lead with the plain-English purpose**; explain in prose what changed
  and *why*. No plan codenames (E6/E7/P4/"Phase N") in commits, comments,
  or docs — say what the thing does.
- Imperative mood; small atomic commits.
- Performance claims must be backed by measured data in the commit, with
  the hardware named.
- Trailer: `Co-Authored-By: Claude <...>` + `Signed-off-by:`. Do **not**
  add `Claude-Session` trailers.
- Never `git push`; the maintainer pushes.
