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
  sees, with stable `seq`, capture-time `lba_bytes`,
  `slba`/`bytes`/`ts`, and completion `lat_ns`. This is the
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
   `nvme_tp_monitor` capture into a fio v3 iolog and certificate. The
   static claim is exact translation of ordered operation/offset/length
   requests, with timestamps quantized from ns to fio's µs. It is not a
   claim that fio, Linux, or the controller executes the same device
   stream. Re-record the fio run and use `compare_streams.py`, which
   reports operation, offset, length, tuple-order, and timing separately.

### Keep capture, replay bundles, and releases separate

A device capture omits payload bytes, keys, and application contents, but it
still exposes exact placement, request timing, device identity, queue details,
and a potentially identifying access pattern. The current fio bundle preserves
exact offsets and timing and includes a source-trace digest. It is a fidelity
artifact for confidential internal use, not a sanitized release format.

Do not describe either artifact as anonymous or safe to publish. The bounded
`bank-local-results-v1` draft contains no trace, exact measurement, path, or
free text, but its verifier deliberately reports `export_allowed: false`.
A future trace release must use a separate allowlisted grammar, rebuild every
sidecar, omit source digests and real paths, name its residual disclosures,
and pass independent release review. Bundle conformance, internal privacy and
utility evidence, and human export authorization are three different verdicts.
The public design boundary and implementation status live in
`tools/kvio/PRIVACY.md`; do not invent a stronger claim in another page.

`tools/reproduce/gnn-readamp/` remains the worked payload-free example: a GNN
reading node features off an SSD at 431× read amplification, charted A/B
against the page-aware fix. Its historical replay matched counts, bytes, and
sizes; it did not establish ordered-offset or correctly paced runtime fidelity.

## The kvio tool (`make kvio` → `./kvio`)

`tools/kvio/` is the user-facing KV-cache-IO tool: one `./kvio` entry
point over the whole loop — `plan` (GPU-free projection), `trace`
(compile real agent requests into an evidence-labeled cache plan),
`workload`/`sweep` (drive a device with **LMCache's real raw_block
engine**, vendored in-tree), `record` (the `nvme_tp_monitor` tracer),
`perfetto` (offset-join attribution),
`iolog`/`compare` (certified fio translation plus runtime comparison), and
`bench`/`bench-compare`
(repeatable sustained storage pressure and A/B comparison). Davidlohr
Bueso's kvspill prototype is the lineage of the benchmark commands, not
a separate current tool; keep usage in the kvio documentation and
history on the kvspill lineage page. The engine's data path is a Rust
pyo3 module: `make kvio` builds the vendored crate (needs cargo; build on
a real box). `tools/kvio/sync-lmcache.sh` refreshes the vendored LMCache
surface (runtime import closure + Rust crate) from a pinned upstream ref
and fails loudly on an upstream API break; `vendor/lmcache/` is
machine-managed — never hand-edit it. Rationale and measured churn:
`tools/kvio/README.md`.

Agent traces are not device traces. LMCache agent traces contain prompt
text and require a pinned tokenizer before chunk reuse can be derived.
TraceLab removes prompt text but retains observed prefix/cache token
accounting, so its session-relative chunk identity is explicitly modeled.
Keep request timing and session boundaries, pin the dataset artifact, label
the output `trace-derived`, and never turn one source into a universal
`agent` benchmark. `docs/kvio.rst` records the current source revisions and
the OpenCode, Aider/RepoAgent, TraceLab, and TauBench contribution lanes.

## Reproduce recipes

Every showcase effort gets its own `tools/reproduce/<effort>/` with a
README and the scripts to regenerate its capture, trace, and figures
from scratch. Do not wedge a new effort into an existing recipe dir.

## Git commit practices

- **Lead with the plain-English purpose**; explain in prose what changed
  and *why*. No plan codenames (E6/E7/P4/"Phase N") in commits, comments,
  or docs — say what the thing does.
- Write for a maintainer who knows this repository but has never heard
  of the proposed feature. A feature commit's first paragraph must
  define what it does, identify the existing gap, distinguish it from
  the current path, and explain why the repository should accept it.
- Give a concrete operation or scenario when the feature or workload
  name is not self-explanatory. Use plain language and define necessary
  acronyms at first use.
- Derive exact object sizes, block sizes, queue depths, rates, and other
  constants, or cite the source and configuration that produced them.
  Never leave a magic value for the reviewer to reverse-engineer.
- Label benchmark workloads as measured, trace-derived, calibrated, or
  synthetic. Do not describe a guessed microbenchmark as real or
  representative. Explain why the workload matters, name the exact
  boundary of its evidence, and say how later measured cases can extend
  it.
- Imperative mood; small atomic commits.
- Wrap the subject and body at 72 columns.
- Performance claims must be backed by measured data in the commit, with
  the hardware named.
- When an AI agent materially authors a change, add the repository's normal
  `Co-Authored-By:` trailer naming that agent, immediately before the human
  `Signed-off-by:`. Name only the agent that actually did the work. Do not add
  session IDs or substitute a different agent or model.
- Never `git push`; the maintainer pushes.
