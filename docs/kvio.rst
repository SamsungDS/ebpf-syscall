kvio GPU-free KV-cache-offload storage-IO toolkit
==================================================

.. note::

   A styled standalone version of this page (identical content, dark
   theme) is served at `/showcase/kvio.html </showcase/kvio.html>`__
   and via htmlpreview from the repository's ``docs/kvio.html``.


Project, issue, replay, and benchmark the NVMe I/O that LLM KV-cache offload
produces — from real model geometry, on real hardware, *without a GPU or a
model*.  kvio can validate command geometry against a captured application or
apply sustained KV-like pressure directly to a storage tier.

**engine:** LMCache ``raw_block`` io_uring_cmd passthrough **tracer:** eBPF ``nvme_uring_cmd_monitor`` **needs:** an NVMe char device (``/dev/ngXnY``) **GPU:** not required **validated:** byte-exact on real NVMe **source:** `mcgrof/LMCache @ ``kvio`` <https://github.com/mcgrof/LMCache/tree/kvio>`__


What it is
----------

Storage and systems engineers need to evaluate the disk I/O of LLM KV-cache offload — command sizes, counts, volume, latency — but that I/O normally only exists behind a GPU running a model through vLLM + LMCache. **kvio removes the GPU from that loop.**

The key observation: **storage I/O geometry is content-independent.** How many NVMe commands a KV store/load produces, and how big each one is, depends only on the KV block size and the device's transfer limit — not on the actual tensor values. So *real model dimensions + fake bytes* reproduce the real offload I/O pattern. kvio computes the block size from real model geometry, issues that store/load workload through LMCache's real ``raw_block`` NVMe-passthrough engine, and confirms the result against the actual device commands captured by an eBPF tracer.

**scope** A GPU is only needed to capture real *access patterns and timing* — which chunk is stored when, hit vs. miss. The I/O *geometry* for any given model is fully determined and reproduced here, GPU-free.

How it works
------------

kvio is a two-phase model layered on top of LMCache's real storage engine.

**1 Project / generate**


From a model config (the LMCache `KV-cache calculator <https://github.com/LMCache/LMCache/tree/dev/examples/kv_cache_calculator>`__'s ``modelconfig.json``) and a chunk size, compute the KV block bytes with the calculator's exact geometry — MHA/GQA, GQA-with-``head_dim``, DeepSeek MLA, Hunyuan CLA.

**Llama-3.1-8B, 256-tok chunk → 32 MiB KV block**

**2 Issue / replay**


Push that store/load workload through LMCache ``RawBlockCore`` on a real device — POSIX, io_uring, or io_uring_cmd NVMe passthrough. The payload is zeros; the engine splits each block into ``max_data_transfer_size``-sized commands (its knob, bounded above by the device's MDTS — on passthrough there is no block layer, so userspace owns the split) exactly as it would for real KV.

**32 MiB block → 256 × 128 KiB NVMe commands**

A recorded workload is captured as a compact ``kvio_record.json`` manifest — per-object payload sizes + device geometry, a few KB — that can be **replayed** later to reissue the identical command stream on any device.

The cross-layer trace_id join
-----------------------------

The distinguishing feature: follow **one KV object** from the LMCache payload, through the raw-block ``max_data_transfer_size`` split, down to the individual NVMe completions — and back. This is done with a single ``trace_id`` threaded across three layers:

+------------------------+------------------------------------------------------------------------------------------------+---------------------------------------+
| Layer                  | What it emits                                                                                  | Carries trace_id as                   |
+========================+================================================================================================+=======================================+
| LMCache ``raw_block``  | a semantic record per KV object op: ``op``, ``bytes``, ``part``, ``object_id``, ``components`` | the record's ``trace_id`` field       |
+------------------------+------------------------------------------------------------------------------------------------+---------------------------------------+
| io_uring / rust engine | the submission for each device command                                                         | user_data = (trace_id<<32) \| counter |
+------------------------+------------------------------------------------------------------------------------------------+---------------------------------------+
| eBPF NVMe tracer       | every ``nvme_setup_cmd``: opcode, slba, nlb, bytes                                             | reads back ``user_data``              |
+------------------------+------------------------------------------------------------------------------------------------+---------------------------------------+

The validator recovers the object for any command as ``trace_id = user_data >> 32``, joining one logical intent to its N (≤ MDTS) wire commands. The low 32 bits stay a unique completion counter, so CQE matching is unchanged.

**K/V aware** The semantic record carries a ``part`` (``kv``/``k``/``v``) and, for packed asymmetric-KV blobs, a ``components`` breakdown (K / V / scale bytes) read from the ``EncodedKV`` header — so a store's device bytes can be attributed to K vs V once the codec emits an asymmetric split.

Components
----------

**`kv_cache_offload_io <https://github.com/mcgrof/LMCache/tree/kvio/examples/kv_cache_offload_io>`__ LMCache**


Real-model-geometry workload generator. ``kv_geometry.py`` (a Python port of the KV-cache calculator) + ``run_kv_offload_io.py``. Lives in LMCache ```examples/kv_cache_offload_io`` <https://github.com/mcgrof/LMCache/tree/kvio/examples/kv_cache_offload_io>`__ on the ``kvio`` branch.

**`raw_block <https://github.com/mcgrof/LMCache/tree/kvio/lmcache/v1/storage_backend/raw_block>`__ LMCache**


The real engine: rust ``lmcache_rust_raw_block_io`` + ``RawBlockCore``, io_uring_cmd NVMe passthrough. Emits the semantic ``trace_id`` record when ``LMCACHE_KVIO_TRACE`` is set.

**kvio_plan ebpf-syscall**


The projector: model/params → device ops, NVMe command count, per-command sizes, total bytes, fragmentation vs. MDTS. No I/O.

**kvio_replay ebpf-syscall**


``--record kvio_record.json`` reissues a whole recorded object set (store-all-then-load-all) on a real device and measures latency/throughput.

**nvme_uring_cmd_monitor ebpf-syscall**


The eBPF tracer: one JSONL record per ``nvme_setup_cmd``, carrying ``user_data`` so each wire command is attributable.

**kvio_validate ebpf-syscall**


Joins tracer + semantic traces by ``trace_id`` and scores fidelity: exact-match, WAPE, and command-size total-variation distance.

Dependencies
------------

+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| Dependency                                                                | Why                                                                                 | Notes                                                                                                     |
+===========================================================================+=====================================================================================+===========================================================================================================+
| LMCache ```kvio`` branch <https://github.com/mcgrof/LMCache/tree/kvio>`__ | the ``raw_block`` engine + the semantic ``trace_id``/``part``/``components`` wiring | ``git clone -b kvio https://github.com/mcgrof/LMCache``; run against source on ``PYTHONPATH``, or install |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| rust ``raw_block`` ext                                                    | ``lmcache_rust_raw_block_io`` does the io_uring_cmd passthrough                     | ``maturin develop --release``; needs rustup ≥ 1.87 (24.04 apt rust 1.75 fails)                            |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| PyTorch (CPU is fine)                                                     | tensor buffers + the asymmetric codec                                               | FP8 casts work on CPU; no GPU needed                                                                      |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| an NVMe char device ``/dev/ngXnY``                                        | io_uring_cmd passthrough target                                                     | use an **empty, unmounted** namespace — never the OS disk                                                 |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| eBPF toolchain                                                            | build ``nvme_uring_cmd_monitor``                                                    | ``clang``, ``libbpf-dev``, ``libelf-dev``, and ``bpftool`` via ``apt install linux-tools-generic``        |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+
| kernel ≥ 5.19                                                             | io_uring_cmd (NVMe passthrough)                                                     | ``CONFIG_IO_URING=y``; Ubuntu 24.04 (6.8) works                                                           |
+---------------------------------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------+

**device safety** The passthrough target is written to. Always confirm the namespace is empty and unmounted (``lsblk``, ``nvme list``) — the OS disk's ``/dev/ng`` is off-limits, and which namespace is empty differs per box.

Build and install
-----------------

Build the eBPF tools and the vendored LMCache engine, then install the complete
runtime and its manuals::

   make all
   make kvio
   sudo make install
   man kvio

The install target honors ``prefix``, ``bindir``, ``libexecdir``, ``mandir``,
and ``DESTDIR``.  It keeps kvio's helper scripts and native modules together
under libexec and installs the user entry points under bindir.

For an environment that keeps captures local and does not need model
projection or the LMCache engine, install the smaller offline surface::

   make kvio-offline
   sudo make install-kvio-offline
   kvio doctor

This is the same ``kvio`` entry point, limited to ``record``, ``iolog``,
``fio-certify``, ``compare``, the three ``release-*`` commands, and ``doctor``.
It omits LMCache, PyTorch, model data, download code, and engine-driving
commands.  Cargo registry access is disabled while building the verifier, so
all build inputs must already be available.  Installation requires an empty
package root to prevent files from a full install from entering this boundary.

The package includes an invented public capture for a no-device check::

   cd /usr/local/libexec/ebpf-syscall/tools/kvio
   kvio iolog offline-capture-v1.example.jsonl /dev/fixture \
       --bundle-dir /tmp/kvio-replay
   kvio fio-certify /tmp/kvio-replay
   kvio compare same:offline-capture-v1.example.jsonl:offline-capture-v1.example.jsonl

These commands translate, certify, and compare files; they do not invoke fio
or touch a device.  ``tools/kvio/OFFLINE-PROVENANCE.md`` lists the installed
components, runtime dependencies, licenses, and remaining deployment checks.

How to run
----------

1 · Generate real-geometry offload I/O (GPU-free)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     LMCache examples/kv_cache_offload_io# real model geometry -> real io_uring_cmd passthrough I/O for fake KV blocks
   python run_kv_offload_io.py --model meta-llama/Llama-3.1-8B-Instruct \
       --dtype bfloat16 --chunk-tokens 256 --num-chunks 8 \
       --device /dev/ng0n1 --engine uring_cmd \
       --record /tmp/kvio_record.json --trace /tmp/sem.jsonl

2 · Capture the wire trace alongside it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     ebpf-syscallsudo ./nvme_uring_cmd_monitor --dur 90 --lba-size 512 --jsonl /tmp/nvme.jsonl &
   # ... run step 1 with LMCACHE_KVIO_TRACE=/tmp/sem.jsonl ...

3 · Validate projection vs. real device commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     ebpf-syscall/examples/lmcachepython kvio_validate.py --tracer /tmp/nvme.jsonl --semantic /tmp/sem.jsonl \
       --lba-bytes 4096 --mdts-bytes 131072
   # exact-match 8/8, WAPE 0.0000%, per-cmd size 8/8, size-dist TV 0.0000

4 · Replay a recorded workload elsewhere
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     ebpf-syscall/examples/lmcachepython kvio_replay.py --record /tmp/kvio_record.json --device /dev/ng0n1 --iters 5
   # reissues the exact store-all-then-load-all command stream

**alignment** Pass ``--lba-bytes`` equal to the ``raw_block`` ``block_align`` (4096), not the device LBA (512) — the projector rounds command tails to that alignment. Mismatched, the geometry looks off by a fraction of a percent; matched, it is exact.

Which command answers which question?
-------------------------------------

The commands form two different workflows.  Capture and replay preserve an
observed request stream.  Benchmarking applies controlled sustained pressure;
it does not recreate a capture.

.. list-table::
   :header-rows: 1

   * - Command
     - Input
     - Result
     - Device access
   * - ``kvio plan``
     - Model and cache geometry
     - Predict command sizes and counts; no application timing or reuse
     - No
   * - ``kvio trace``
     - An application-level agent trace
     - Compile observed requests into a cache load/store plan
     - No
   * - ``kvio workload``
     - Model settings or an agent plan
     - Issue cache loads and stores through LMCache's real storage engine
     - Yes; may write
   * - ``kvio record``
     - A selected NVMe namespace
     - Observe the commands that actually reach the NVMe driver
     - Read-only observation
   * - ``kvio perfetto``
     - Semantic records plus a device capture
     - Attribute device commands to cache objects and make a timeline
     - No
   * - ``kvio iolog``
     - A device capture
     - Export the captured requested stream as a fio replay bundle
     - No
   * - ``kvio fio-certify``
     - A fio replay bundle
     - Check that the bundle still describes the captured requested stream
     - No
   * - ``kvio compare``
     - Original and replay device captures
     - Report what fio and the storage stack actually preserved
     - No
   * - ``kvio release-build``
     - A bounded result draft
     - Build a two-file results-only candidate with no source trace
     - No
   * - ``kvio release-example``
     - No input
     - Print the canonical result draft
     - No
   * - ``kvio release-verify``
     - A results-only candidate
     - Check its closed grammar, inventory, and payload hash
     - No
   * - ``kvio bench``
     - An evidence-labeled stress profile
     - Run sustained pressure without claiming capture fidelity
     - Yes, including writes
   * - ``kvio bench-compare``
     - Results from repeated benchmark runs
     - Compare the median results of two configurations
     - No

The exact-replay path is ``record`` → ``iolog`` → ``fio-certify`` → run fio
while recording again → ``compare``.  The agent path begins one level above
that: ``trace`` → ``workload``, with ``record`` running alongside it.  ``bench``
and ``bench-compare`` are a separate controlled-load path.

Privacy and fidelity boundary
-----------------------------

``kvio record`` captures request metadata without capturing payload bytes,
prompts, tensors, feature values, graph contents, or KV keys. ``kvio iolog``
reduces that metadata to operation, exact byte offset, length, and relative
time. This is **payload-free and data-minimized, not automatically anonymous**:
offsets reveal locality and address range, timing reveals cadence, and a
distinctive pattern can identify a workload. The separate
``nvme_uring_cmd_monitor --kv`` path records ``key_hex`` and needs an
additional privacy review before publication.

Keep three boundaries separate:

* A **capture** is confidential source evidence. It retains device scope,
  exact placement, timing, queue metadata, and completion observations.
* The current **fio replay bundle** is a confidential fidelity artifact. It
  retains exact placement and timing, and its certificate contains a digest of
  the source capture. ``fio-certify`` checks translation, not release safety.
* An **external release** needs an allowlisted grammar, independent evidence,
  and human authorization. kvio implements a bounded results-only draft and
  format checker, but not evidence authentication or release authorization.
  Do not export a capture or current replay bundle merely because it is
  payload-free.

Capture schema v1 begins with one ``capture_meta`` record, binds the stream to
one selected ``--disk`` and device/namespace identity, and ends with exactly
one ``drops`` record. Replay consumers reject duplicate JSON keys, unknown
versions, mixed scopes, and a non-terminal footer. Use
``--allow-legacy-capture`` to inspect old unversioned captures; the override
cannot reconstruct their missing scope guarantee.

``tools/kvio/PRIVACY.md`` defines the bank-local release strategy, threat
model, proposed profiles, and language the project can defend. Planned
features are labeled there. The results-only format is a draft candidate, not
an authorization to transfer it.

Fidelity has a file gate and a runtime gate. ``kvio iolog`` plus the
independent Rust ``kvio fio-certify`` check the finite requested stream. A
second ``kvio record`` capture plus ``kvio compare`` checks the ordered
operation, offset, and length tuples actually issued by fio and Linux. It also
reports rebased issue-time error and completion-latency distributions. When
both captures have unambiguous hardware-queue and command-ID records, it pairs
each completion with its command and reports per-command latency error. A
command ID may be reused after its earlier command completes; overlapping reuse,
missing or orphan completions, and inconsistent latency timestamps disable the
paired claim. ``--update-bundle BUNDLE`` stores one hash-bound source/replay
result in its matching confidential bundle, refreshes its checksums, and lets
``fio-certify`` reject contradictory runtime fields. This does not measure
application end-to-end latency.

The replay claim ends at one NVMe leaf namespace. ``nvme_tp_monitor --disk``
matches the requested name against the leaf request's kernel ``disk_name``;
use a whole namespace such as ``nvme1n1``, not a partition. IO submitted
through a filesystem, device-mapper, LVM, or software RAID is visible only
after that upper layer has mapped, split, merged, or reordered it. The captured
namespace-relative LBAs are leaf-device evidence; they do not reconstruct file
offsets, logical-volume addresses, RAID members, or redundancy. Schema v1 also
does not record the controller path, ANA state, failover, or transport identity
needed to certify native NVMe multipath behavior. Record each namespace
separately. Unfiltered or mixed-namespace captures, including namespaces with
different logical block sizes, are not certifiable replay input.

The `DGraphFin case study <gnn-readamp.html>`__ shows how the same method
reveals an architectural reduction in read amplification while omitting graph
and feature contents. Exact offsets and timing remain sensitive metadata. Open
sanitization, corrected hardware replay, pacing, concurrency, and latency work
is tracked in ``tools/kvio/TODO.md`` and summarized in ``kvio(1)``.

Build a bounded result candidate
--------------------------------

``kvio release-build`` accepts a closed set of storage questions, metrics,
coarse ratio bands, evidence labels, and residual-disclosure labels. It rejects
free text, exact numerical results, paths, source hashes, unknown fields,
duplicate keys, and non-draft status::

   ./kvio release-example > result.json
   ./kvio release-build result.json candidate
   ./kvio release-verify candidate

The candidate contains only ``result.json`` and ``manifest.json``. Verification
checks the closed grammar, exact inventory, regular-file types, and payload
hash. Its successful verdict still reports ``internal_evidence: not_checked``,
``release_authorization: not_checked``, and ``export_allowed: false``. Connect
those decisions to the organization's existing review and signing systems
before transferring a candidate.

The 64 KiB input ceiling is more than 100 times the 617-byte example while
bounding parser memory for a format intended to stay small. The command does
not inspect a confidential source, perform a privacy attack, authenticate a
reviewer, or authorize release.

Compile real agent traffic
--------------------------

``kvio trace`` turns application-level agent requests into a logical KV-cache
plan.  ``kvio workload --agent-plan`` then runs that plan through the real
``raw_block`` engine.  The plan keeps request order, relative timestamps, and
hashed session identity, and labels every inference it makes.  It is
**trace-derived**, not measured device I/O; record the execution with
``kvio record`` to learn what the NVMe device actually received.

Two public datasets expose different evidence:

* `LMCache agent traces <https://github.com/LMCache/lmcache-agent-trace>`__
  retain complete prompt text.  kvio requires a pinned tokenizer, splits the
  resulting token IDs into complete chunks, and hashes either the prefix chain
  or each chunk's content.  Loads therefore come from content actually reused
  by later prompts, rather than a random ``--hit-rate``.
* `TraceLab <https://github.com/uw-syfi/TraceLab>`__ publishes 357,161
  sanitized Claude/Codex rounds from 43 developers under CC BY 4.0.  It removes
  prompt text for privacy but retains input, prefix, cache-creation, and
  cache-read token accounting.  kvio uses the observed prefix count and assigns
  session-relative logical chunk positions.  Those positions are a model, not
  recovered content hashes.

TensorMesh's `agent-caching study
<https://www.tensormesh.ai/blog-posts/blog-non-prefix-prompt-caching-ai-agents>`__
is the useful signpost to the LMCache corpus; the trace repository is the
artifact kvio pins.  Do not confuse it with TensorMesh's older
`benchmark generator <https://www.tensormesh.ai/blog-posts/tensormesh-benchmark>`__,
which makes synthetic repeated-text prompts under a closed-loop scheduler.
That generator is useful stress, not a measured agent workload.

The LMCache repository is Apache-2.0, but its traces are benchmark/application
captures rather than a production-traffic sample.  Pin the exact repository
commit and tokenizer in every plan.  For example, this OpenCode trajectory is
append-heavy and exercises ordinary prefix reuse::

   git clone https://github.com/LMCache/lmcache-agent-trace
   git -C lmcache-agent-trace checkout 780bcc2979715150d8b9fd4737e026e625444cc9
   ./kvio trace lmcache-agent-trace/opencode/gpt-5-mini-task1.jsonl \
       --out opencode-prefix.json --format lmcache-agent \
       --tokenizer tiktoken:gpt-5-mini \
       --tokenizer-revision tiktoken-0.12.0 \
       --policy prefix --chunk-tokens 256 \
       --source-url https://github.com/LMCache/lmcache-agent-trace \
       --source-revision 780bcc2979715150d8b9fd4737e026e625444cc9 \
       --source-license Apache-2.0

   sudo ./kvio workload --agent-plan opencode-prefix.json \
       --model Qwen/Qwen2.5-Coder-32B-Instruct --dtype bfloat16 \
       --chunk-tokens 256 --device /dev/ngXnY --engine uring_cmd \
       --sem-out opencode-sem.jsonl

Use ``--policy substring`` on Aider or RepoAgent traces to test exact complete
chunks that recur after content shifts.  This is a fixed-chunk content-reuse
model; it must not be described as a byte-for-byte implementation of
CacheBlend.  ``--capacity-chunks`` adds explicit LRU eviction.  Incomplete tail
chunks are ignored because their identity changes when a prompt grows.

For TraceLab, download and verify the pinned ``v0.0.1`` release artifact before
compiling a bounded sample::

   curl -L --fail -o syfi_coding_trace.jsonl.gz \
       https://github.com/uw-syfi/TraceLab/releases/download/v0.0.1/syfi_coding_trace.jsonl.gz
   echo "9d265eae69a31cae203848bea936f018148eed7ca8bf56050c5abe96da0b4e6b  syfi_coding_trace.jsonl.gz" | sha256sum -c -
   ./kvio trace syfi_coding_trace.jsonl.gz --format tracelab \
       --provider claude --max-requests 200 --out tracelab-claude.json \
       --source-url https://github.com/uw-syfi/TraceLab/releases/tag/v0.0.1 \
       --source-revision v0.0.1 --source-license CC-BY-4.0

These sources support four useful contribution lanes: OpenCode/MiniSWE for
append-only prefix growth, Aider/RepoAgent for shifted repository context,
TraceLab split by Claude and Codex for real day-to-day coding-agent cache
accounting, and TauBench for a non-coding agent domain.  Add each as a pinned,
separately labeled workload; do not average them into one supposed universal
"agent" profile.

Export and certify fio replays
------------------------------

Storage engineers can consume a captured stream without learning kvio's
engine.  New ``nvme_tp_monitor`` captures discover the selected namespace's
logical LBA size from sysfs and record it with a stable command sequence.
Without ``--disk``, the monitor requires an explicit ``--lba-size`` because a
single value cannot describe several namespaces.  ``kvio iolog`` rejects
incomplete captures, dropped events, unsupported commands, malformed versioned
envelopes, and mixed scopes by default, converts monotonic nanoseconds to
fio v3 microseconds, reparses its own output, and can emit a portable bundle::

   sudo ./kvio record --disk nvme0n1 \
       --jsonl capture.jsonl --dur 60
   ./kvio iolog capture.jsonl /dev/source \
       --bundle-dir qwen-agent-replay
   cd qwen-agent-replay
   sha256sum -c SHA256SUMS
   KVIO_TARGET=/dev/nvmeXnY fio replay-block.fio

The bundle contains ``commands.iolog``, normal-block and ``io_uring_cmd`` fio
job files, a normalized workload, checksums, and ``certificate.json``.  The
certificate proves a finite translation property: reparsing the iolog returns
the same ordered ``(operation, offset, length)`` stream, with less than one
microsecond of timestamp quantization.  It does **not** prove that fio, Linux,
the NVMe driver, or firmware leaves that requested stream unchanged.  Re-record
the replay and use ``kvio compare``; it now reports operation, offset, length,
and full tuple equality separately, plus timing error.

This export path is inspired by the pending fio `iolog-device-record branch
<https://github.com/mcgrof/fio/tree/iolog-device-record>`__.  That branch adds
device-level fio recording and offset-join sharding.  Its single-stream mode
keeps global order; object-sharded replay deliberately trades cross-object
ordering for parallelism while retaining each object's order.  kvio's bundles
are ordinary fio v3 iologs and interoperate with that work.

The ``kvio-ir`` Rust crate implements checked alignment, transfer splitting,
timestamp conversion, and fio parser/emitter round trips without device I/O.
Build it and independently validate the three bundle artifacts::

   make kvio-ir
   ./kvio fio-certify qwen-agent-replay

The validator checks ``workload.json``, ``commands.iolog``, and
``certificate.json`` against each other.  Pass ``--region-bytes`` or
``--max-transfer-bytes`` to check a known device bound or transfer limit.  This
is exhaustive validation of one finite bundle, not a proof of fio or device
runtime behavior.

For example, suppose the capture says to read 4096 bytes starting at byte
offset 4096.  Offsets start at zero, so this is the second 4096-byte block.  Its
fio action must be::

   0 /dev/source read 4096 4096

The line ``0 /dev/source read 8192 4096`` is also valid fio syntax and is still
4096-byte aligned, but it reads the third block.  It is therefore an invalid
translation of that capture: the replay targets a different device region,
changes the spatial access pattern, and can map to a different KV-cache object.
``kvio fio-certify`` rejects the mismatch before fio runs.

``make kvio-ir-test`` runs ordinary and property tests.  The crate includes
bounded Kani harnesses for timestamp rounding, logical-block multiplication,
alignment overflow, and gap-free transfer splitting.  Run them with
``make kvio-ir-kani``.  Their presence alone is not a completed Kani proof; the
target must finish successfully before making that claim.  Even then, the
claim stays narrow: workload translation can be machine-checked; performance
equivalence cannot.  Rust string formatting and parsing are covered by
generated round-trip tests and the exhaustive check of each bundle, not by
Kani.

``kvio bench``: sustained storage pressure
------------------------------------------

``kvio bench`` asks how much KV-like I/O a storage tier can sustain, what its
tail latency is under load, and how large transfers affect another workload on
the same drive.  It runs fio without requiring a GPU or model server and saves
the resolved workload, fio output, result rows, hardware details, and kernel
settings for each run.

This is a different fidelity level from kvio capture and replay.  ``bench``
runs controlled, closed-loop load for device and kernel A/B comparisons.
Capture plus iolog export preserves the requested arrival times, offsets, and
command order of an observed workload, subject to fio's microsecond timestamp
quantization.  Re-record the replay before claiming that the device received
the same stream.  Use ``bench`` for headroom and interference; use capture and
certified export when the recorded request stream matters.

======================== ========== ===========================================
Profile                  Evidence   What it represents
======================== ========== ===========================================
``restore``              synthetic  Concurrent random reads standing in for
                                    chats whose KV must return from storage.
``restore-calibrated``   measured   Four synchronous workers restoring whole
                                    7 MiB Qwen2.5-1.5B KV objects.
``prefix``               synthetic  Concurrent sequential reads standing in
                                    for shared-prefix KV reloads.
``qos-sustain-4k``       synthetic  Large restore-like reads beside a sustained
                                    4 KiB reader on the same drive.
``evict``                synthetic  Writes standing in for KV demotion when the
                                    memory tier is full.
======================== ========== ===========================================

Inspect the evidence and exact fio shape without touching a device::

   make kvio-test
   ./kvio bench --list-profiles
   ./kvio bench --help

Run the default profiles on an **empty, disposable, unmounted raw namespace**::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device \
       --size 8GiB --runtime 20 --ramp-time 3 --reps 3 \
       --output-dir results/pm9a3-baseline

The benchmark preconditions its test region and the eviction profile writes
it.  The acknowledgement does not bypass safety checks: kvio refuses mounted
or undersized targets, partitions, holders, and signatures unless signatures
receive their own explicit acknowledgement.

To compare a kernel, transfer limit, or queue setting, keep the device, region,
runtime, and repetition count identical, then compare the result files::

   ./kvio bench-compare results/baseline/results.jsonl \
                        results/candidate/results.jsonl

The comparison reports median bandwidth, IOPS, whole-I/O p50 and p99 latency,
fio system CPU, and target-controller interrupts per GiB.

Measured and synthetic profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Only ``restore-calibrated`` is derived from a recorded KV-cache setup.  David
traced LMCache 0.5.3 with vLLM 0.27.1, Qwen2.5-1.5B-Instruct, TP1, bf16, and
256-token chunks.  One complete KV object contains K and V for every layer,
head, value, and token::

   2 (K and V) * 28 layers * 2 KV heads * 128 values per head
   * 2 bytes (bf16) * 256 tokens = 7,340,032 bytes = 7 MiB

That run used four synchronous disk workers and reported 108 stores and 200
restores.  The `source profile
<https://github.com/davidlohr/kvspill/blob/66f21115ed7fcbe8c76e15a9446c3143a0bca8e4/profiles/lmcache-qwen2.5-1.5b.md>`__
is one calibration point, not a universal object size.  Override it for a
different model, tensor-parallel rank, dtype, or chunk size::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device --cases restore-calibrated \
       --calibrated-block-size 32MiB --size 8GiB \
       --output-dir results/restore-32m

The remaining built-ins are synthetic stress profiles.  In particular,
``qos-sustain-4k`` does not claim that LMCache issues 4 KiB reads or that its
mix came from a production trace.  It measures how a sustained large-read load
delays one possible latency-sensitive neighbor.  Treat it as an optional
same-device interference test, not as a universal KV-cache QoS workload.

Add a sustained profile from a capture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``--profile FILE`` accepts additional JSON profiles without a Python change.
Each profile must label its evidence ``measured`` or ``synthetic``, identify
the source, and define each fio job's operation, block size, queue depth, and
worker count.  The resolved definition is copied into ``run.json``::

   {
     "schema_version": 1,
     "name": "service-a-restore",
     "description": "Sustained restore shape from service A capture 17",
     "evidence": {
       "kind": "measured",
       "source": "/srv/kvio/captures/service-a-17.jsonl"
     },
     "jobs": [{
       "name": "restore",
       "rw": "randread",
       "bs": "32MiB",
       "iodepth": 1,
       "numjobs": 4
     }]
   }

Run only that external profile by omitting ``--cases``::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device --profile service-a-restore.json \
       --size 8GiB --output-dir results/service-a

Lineage
~~~~~~~

Davidlohr Bueso wrote the standalone `kvspill
<https://github.com/davidlohr/kvspill>`__ prototype.  Its workload shapes,
preconditioning, fio result parsing, and median A/B comparison became the
starting point for ``kvio bench``.  They were merged with his permission and
credit under this repository's Apache-2.0 license, then integrated with kvio's
single CLI, evidence labels, external profile format, result artifacts, and
raw-device safety checks.  There is no separate kvspill command in this tree;
`kvspill.kvcache.io <https://kvspill.kvcache.io/>`__ records that history.

The integrated benchmark was exercised on a verified-empty Samsung PM9A3 in a
Latitude ``m4-metal-medium`` node.  All five profiles, the 32 MiB calibrated
override, comparison, OS-disk refusal, and tuning cleanup completed, and queue
and hugepage settings matched their pre-run values afterward.  The reproduce
record is in ``tools/reproduce/kvio-bench/RESULTS.md``.

Fidelity metrics
----------------

Three complementary scores, joined per object by ``trace_id``. AUC is deliberately *not* used — there is no class label; the geometry is deterministic.

**= Exact-match**


Per object, do the measured command count *and* total device bytes equal the projection? The strictest check.

**% WAPE**


Weighted Absolute Percentage Error: total mispredicted bytes ÷ total measured bytes. **0% = the I/O volume is exactly right.**

**△ Size-dist TV**


Total-variation distance between projected and measured command-size distributions (log2 bins). **0 = identical shape** — every command the right size.

**why both** The same total bytes in the same command count can still hide a wrong split (256K+768K vs 512K+512K). WAPE and count both pass; TV catches it. WAPE = right *volume*, TV = right *shape*. Both zero = the device I/O is reproduced byte-for-byte and command-for-command.

Validated results
-----------------

On an 8× H100 server with real Samsung Gen5 NVMe (io_uring_cmd passthrough on ``/dev/ng``), the projection was validated against a **real GPU-driven vLLM + LMCache offload** — the previously hardware-gated step is now closed.

**real GPU, kernel-verified** vLLM (Llama-3.1-8B) on an H100 offloading KV to ``/dev/ng1n1``: **230/230 objects exact** (cmds *and* bytes), WAPE 0.0000%, size-distribution TV 0.0000, over **58,729 real NVMe commands** captured by the eBPF tracer and joined by ``trace_id``. Roundtrip proof: repeated prompts (temp 0) regenerated *identical* outputs from NVMe-loaded KV vs. recomputed KV. The GPU-free generator, run at the same geometry, reproduced that device command stream *indistinguishably*.

Scale & parity campaign — 7 models, 1B → 70B, TP 1/2/4
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each cell: real GPU capture → wire-validate → replay the recorded manifest → regenerate GPU-free from the calculator. Every real leg was exact.

============= ============== == ======= =========== =======
Model         KV family      TP Objects Exact-match WAPE
============= ============== == ======= =========== =======
Llama-3.2-1B  GQA            1  230     100.0%      0.0000%
Llama-3.2-3B  GQA            1  230     100.0%      0.0000%
Qwen3-8B      GQA · head_dim 1  394     100.0%      0.0000%
Qwen3-14B     GQA · head_dim 1  392     100.0%      0.0000%
Llama-3.1-8B  GQA            2  456     100.0%      0.0000%
Llama-3.1-8B  GQA            4  912     100.0%      0.0000%
Llama-3.1-70B GQA            4  916     100.0%      0.0000%
============= ============== == ======= =========== =======

**tensor-parallel sharding is exact** Under TP=\ *N*, vLLM runs one KV worker per rank, so a logical chunk becomes *N* per-rank objects (same chunk hash, distinct ``kv_rank``): object count scales **×N**, per-rank payload **÷N**. The 70B case shards its 80 MiB chunk into exactly **4 × 20 MiB** per-rank objects (2 of 8 KV-heads each), 161 store / 160 load commands apiece — and the calculator-driven generator now reproduces that sharded pattern byte-for-byte.

**load vs recompute — capacity, not speed** On this H100 + Gen5-NVMe rig, loading KV from NVMe is still slower than recomputing prefill on the GPU, but the gap **collapses with scale**: load ÷ recompute falls from ~\ **6.9×** (1B) to ~\ **2.2×** (70B, TP4). The crossover — where offload beats recompute — lies beyond 70B, or on slower GPUs / faster storage. (n=2/cell, ~QD1; directional, not a rigorous latency benchmark — tokenizers differ across families.)

**bottom line** Capture wiring, the cross-layer ``trace_id`` join, fidelity metrics, and record/replay are byte-faithful on real NVMe, now proven against a real GPU offload across 7 models and TP degrees. The GPU-free generator and the recorded-manifest replay both reproduce the real device command stream exactly, so anyone can simulate a model's KV-offload I/O — including its TP sharding — with *no GPU*.

**case study** The same eBPF attribution found a concrete engineering win: LMCache's KV loader ran at ~11% of a Gen5 NVMe (single-threaded, QD~1). See `The QD~1 KV-load bottleneck — found with eBPF, fixed with parallel loads <kvio-loadpath.html>`__ for the wire evidence, how to reproduce it, and the ~2.8× fix.

kvio — GPU-free KV-cache-offload storage-IO projector & replayer engine: LMCache ``raw_block`` · tracer: eBPF ``nvme_uring_cmd_monitor``
