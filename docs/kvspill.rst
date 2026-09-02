kvspill is now ``kvio bench``
==============================

.. note::

   A styled standalone version is available at
   `/showcase/kvspill.html </showcase/kvspill.html>`__.

Davidlohr Bueso wrote `kvspill <https://github.com/davidlohr/kvspill>`__ to
load-test storage with fio patterns chosen for KV-cache offload.  It answers a
different question from kvio's calculator and replay tools: **how much of this
kind of I/O can an SSD sustain, and what happens to latency when it is busy?**
With David's permission, the profiles and comparison workflow now live here
under the Apache-2.0 license with his authorship retained.

Why kvspill existed
-------------------

kvio began from the application side.  It computes a model's KV-object size,
projects the resulting NVMe command geometry, records real LMCache operations,
joins them to kernel/device traces, and replays captured streams.  That proves
whether an emulation is faithful.

kvspill began from the drive side.  It expresses five sustained fio workloads
without requiring a GPU or model server.  The examples explain what each one is
trying to stand in for; the evidence column says whether that exact shape was
captured from a real stack.

======================== ========== ===========================================
Case                     Evidence   Concrete example
======================== ========== ===========================================
``restore``              synthetic  A chat returns after its KV was evicted, so
                                    the server reads that KV before resuming it.
``restore-calibrated``   measured   LMCache reads one 7 MiB Qwen2.5-1.5B KV
                                    chunk on each of four synchronous workers.
``prefix``               synthetic  Several requests reload KV for a shared
                                    system prompt from one SSD.
``qos-sustain-4k``       synthetic  A sustained 4 KiB reader shares the SSD with
                                    large restore-like reads.
``evict``                synthetic  A full memory tier writes KV chunks to SSD
                                    to make room for active requests.
======================== ========== ===========================================

Only ``restore-calibrated`` is capture-derived.  The other built-ins are
controlled stress cases inherited from kvspill.  In particular,
``qos-sustain-4k`` does **not** claim that LMCache issues 4 KiB reads.  It asks
one narrow question: if some latency-sensitive 4 KiB workload shares this SSD,
how badly do sustained large reads delay it?  David's original storage campaign
measured that synthetic mix, but did not capture the mix from a production
serving deployment.  Treat it as the first QoS interference profile, not as a
universal KV workload.

Those are complementary layers.  A projector is not a saturation benchmark,
and a synthetic saturation benchmark is not a trace-faithful replay.  Keeping
both under one command makes that distinction explicit instead of forcing
users to choose one tool and accidentally overclaim what it measures.

What was merged
---------------

The five workload shapes, preconditioning, per-repetition fio JSON parsing,
``RESULT`` records, and median A/B comparison come from kvspill.  kvio adds:

* one ``./kvio`` entry point for projection, capture conversion, replay,
  validation, benchmarking, and comparison;
* a reachable calibrated-restore case and an overridable whole-object size;
* evidence labels for every built-in and JSON profiles for adding future
  sustained workloads derived from real captures;
* hard refusal of partitions, mounts, holders, undersized devices, and disk
  signatures unless signatures are separately acknowledged;
* workload regions that cannot run past the namespace capacity;
* target-controller IRQ accounting instead of summing every NVMe interrupt;
* structured gates and result artifacts alongside human-readable lines;
* checked fio failures and guaranteed restoration of ``max_sectors_kb`` and
  hugepage reservations after success, failure, SIGINT, or SIGTERM.

Run it
------

First inspect dependencies without touching storage::

   make kvio-test
   ./kvio doctor
   ./kvio bench --list-profiles
   ./kvio --help

Then select an **empty, disposable, unmounted raw namespace**.  Benchmarking
preconditions the requested region and the evict case writes it, so the
acknowledgement is intentionally long::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device \
       --size 8GiB --runtime 20 --ramp-time 3 --reps 3 \
       --output-dir results/pm9a3-baseline

Use a model-derived block size for the calibrated restore.  For example, a
32 MiB per-rank KV object::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device --cases restore-calibrated \
       --calibrated-block-size 32MiB --size 8GiB \
       --output-dir results/restore-32m

Add a sustained profile from a future capture
----------------------------------------------

``--profile`` loads a JSON description instead of requiring a Python change.
Every profile must say whether it is measured or synthetic and identify its
source.  For example::

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

Run only that profile by omitting ``--cases``::

   sudo ./kvio bench /dev/nvmeXnY \
       --yes-really-use-device \
       --profile service-a-restore.json \
       --size 8GiB --output-dir results/service-a

The resolved jobs and evidence source are copied into ``run.json``.  This
interface describes sustained load.  Use kvio capture and iolog replay when the
arrival times and exact command order from the record must also be preserved.

To evaluate a kernel or queue-limit change, keep the device, region, runtime,
and repetitions identical.  ``bench-compare`` accepts either JSONL or the
human-readable RESULT log::

   ./kvio bench-compare results/baseline/results.jsonl \
                        results/candidate/results.jsonl

The output reports median bandwidth, IOPS, whole-I/O p50/p99, fio system CPU,
and target-controller interrupts per GiB.  Positive bandwidth/IOPS deltas are
good; positive latency/CPU/IRQ deltas are generally regressions.

Which kvio mode to use
----------------------

======================= =============================== =====================
Need                    Command                         Fidelity boundary
======================= =============================== =====================
Size one KV operation   ``kvio plan``                   Geometry only
Exercise real LMCache   ``kvio replay``                 Real engine, fake bytes
Reissue captured I/O    ``kvio iolog`` + fio            Command stream; fio may
                                                        run it flat-out
Attribute wire commands ``kvio validate``               Requires two witnesses
Stress a storage tier   ``kvio bench``                  Synthetic closed-loop
Compare two systems     ``kvio bench-compare``          Medians; control setup
======================= =============================== =====================

Interpretation limits
---------------------

``kvio bench`` is a closed-loop fio benchmark.  Its block size, direction,
worker count, queue depth, and sequential/random shape model important KV-tier
conditions, but it does **not** recreate request arrival times, cache hits,
admission policy, object lifetimes, or the exact offset sequence of a serving
trace.  Use capture plus replay when those details matter.  Conversely, trace
replay may preserve a production stream without driving a device to saturation;
use the benchmark profiles when the question is headroom or interference.

The default calibrated size is not a magic constant.  David traced LMCache
0.5.3 with vLLM 0.27.1 and Qwen2.5-1.5B-Instruct at TP1 and chunk size 256.  The
capture reported 108 stores and 200 restores, each one whole-object syscall on
a four-thread synchronous disk pool.  The object contains K and V for every
token and layer, so its size is::

   2 (K and V) * 28 layers * 2 KV heads * 128 values per head
   * 2 bytes (bf16) * 256 tokens = 7,340,032 bytes = 7 MiB

The source profile and capture description are in
`kvspill commit 66f2111 <https://github.com/davidlohr/kvspill/blob/66f21115ed7fcbe8c76e15a9446c3143a0bca8e4/profiles/lmcache-qwen2.5-1.5b.md>`__.
This is one measured configuration, not a universal KV size.  Pass
``--calibrated-block-size`` or load a measured JSON profile for another model,
tensor-parallel rank, dtype, or chunk size.

Bare-metal validation
---------------------

Before merge, all five cases, the 32 MiB calibrated override, A/B comparison,
OS-disk refusal, and tuning cleanup were exercised on a verified-empty Samsung
PM9A3 namespace in a Latitude ``m4-metal-medium`` node.  Both
``max_sectors_kb`` and hugepages matched their pre-run values afterward.  The
commands, hardware gates, short-run numbers, and interpretation caveat are
recorded in ``tools/reproduce/kvio-bench/RESULTS.md``.
