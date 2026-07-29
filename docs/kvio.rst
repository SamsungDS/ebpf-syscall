kvio GPU-free KV-cache-offload storage-IO projector & replayer
==============================================================

.. note::

   A styled standalone version of this page (identical content, dark
   theme) is served at `/showcase/kvio.html </showcase/kvio.html>`__
   and via htmlpreview from the repository's ``docs/kvio.html``.


Project, issue, and replay the NVMe I/O that LLM KV-cache offload produces — from real model geometry, on real hardware, *without a GPU or a model*. Every device command is attributed back to the KV object that caused it via a cross-layer ``trace_id`` join, and validated byte-for-byte against the projection.

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
