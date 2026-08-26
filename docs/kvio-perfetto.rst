kvio × Perfetto see every KV object and every NVMe command on one timeline
==========================================================================

.. note::

   A styled standalone version of this page (identical content, dark
   theme) is served at `/showcase/kvio-perfetto.html </showcase/kvio-perfetto.html>`__
   and via htmlpreview from the repository's ``docs/kvio-perfetto.html``.


Convert kvio's cross-layer traces — LMCache semantic object ops, eBPF NVMe passthrough commands with device completions, and serving-layer request spans — into a Perfetto trace you drag onto `ui.perfetto.dev <https://ui.perfetto.dev>`__ (processing is local to your browser), plus a one-command SQL metrics report.


Why a converter is the only way in
----------------------------------

kvio IO is ``io_uring_cmd`` NVMe passthrough on ``/dev/ng*``, which bypasses the block layer — Perfetto's stock ftrace/block ingestion (and ``iostat``) see none of it. The kernel's nvme driver tracepoints do fire for passthrough, but carry no ``user_data`` — so they cannot be joined to KV objects. The eBPF tracer ``nvme_uring_cmd_monitor`` is **the only source that carries trace_id** (``user_data >> 32``, planted by LMCache's raw_block engine), and ``kvio2perfetto.py`` is the bridge from it to a semantically-joined timeline.

**found visually**


The QD~1 load bug (83 µs submission gaps, worth 4–15× TTFT) is one lonely command slice at a time instead of a dense band.

**flows**


Arrows tie each KV object span to its first and last device command — click an object, see its IO.

**real durations**


The tracer's device-completion probe (fentry on ``nvme_uring_cmd_end_io`` — immune to CQ overflow) gives every command its true latency; queue depth becomes visible as slice overlap.

Quickstart
----------

::

   capture → convert → view# 1. capture: eBPF device stream (+ completions) and the LMCache semantic trace
   sudo ./nvme_uring_cmd_monitor --jsonl ebpf.jsonl --lba-size 4096 &
   LMCACHE_KVIO_TRACE=sem.jsonl <run your LMCache raw_block workload>

   # 2. convert (pip install perfetto)
   python3 examples/lmcache/kvio2perfetto.py --sem sem.jsonl --ebpf ebpf.jsonl -o kv.pftrace

   # 3. view: drag kv.pftrace onto https://ui.perfetto.dev  (local-only WASM)
   # 4. metrics report
   python3 examples/lmcache/kvio_tp_report.py kv.pftrace

**A/B overlays** ``--merge stock=sem1,ebpf1 --merge batched=sem2,ebpf2`` renders arms as separate process groups, each rebased to t=0 — stock-vs-batched or real-vs-replay side by side. A third component per arm (``label=sem,ebpf,serving.jsonl``) adds serving-layer request spans (e.g. recompute-vs-load TTFT) above the device activity.

**wedged runs** The converter tolerates a truncated final line and converts still-growing files — converting the live JSONL is the supported way to look inside a hung run.

What the timeline shows
-----------------------

+--------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| process            | tracks                        | content                                                                                                                                                               |
+====================+===============================+=======================================================================================================================================================================+
| Serving <label>    | requests.N                    | request spans from a driver (op, tokens, TTFT) — the crossover view                                                                                                   |
+--------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| LMCache <label>    | objects.N                     | one span per KV object op: store/load/delete, span = op-start → op-end (schema-2) with pre-submit time visible; args: trace_id, rank/fmt, chunk, bytes, n_cmds, error |
+--------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| NVMe <dev> <label> | writes.N / reads.N / untagged | one slice per command, real duration when completions were captured (lanes = live queue depth); args: slba, data_len, trace_id, role=header|payload                   |
+--------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| counters                                           | cmds/ms, MB/s, slba-over-time (space axis: ramps = sequential, sawtooth = slot reuse), objects in flight                                                              |
+----------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+

The metrics report (P4 pack)
----------------------------

``kvio_tp_report.py`` runs the canned analyses over any converted trace — per label, with paired A/B diffs when arms share object keys:

- **QD1 detector** — per-object submission-gap p50/p95 vs device service time; flags the serialized load path in one line (verified: fires on the original buggy captures, and on a stock core today).
- **Per-command latency** p50/p95/p99 and **achieved QD** (%time at QD≤1) — needs the completion probe.
- **Object spans** — device window, end-to-end, pre-submit cost; effective MB/s per op.
- **Inferred batches** — submission clusters split on a gap threshold; contrasts stock vs batched arms with no producer-side events.
- **TP all-rank-ready barrier** — per chunk, max−min object end across shards (grouped by the key fmt field).
- **Space axis** — LBA reuse, write sequentiality, header-write share. **Throughput**, untagged share, failed ops, serving-span percentiles.

``--json`` emits the same metrics machine-readably (campaign drivers consume this).

Trace schema (what the producers emit)
--------------------------------------

+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| line                               | source             | fields                                                                                                                                          |
+====================================+====================+=================================================================================================================================================+
| kvio_meta                          | LMCache (schema 2) | schema, hostname, pid, instance, device_path, slot/align/MDTS geometry, engine, monotonic+realtime clock anchors — the file is self-contained   |
+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| store/load/delete                  | LMCache            | trace_id, key, object_id, part, bytes, slot_offset, ts_start (op begin), ts (op end), pid, instance, error (failed ops), components (K/V split) |
+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| nvme_cmd                           | eBPF tracer        | ts (monotonic ns), user_data, opcode, nsid, slba, nlb, data_len, rdev, comm                                                                     |
+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| nvme_cmp                           | eBPF tracer        | ts, user_data, lat_ns (kernel-computed), err, hwq, cid — paired in kernel via the ioucmd pointer, CQ-overflow-immune                            |
+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| cq_overflow / clock_anchor / drops | eBPF tracer        | overflowed CQEs; periodic monotonic↔realtime anchors; final ringbuf-drop count                                                                  |
+------------------------------------+--------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+

**clocks** Semantic ``time.monotonic()`` and eBPF ``bpf_ktime_get_ns()`` are the *same* CLOCK_MONOTONIC — no offset estimation exists or is needed; semantic seconds land directly on the ns axis. Cross-boot arms are each rebased to t=0.

SQL cookbook (trace_processor)
------------------------------

::

   python -c … or trace_processor_shell kv.pftrace-- every KV object with its device-command count and span
   select s.name, s.dur/1e6 ms, extract_arg(s.arg_set_id,'debug.n_cmds') cmds
   from slice s join process_track pt on s.track_id=pt.id
   where pt.name like 'objects%' order by s.dur desc limit 20;

   -- real per-command latency percentiles
   select count(*), min(dur), max(dur) from slice s
   join process_track pt on s.track_id=pt.id
   where pt.name like 'reads%' and extract_arg(s.arg_set_id,'debug.real_dur')=1;

   -- flows: which commands belong to object trace_id 42
   select * from slice where extract_arg(arg_set_id,'debug.trace_id')=42;

kvio × Perfetto — cross-layer KV-offload introspection tools: ``kvio2perfetto.py`` · ``kvio_tp_report.py`` · ``nvme_uring_cmd_monitor``
