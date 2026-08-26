NVMe io_uring_cmd DMA-mapping matrix
====================================

``nvme_uring_cmd_smoke`` issues READ-only NVMe passthrough commands on a
namespace character device such as ``/dev/ng0n1``.  It is both a firing test
for ``nvme_uring_cmd_monitor`` and a controlled workload for comparing
ordinary per-command DMA mapping with a requested blk-iobuf retained mapping.
It prints exactly one JSON object on stdout for a run that reaches the
measurement phase; diagnostics go to stderr.

Build and host-only tests
-------------------------

The tool needs liburing.  The focused test builds all C with ``-Werror`` in a
temporary directory, so it does not overwrite an existing local binary:

.. code-block:: console

   $ tests/nvme_uring_cmd_smoke_test.sh

The hardware workload only reads, but its sequential LBA range is
``[0, last_lba_exclusive)``.  The caller must verify that the namespace has at
least the JSON-reported ``last_lba_exclusive`` LBAs and that ``--lba-size``
matches its active format.  Use a namespace that is safe for benchmarking.

Buffer modes
------------

``--buffer-len`` is the size of every allocated and, where applicable,
registered slot.  ``--len`` is the smaller or equal range used by each READ.
``--slots`` defaults to ``--qd`` but can be larger; the campaign setting is
256 slots at QD 64.  A FIFO free-slot scheduler keeps other slots available
when a command completes out of order, while a per-slot ownership guard
prevents a slot from being reused before its CQE.

.. list-table::
   :header-rows: 1

   * - Flags
     - Backing and registration
     - NVMe ``addr``
     - DMA-mapping intent
   * - none
     - Anonymous normal pages, unregistered
     - User virtual address
     - Per command
   * - ``--hugepage``
     - Anonymous hugetlb pages, unregistered (legacy-compatible behavior)
     - User virtual address
     - Per command
   * - ``--fixed``
     - Anonymous normal pages, ordinary io_uring fixed registration
     - Registered user virtual address
     - Per command
   * - ``--fixed --hugepage``
     - Anonymous hugetlb pages, ordinary io_uring fixed registration
     - Registered user virtual address
     - Per command
   * - ``--premap``
     - blk-iobuf KBUF allocation request in a sparse fixed-buffer table
     - Offset zero
     - Retained-registration request
   * - ``--strict-premap``
     - The same request, rejecting a DMA page smaller than the pool folio
     - Offset zero
     - Strict retained-registration request

The address distinction is an ABI requirement, not presentation.  An ordinary
registered buffer retains its userspace base as ``imu->ubuf``; the scalar fixed
import therefore receives that virtual address (plus an offset if desired).
The blk-iobuf KBUF provider has ``imu->ubuf == 0``, so its scalar address is an
offset and the first byte is ``0``.

An accepted ``ALLOC_IOBUF`` CQE proves that the fixed KBUF slot was allocated,
but best-effort premap can still fall back to ordinary mapping.  Consequently
the JSON says ``premap_requested`` and ``dma_mapping_intent`` rather than
claiming a retained DMA mapping.  The hardware runner must establish the
actual result from the queue/controller premap counters and trace evidence.

The two matrices
----------------

Keep ``--dev``, ``--count``, ``--qd``, ``--slots``, ``--buffer-len``, and the
LBA range identical within a comparison.  The campaign common arguments are:

.. code-block:: console

   common="--dev /dev/ng0n1 --count 65536 --qd 64 --slots 256 \
           --buffer-len 2097152 --lba-size 512"

The count above is only an example, but use a multiple of ``--slots`` so the
JSON touched-slot bitmap must contain every slot.

Matrix A: clamp-safe requests on the ordinary/strict kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every slot is 2 MiB and every command is 128 KiB.  This keeps command counts
and bytes identical while comparing normal-page dynamic mapping,
hugetlb-backed dynamic mapping, and requested retained mapping:

.. code-block:: console

   sudo ./nvme_uring_cmd_smoke $common --len 131072 --fixed
   sudo ./nvme_uring_cmd_smoke $common --len 131072 --fixed --hugepage
   sudo ./nvme_uring_cmd_smoke $common --len 131072 --premap
   sudo ./nvme_uring_cmd_smoke $common --len 131072 --strict-premap

Matrix B: 2 MiB requests on the test-only clamp-lift kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The required ordinary no-premap arm is the hugetlb-backed fixed buffer.  It is
physically hugepage-backed but still takes the NVMe dynamic DMA-map path for
every command:

.. code-block:: console

   sudo ./nvme_uring_cmd_smoke $common --len 2097152 --fixed --hugepage
   sudo ./nvme_uring_cmd_smoke $common --len 2097152 --premap
   sudo ./nvme_uring_cmd_smoke $common --len 2097152 --strict-premap

``--fixed`` with normal 2 MiB slots is diagnostic-only, not a performance arm.
``MADV_NOHUGEPAGE`` forces 4 KiB backing, so a 2 MiB request can exceed the
NVMe/block maximum-segment limit.  It may fail, silently take a
``bio_copy_user_iov()`` bounce/copy fallback, or map directly if enough
physically adjacent pages coalesce.  Any success is path-ambiguous.  Exclude
both the failure and an otherwise unproven success from performance results
unless an independent probe proves a direct no-copy path.  Neither outcome is
evidence against the hugetlb or premap paths.

Backing proof and hugepage provisioning
----------------------------------------

All user mappings are allocated and completely faulted before ``ready``.
Normal mappings must pass all of these checks or the tool refuses to run:

* ``MADV_NOHUGEPAGE`` succeeds and ``smaps`` contains ``VmFlags: nh``;
* ``AnonHugePages`` is zero;
* ``KernelPageSize`` and ``MMUPageSize`` equal the base system page;
* every slot has base-page alignment; and
* ``mincore`` reports every base page resident.

For ``--hugepage``, the slot length must be a multiple of the default
``Hugepagesize`` from ``/proc/meminfo``.  The tool requires every slot to have
that alignment, complete ``mincore`` residency, ``VmFlags: ht``, sufficient
``Private_Hugetlb``/``Shared_Hugetlb`` bytes, and matching
``KernelPageSize``/``MMUPageSize``.  JSON records those fields and the
``HugePages_*`` counters before and after setup.

At 256 slots of 2 MiB, reserve at least 512 MiB (256 pages) plus headroom for
other hugetlb users.  Also raise ``RLIMIT_MEMLOCK`` enough for ordinary fixed
registration.  Check the host before running, for example:

.. code-block:: console

   $ grep '^Huge' /proc/meminfo
   $ ulimit -l

Measurement barrier
-------------------

Pass two inherited file descriptors together:

* ``--ready-fd`` is the tool-to-controller event stream;
* ``--start-fd`` is the controller-to-tool control stream.

The protocol is ``ready-S-done-F-v1`` and all bytes are exact:

1. The tool allocates, faults, registers, proves backing, and samples initial
   io_uring counters.
2. It writes ASCII ``ready\n`` to the event fd and blocks.
3. The controller enables perf/tracing, then writes the single byte ``S``.
4. The tool runs and times the SQE preparation, submission, and CQE-reap loop.
5. Immediately after the last CQE/end timestamp and the two ring-counter loads,
   it writes ``done\n`` when the timed loop completed.  A timed-loop failure
   writes ``error\n`` instead.  ``done`` is not the final acceptance verdict:
   post-window validation and teardown can still make JSON and exit status
   report failure.
6. The controller disables measurement and writes the single byte ``F``.
7. After a valid ``F``, the tool summarizes latencies, unregisters buffers,
   unmaps memory, closes the device, and emits JSON.

Wrong control bytes, EOF, short/failed writes, or interrupted syscalls that do
not recover cause a nonzero exit.  A bad or missing ``S`` causes a best-effort
``error\n`` event and no wait for ``F``.  A bad or missing ``F`` invalidates the
run; cleanup then proceeds without the acknowledgement rather than waiting
forever.  Controllers must monitor both the event stream and child exit/EOF.
The successful handshake keeps both allocation and premap
invalidation/unregistration outside the external PMU window.

Machine-readable acceptance fields
----------------------------------

The JSON schema identifier is ``nvme_uring_cmd_smoke/v1``.  A successful
campaign run requires at least:

* ``status == "ok"``, ``errors == 0``, and
  ``successful_commands == count``;
* ``submitted == completed == count``;
* ``slot_validation.passed == true`` and, when count is at least slots,
  ``slot_validation.touched == slots``;
* every ``ring_counters`` value and delta is zero;
* when enabled, every ``barrier`` state flag and ``barrier.complete`` is true;
* ``latency_ns.samples == count``; and
* the mode-specific backing proof above.

The touched bitmap is a hex string of bytes.  Slot ``N`` is bit ``N % 8`` of
byte ``N / 8``.  Latency mean/p50/p95/p99/max values are userspace-observed
nanoseconds from the batch's immediate pre-submit timestamp to CQE reap.  The
aggregate ``elapsed_ns`` covers the complete I/O loop.  Neither substitutes
for device latency tracepoints, but both are bounded, consistent comparison
evidence.

External NVMe command evidence
------------------------------

JSON and CQEs prove the userspace workload outcome, but not device-level trace
attribution.  Capture command evidence in a separate, non-performance run and
fail the run unless the tracer reports zero producer drops, exactly ``count``
unique ``nvme_cmd`` records, and exactly ``count`` matching
``nvme_cmp`` records keyed by ``user_data``.  The low 32 bits of ``user_data``
must be the complete sequence ``0..count-1``; its high 32 bits must match the
expected trace group.  Every command must be opcode ``0x02`` with
``NVME_URING_CMD_IO``, and its namespace, ``data_len``, SLBA, ``bytes``, and
``nlb`` must match the JSON geometry and sequence.  The monitor reports
``nlb == blocks_per_io``; a raw-command tracer instead sees
``cdw12[15:0] == blocks_per_io - 1``.  Every matching completion must report
zero error.  Command-setup records without matching successful completions are
not proof that I/O reached the device.

For this proof, start the monitor with the workload PID plus ``--quiesced`` and
``--no-cq-overflow``.  The overflow hooks are system-wide, so disabling them
leaves only PID-scoped command records and their transitively filtered device
completions as ring-buffer producers.  The smoke JSON's ``cq.koverflow`` start,
end, and delta values are the authoritative CQ-overflow proof.  The optional
BPF overflow events are supplementary diagnostics: on modern kernels the
capability record reports complete coverage only when the shared
``io_alloc_ocqe`` helper attached, or when both ``io_cqe_overflow`` and
``io_cqe_overflow_locked`` attached.  The allocator strategy is preferred
because it covers both paths without double-counting and remains attachable
when the compiler inlines the locked wrapper.

The workload must remain blocked after ``done`` while the controller signals
and waits for the monitor.  Submission fentry returns before request issue,
device end-io fentry returns before the CQE can be reaped, and ``done`` follows
the final CQE.  It is therefore the causal quiescence boundary for these
PID-scoped producers.  The monitor then detaches every BPF link, consumes the
ring buffer until it is empty, emits a final clock anchor, and writes its
terminal ``drops`` record.  Require monitor exit status zero and all of these
terminal fields:

* ``dropped == 0``;
* ``consumer_drained == true``;
* ``quiesced_contract == true``;
* ``consumer_complete == true``; and
* ``drained_after_detach >= 0`` (the value is informational).

Only after the monitor has exited successfully may the controller send ``F``
to let the workload unregister its buffers and exit.  This ordering proves
that no committed command or completion record was abandoned in
the userspace ring-buffer consumer and prevents PID reuse during attribution.
The monitor rejects ``--quiesced`` without a nonzero ``--pid``, with ``--dur``,
or without ``--no-cq-overflow``.  An ordinary duration expiry or signal does
not claim this completeness contract.
