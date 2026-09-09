ebpf-syscall
============

Observe real storage IO at the layer where it actually happens — syscalls,
io_uring, mmap page faults, and Linux NVMe driver requests — and turn those
captures into things you can *look at* (Perfetto timelines) and *reproduce*
(fio replays). The recurring idea across every tool here is the
**two-witness join**: the application knows *intent* (what it asked for),
the kernel or device knows *mechanism* (what actually moved), and the
interesting number is the gap between them.

Do not treat those layers as interchangeable.  ``syscall_monitor`` does not
hook ``io_uring_enter()``, and even a generic syscall tracer would see one
batch call rather than every SQE.  ``kvio record`` attaches at
``nvme_setup_cmd`` and ``nvme_complete_rq`` below that batching boundary.  See
`How eBPF sees NVMe commands after io_uring batching
<kvio.html#join>`__ for the concrete 64-SQE example, exact probe sites,
correlation maps, and limits of the Linux-driver witness.

These pages are the reStructuredText build of the project's case studies,
so they are searchable and viewable anywhere. Each one also has a
dark-themed standalone HTML version — richer to look at, identical in
content — served under ``/showcase/`` below and reachable via htmlpreview
from the repository's ``docs/*.html``.

.. toctree::
   :maxdepth: 2
   :caption: Case studies

   kvio
   kvio-loadpath
   kvio-perfetto
   gnn-readamp

.. toctree::
   :maxdepth: 1
   :caption: Tools

   nvme-uring-cmd-smoke

Styled showcase pages
---------------------

The standalone dark-themed pages (same content, rich figures) are served
straight from this build:

- `kvio — GPU-free KV-offload IO projector and replayer </showcase/kvio.html>`__
- `kvio load path — the QD~1 case study </showcase/kvio-loadpath.html>`__
- `kvio × Perfetto — cross-layer KV-offload introspection </showcase/kvio-perfetto.html>`__
- `GNN read amplification — see it, replay it without the data </showcase/gnn-readamp.html>`__
- `hardware-model visualization </showcase/hw_model_visualization.html>`__ (an
  interactive plot; it stays HTML rather than reStructuredText)

Reproduce
---------

Every case study has a reproduce recipe under ``tools/reproduce/`` in the
repository, and the tracers, converters, and replay tools it uses are
described in ``CLAUDE.md``. The GNN read-amplification recipe
(``tools/reproduce/gnn-readamp/``) is the worked end-to-end example:
capture with eBPF, chart the A/B on Perfetto, and replay from a payload-free
fio iolog.
