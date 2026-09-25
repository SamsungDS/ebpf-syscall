# kvio open work

This file records the gaps between what kvio proves today and what users may
reasonably expect it to prove. A completed item must include a test or a
published artifact; changing the wording alone does not complete it.

## Current boundary

- A drop-free `nvme_tp_monitor` capture records the commands built and
  completed by the selected Linux NVMe namespace, plus completion-latency
  metadata, without recording payload bytes. It is below syscall and io_uring
  batching, but it is not a PCIe/firmware trace and cannot see SPDK/VFIO paths
  that bypass the Linux NVMe driver.
- `kvio iolog` and `kvio fio-certify` check the finite file translation:
  operation, byte offset, length, order, and sub-microsecond timestamp
  quantization.
- `kvio compare` checks the re-recorded device stream, reports issue-timing
  error, completion latency, and nonzero completion status, and can store that
  hash-bound result in the confidential replay bundle. Requested-stream
  equality and successful completion are separate verdicts.
- These checks do not prove equal application latency, equal performance, or
  anonymity.
- Capture schema v1 binds replay input to one selected device/namespace and a
  terminal drop count. Legacy unversioned input requires an explicit override.

## Build a bank-local release boundary first

- [x] Distinguish confidential capture, confidential replay bundle, and an
  externally authorized release in the manuals.
- [x] Reject duplicate JSON keys, non-terminal drop accounting, unknown capture
  versions, and mixed device/namespace scope for versioned replay input.
- [x] Define a fresh, closed external-result grammar. Do not reuse the current
  bundle, which preserves exact placement and carries a source digest.
- [x] Add an offline verifier that rejects unknown files and fields, real paths,
  source digests, executable hooks, path traversal, and hash mismatches.
- [x] Keep bundle conformance, bank-internal evidence, and human release
  authorization as separate machine-readable verdicts.
- [ ] Authenticate internal evidence and connect authorization to existing
  organizational identity, signing, revocation, and approval systems. A draft
  candidate must continue to report `export_allowed: false` until then.
- [x] Package the minimal capture/fio/verification path without PyTorch, model
  downloads, a runtime network requirement, or the LMCache engine. Build the
  Rust verifier with Cargo registry access disabled and ship a synthetic
  fixture.
- [ ] Run a bank-local A/B pilot that exports only fixed, rounded result fields.
  Add trace relocation only if that results-only boundary cannot answer the
  engineering question.

## Repeat the historical DGraphFin replay

- [ ] Capture the original and fio replay again with the fixed nanosecond to
  microsecond exporter and a final zero-drop record on both sides.
- [ ] Publish the bundle and successful independent Rust certification.
- [ ] Publish ordered `(operation, offset, length)` equality or the exact
  mismatch. Do not substitute command count or a size histogram for this
  result.
- [ ] Publish rebased issue-time error and both completion-latency
  distributions. Keep these separate from the read-amplification A/B result.

The old run established rounded command-count, byte-count, and request-size
agreement. Its referee did not compare ordered offsets and its timestamps were
compressed by 1,000. It is not evidence for the checks above.

## Define and implement optional trace relocation

- [x] Maintain the threat model in [`PRIVACY.md`](PRIVACY.md) for workload
  identity, tenant identity, device layout, request cadence, and KV object
  identity. Use *payload-free*, *data-minimized*, and *anonymous* deliberately.
- [ ] Add a sanitizer that can remove disk, namespace, PID, TID, process name,
  `user_data`, queue, command ID, clock anchors, and absolute time.
- [ ] Reject or cryptographically remap `key_hex`, object IDs, and session IDs.
  Add negative tests that scan every output field for prohibited identifiers.
- [ ] Support an offset transform that rebases or consistently remaps regions
  while preserving declared locality properties. Record that this loses
  absolute placement and may prevent offset-to-object attribution.
- [ ] Support explicit time shifting, scaling, bucketing, or bounded jitter.
  Record the transform and its maximum error in the certificate.
- [ ] Make sanitized artifacts self-describing: list removed, remapped, and
  retained fields and the fidelity claims that remain valid.

Exact offsets and timing are necessary for exact device replay, so strong
sanitization and exact fidelity cannot always be offered by the same artifact.
Provide separate shareable and in-house artifacts when the threat model
requires it.

Relocating addresses does not hide the access graph: `A, B, A, C` and
`X, Y, X, Z` have the same repetition pattern. Call relocated traces
confidential transformed traces, disclose that linkage can remain, and prefer
bank-local results when that disclosure is unacceptable. A storage slot is
also not automatically an application object, tenant, or customer; v1 must
reject ambiguous or reused mappings rather than inventing that attribution.

## Extend runtime fidelity

- [x] Write one source/replay `kvio compare` result into the bundle's
  `runtime_device_validation` field, bind it to both captures, refresh bundle
  checksums, and reject contradictory fields in the independent Rust verifier.
- [x] Pair each completion with its command across queue and command-ID reuse,
  then report per-command latency error in addition to independent latency
  distributions. Refuse the paired claim for overlap, missing commands,
  orphan completions, or inconsistent latency timestamps.
- [ ] Validate fio timestamp pacing and publish tolerances for each supported
  IO engine at low and high IOPS.
- [ ] Represent concurrent producers explicitly. A single fio iolog preserves
  a total order but not the original queue occupancy or submission overlap.
- [ ] Test flush, discard, and write semantics before certifying those
  operations. Keep raw-device recipes read-only until the destructive case is
  intentional and independently guarded.
- [x] Document limits for stacked block devices, native NVMe multipath,
  partitions, and captures that span namespaces with different logical block
  sizes. Define the claim as a leaf-namespace stream, not an upper-layer or
  controller-path reconstruction.

## Grow the real-workload catalog

- [x] Add a machine-readable workload schema with source, revision, capture
  method, hardware geometry, privacy transformation, and evidence label.
  Validate unknown fields, duplicate identifiers, artifact digests, and the
  distinction between trace-derived and device-measured evidence.
- [ ] Record real agentic prefix-growth, restore, eviction, and same-device
  interference traces. Keep synthetic stress profiles clearly labeled.
- [ ] Add measured profiles only after preserving the source record and the
  derivation from that record to benchmark parameters.
- [ ] Keep the DGraphFin GNN workload as a method example, not as evidence that
  every KV-cache workload has the same request shape.

## Capture application storage work above the device and replay it elsewhere

kvio began below the block layer: a device capture, a fio translation, a
comparison. The work in this section moves the capture point up to where an
application or its storage engine decides *what* to store, load, list,
rename and delete, so the same logical workload can be replayed on a
different target, including a mounted file system or an object endpoint on
another machine, from several clients at once, without a GPU. Each item
below is written to be picked up on its own; a completed item includes a
test, a fixture or a published run record, and never a wording change alone.

### What exists

- `kvio.workload.v3` (`workload3.py`): one envelope for typed operations of
  three API families, `object` (store, load, release, exists), `posix`
  (open, close, pread, pwrite, read, write, fstat, stat, readdir, rename,
  unlink, mkdir, rmdir, truncate, ftruncate, fsync, fdatasync) and `s3`
  (put, get, head, list, delete, multipart create, part, complete, abort).
  Identities are opaque node ids with an incarnation, synthetic entry
  names and handle ids that replay rebinds; every dependency edge carries
  its kind (program order, application synchronization, observed overlap,
  or the older same-object rule of the v2 normalizer); an operation may
  declare the set of outcomes an intentional race is allowed to produce;
  provenance says whether release times are observed submissions,
  measured arrivals or declared delays. `kvio.intent.v2` records carry
  forward through an explicit adapter and keep their own digests.
- Capture adapters that observe a real component and record its typed
  calls, outcomes and timestamps without touching payload: a wrapper for
  LMCache's raw_block core (`lmcache_adapter.py`) and a serving-time hook
  that wraps the cores a running LMCache builds inside a vLLM worker
  (`lmcache_capture_hook.py`, armed by `sitecustomize` when
  `KVIO_CAPTURE_DIR` is set); an in-process POSIX recorder (`posix_fs.py`,
  `RecordingFS`); a boto3-wrapping S3 recorder (`s3_client.py`,
  `RecordingS3`). Names and keys are replaced by synthetic ones; the
  mappings stay in private sidecars.
- Replay engines behind one registry (`engines.py`, `kvio engines`):
  LMCache's real raw_block core over a file or a namespace, a direct POSIX
  target under a generated root, an S3 SDK against a configured endpoint,
  and in-memory fakes for contract tests. Preflight refuses a workload
  whose calls the engine cannot make before anything is mutated. Every run
  writes a fidelity manifest naming the workload's evidence labels, the
  modules actually loaded, the provider and resolved configuration, the
  timing profile, the content profile, and the missing dimensions.
- One executor (`intent_exec.py`, `kvio execute`) with three timing
  profiles: offered load (recorded release times; a slow target shows as
  backlog, never as a quietly reduced offered load), dependency replay and
  saturation. A coordinator (`coordinator.py`, `kvio coordinate`) shards a
  workload by stream across clients on any number of hosts, starts them
  together, measures each client's clock offset and drift, refuses
  cross-client dependencies it cannot acknowledge, and merges ledgers with
  pooled quantiles.
- Named content profiles (`content_profile.py`, `kvio content`): zeros and
  incompressible as controls, and a mixed profile with independent knobs
  for zero runs, repeated patterns and duplicate classes; reported ratios
  are calibration figures for the generator, not claims about a target.
- Validated so far: contract fixtures on the fakes; an in-process POSIX
  capture equal to the application's own ledger and replayed on a real
  directory to the same final state; an SDK-level S3 capture replayed to
  the same state against an independently implemented S3 service; the
  same object workload from one client, two clients on one host and two
  hosts over a virtual network against that service, with the client
  process identified as the limit; one real serving capture (a vLLM with
  LMCache's raw_block tier on a GPU) replayed on a CPU-only host through
  the real engine with every object outcome reproduced.

### Multi-client dynamics

- [ ] Add a queueing positive control: a fake service with configurable
  service time and fault injection, so the coordinator demonstrably shows
  backlog, latency growth and errors before any real service is measured.
- [ ] Prove client headroom before ranking targets: sweep clients per host
  and workers per client, record client CPU, memory and NIC use beside
  the ledger, and report the point where the service rather than the
  client limits. A client-limited run is a result; say so.
- [ ] Publish the two scaling experiments separately: fixed total offered
  load spread over more clients, and fixed per-client load with more
  clients; for each, disjoint versus shared files or key prefixes, and
  data-only, metadata-heavy and mixed operation mixes.
- [ ] Run the two-host case over a physical network with the transport
  named and verified (a mount does not prove RDMA; HTTP does not become
  RDMA because the NIC supports it).
- [ ] Implement cross-client dependencies through explicit acknowledgement
  relayed by the coordinator; keep timestamps out of synchronization.

### Witnesses for a network target

- [ ] Add collectors for process resources, network interfaces, RDMA port
  counters where present, and file-system client statistics (for a
  parallel file system client: its per-mount and per-target RPC
  statistics and its network-layer state). Snapshot shared counters, never
  reset them; keep raw snapshots, units, windows and parser version.
- [ ] Ingest server-side counters or per-request spans when an operator can
  supply them, join them to the client ledger with the clock uncertainty
  recorded, and label what each level of evidence permits: client-visible
  latency and throughput always; per-stage attribution only where joined.
- [ ] Keep the block-level witness for local replays as the auditable
  baseline and say when it is absent (a client of a remote service has no
  NVMe tracepoint to watch).

### A native object client

- [ ] Add an adapter for the public NIXL object-storage plugin contract:
  host-memory and object descriptors, registration and buffer lifetime,
  completion polling, and a doctor that distinguishes an absent plugin,
  absent native libraries, configuration failure, connection failure and
  an unsupported operation. Reject range reads, partial writes, delete,
  listing, expiry and conditional operations unless the installed
  provider is shown to support them; memory deregistration is not object
  deletion.
- [ ] Add a differential harness for every adapter: drive the real
  component directly and through kvio with the same inputs, compare
  outcomes, final state and the request properties the profile claims,
  and check the loaded library's provenance rather than the adapter's
  label. Timing agreement needs repeated runs and bounds.

### File-system capture beyond adapters we control

- [ ] Repair the eBPF syscall tracer into a replayable request record:
  paired enter and exit keyed by task and operation, open, dup, close,
  fork and exec handle lifetimes, requested and completed bytes, known and
  unknown offsets, returned metadata and directory enumeration, flags,
  errors and loss accounting; publish the supported-syscall matrix. Until
  that gate passes, capture support is adapter-scoped.
- [ ] Capture one real CPU application through the in-process adapter (a
  feature store that reads node features off storage is the obvious
  candidate) with reproducible inputs and independent output checks,
  replay it on a second file system configuration and compare final
  state. Record which calls the integration covers.
- [ ] Represent the initial namespace as a graph with hierarchy, shared hot
  directories and fan-out preserved; a flat hash-named directory changes
  metadata contention.

### Object-store capture beyond fixtures

- [ ] Capture one real object-store application through the SDK recorder
  and replay it against an independently implemented S3 service; record
  uncovered SDK paths and transfer helpers as coverage gaps.
- [ ] Add the endpoint capability matrix (conditional requests, versioned
  operations, tags, copy, rename where an endpoint offers it) as declared
  capabilities with probes; refuse an operation an endpoint does not
  support rather than lowering it silently (an atomic rename is not a
  copy plus a delete).
- [ ] Add a logical-workload replay mode for multipart uploads that may
  re-choose part size and concurrency, reported separately from the
  API-fidelity mode that preserves the captured request graph.
- [ ] Add a recording proxy as a later, separately qualified capture method
  for clients that cannot be instrumented.

### Content

- [ ] Add an opt-in payload profiler that samples buffers when they are
  stable and records compressibility under named algorithms, entropy and
  keyed equality classes for duplicate accounting, with its overhead and
  coverage; default capture stays metadata-only.
- [ ] Calibrate profiles against real KV-cache chunk representations
  (bf16, fp8 and codec-encoded) with the representation and source
  recorded, without shipping the chunks.
- [ ] Report a target's physical reduction only from the target's own
  counters; without them report logical bytes and the profile and leave
  reduction unknown.

### Serving capture

- [ ] Write the recorder's end marker from a signal handler in the worker,
  so a capture stopped by SIGTERM is complete rather than partial.
- [ ] Capture and replay the realization where the storage engine stages
  through device memory rather than host memory, and state the memory
  path in the manifest.
- [ ] Treat the observed cost of loading a prefix from the tier against
  recomputing it as a benchmark question with queue depth and load
  parallelism as the variables, not as a fact about any drive.

### Qualification pack for an operator

- [ ] Produce a pinned build recipe, public synthetic fixtures for data,
  metadata, reuse and content profiles, a doctor, a target-configuration
  template for a mounted file system, an S3 endpoint and a native object
  client, exact commands for smoke, bounded load and evidence packaging,
  the expected checks, and a report bundle that marks every unrun gate
  `NOT_RUN`. An operator with a parallel file system mount or an object
  endpoint should be able to run it without private source access, a GPU
  or a model download, and return capability gaps and evidence rather
  than design an adapter.
- [ ] Keep credentials, production paths and keys out of every capture and
  report; opaque identities are not a claim of anonymity, and the privacy
  boundary in [`PRIVACY.md`](PRIVACY.md) applies to network captures as
  it does to device captures.

## Packaging and regression tests

- [x] Add a clean offline installation test using `DESTDIR`, block Python
  socket creation, run every file-only workflow, and check recorder dispatch.
- [ ] Produce a distribution SBOM, record final artifact hashes, and validate
  the package under an independently enforced network-denied host or container.
- [ ] Add compressed manual pages when a distribution packaging format is
  introduced.
- [ ] Decide whether a future package should split the eBPF tracers, kvio
  runtime, and development/reproduction material.
