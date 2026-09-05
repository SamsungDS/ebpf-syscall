# kvio open work

This file records the gaps between what kvio proves today and what users may
reasonably expect it to prove. A completed item must include a test or a
published artifact; changing the wording alone does not complete it.

## Current boundary

- A drop-free `nvme_tp_monitor` capture records the requested NVMe command
  stream and completion-latency metadata without recording payload bytes.
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

- [ ] Add a machine-readable workload schema with source, revision, capture
  method, hardware geometry, privacy transformation, and evidence label.
- [ ] Record real agentic prefix-growth, restore, eviction, and same-device
  interference traces. Keep synthetic stress profiles clearly labeled.
- [ ] Add measured profiles only after preserving the source record and the
  derivation from that record to benchmark parameters.
- [ ] Keep the DGraphFin GNN workload as a method example, not as evidence that
  every KV-cache workload has the same request shape.

## Packaging and regression tests

- [x] Add a clean offline installation test using `DESTDIR`, block Python
  socket creation, run every file-only workflow, and check recorder dispatch.
- [ ] Produce a distribution SBOM, record final artifact hashes, and validate
  the package under an independently enforced network-denied host or container.
- [ ] Add compressed manual pages when a distribution packaging format is
  introduced.
- [ ] Decide whether a future package should split the eBPF tracers, kvio
  runtime, and development/reproduction material.
