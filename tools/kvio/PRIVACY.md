# kvio privacy and release boundary

kvio can help an organization reproduce a storage decision without exposing
application payloads. That does not make its traces anonymous. This document
defines the privacy boundary the project can defend, the first workflow to
build, and the claims that remain out of scope.

## Implementation status

Implemented today:

- `nvme_tp_monitor` records NVMe command metadata without reading payloads.
- Capture schema v1 binds replay input to one selected device/namespace and a
  terminal drop count.
- `kvio iolog` translates a captured requested stream into a fio bundle.
- `kvio fio-certify` checks that finite file translation independently.
- `kvio compare` measures what a re-recorded fio run issued to the device.
- `kvio bench` provides workloads designed from public information and labels
  their evidence.

Not implemented today:

- A format authorized for release outside the data owner's boundary.
- A fixed results-only release grammar and offline release verifier.
- Trace relocation, time transformation, signing, or approval adapters.
- Re-identification tests or a claim that any trace is anonymous.
- A differential-privacy mechanism or privacy budget.

The current capture and fio bundle are confidential engineering artifacts.
They are not release packages.

## The useful first question

Start with a narrow storage decision, such as:

> Does a batching change increase restore-tail latency at a fixed offered
> load?

Run the capture, replay, and A/B comparison inside the organization. Export
only fixed, rounded result fields after review. The recipient can inspect the
open tool and repeat the same public fixture without receiving the production
trace.

This is more useful and easier to defend than beginning with a promise that an
exact trace can safely leave. Exact offsets and request cadence are often the
features needed for replay, and the same features can identify a workload or
reveal infrastructure behavior.

## Protect more than payload bytes

Consider at least these subjects:

- A customer or transaction whose activity affects the trace.
- A session, tenant, application, model, or business unit.
- The organization, including its load, incidents, operating schedule, and
  capacity.
- Its infrastructure, including layout, namespace size, queue behavior, and
  working-set placement.

Assume a recipient may have public benchmark traces, earlier releases, known
incident times, common model geometries, candidate identifiers, and classifiers
over request sizes and timing. Also consider accidental publication, recipient
compromise, subcontractors, and comparison across several releases.

The absence of payload bytes reduces exposure. It does not answer whether the
remaining metadata may leave.

## Keep three verdicts separate

1. **Bundle conformance** checks a versioned grammar, allowed inventory, hashes,
   and internally decidable claims.
2. **Internal evidence** checks source completeness, capture impact, mapping,
   decision utility, and disclosure attacks using data that stays private.
3. **Release authorization** resolves the recipient, purpose, approved roles,
   signer trust, expiration, and final bytes through the organization's own
   controls.

A conforming bundle can still leak information. A bundle containing two strings
called `approval` is not thereby authorized. An external verifier cannot prove
facts about a confidential source it cannot inspect; it can authenticate a
reviewed statement about those facts.

## Release profiles

### Exact confidential

Keep the capture and current fio bundle internal. They preserve exact placement
and relative timing and support the strongest requested-stream comparison. The
current certificate also contains a source-capture digest. Make no anonymity
claim.

This is the current implementation.

### Bank-local results

Run a fixed A/B recipe inside the organization and release only approved,
bounded result fields. Do not allow arbitrary metric names, free text,
per-command rows, source paths, exact timestamps, or unbounded arrays. Keep the
full evidence and source binding in a private audit record.

This is the first planned release profile because it can answer an engineering
question without moving the trace.

### Partner-relocated trace

Optionally build a complete, allowlisted replay bundle for one named recipient
and purpose. Replace source placement with newly allocated regions, remove real
device and process identity, transform time as declared, rebuild every sidecar,
and omit confidential-source digests.

Relocation does not hide the access graph. For example, these traces have the
same repetition pattern:

```text
source:     A B A C
relocated:  X Y X Z
canonical:  0 1 0 2
```

A recipient still learns that the first region was revisited after one other
region. Request sizes, order, and timing make cross-release linkage easier.
Describe this profile as a confidential transformed trace with declared
residual disclosure, not as anonymous.

This profile is planned only after the results-only boundary. Its first adapter
must support one fixed-slot layout and reject ambiguous, overlapping,
cross-region, reused-generation, and unsupported operations. A physical slot is
not automatically an application object, tenant, or customer.

### Public designed workload

Generate a workload from public model geometry or an explicit synthetic stress
assumption, with a public recipe and seed. State whether it is measured,
trace-derived, calibrated, or synthetic. Do not tune or select a supposedly
public workload using private outcomes without subjecting that decision to
release review.

`kvio bench` implements this class today. Its profiles do not claim to
reproduce a confidential deployment.

### Public statistical workload

Generate a new workload from approved aggregate statistics. Calling it
synthetic does not establish anonymity. A differential-privacy claim requires
an implemented mechanism, protected unit, adjacency definition, contribution
bound, release horizon, epsilon, delta, and composed budget.

For customer protection, a candidate neighboring dataset differs by all records
attributable to one customer over the declared horizon. Protecting one request
or one session does not automatically protect that customer. If device commands
cannot be attributed to the claimed unit with bounded sensitivity, do not make
the claim.

This is research, not part of the first release format.

## Requirements for an external format

Build releases from a fresh typed representation in an empty staging directory.
Do not delete fields from a copy of the confidential bundle. The external
serializer must emit only fixed filenames and allowlisted fields.

Reject:

- Unknown schema versions, fields, claims, profiles, and files.
- Duplicate JSON keys, invalid Unicode, and lossy large-integer conversion.
- Source hashes, real paths, device identity, mapping secrets, and raw logs.
- Symlinks, path traversal, archive surprises, executable hooks, and oversized
  or unbounded inputs.
- Missing, failed, inconclusive, or stale evidence required by the profile.
- Changes to any byte after approval.

Rebuild normalized streams, translations, manifests, and replay files from the
same external representation. A transformed `commands.iolog` beside an
unchanged source-derived `workload.json` is not a safe release.

Generate fio wrappers from trusted local templates. Never execute job files or
pre-run commands supplied by a received bundle. Bind replay at execution time
to an explicitly approved disposable target and byte range.

## State fidelity by endpoint

Every fidelity claim must name both sides:

- source capture to transformed stream;
- transformed stream to fio input; or
- fio input to the re-recorded device stream.

A relocated stream can translate exactly into fio even though it deliberately
differs from the source placement. Time bucketing may preserve order while
changing bursts and queue pressure. Removing completion data preserves a
requested stream, not source service time. Report each invariant and each
intentional change separately.

Privacy and utility also need separate results. A transformation that hides
placement but reverses the storage decision is not useful. A transformation
that preserves the decision can still disclose a recognizable workload.

## Words the project can defend

- **Payload-free:** the named capture path does not record application payload
  bytes. This does not apply to prompt-bearing agent traces.
- **Data-minimized:** the named artifact contains only the listed fields needed
  for a stated purpose. This does not mean non-identifying.
- **Pseudonymized:** identifying values were replaced while the additional
  identifying information is controlled separately. Do not apply this word to
  an LBA merely because it moved.
- **Anonymous:** no automated kvio claim. This needs a context-specific
  identifiability assessment and may be inappropriate for exact access
  patterns.
- **Synthetic:** generated by a named method from either public or confidential
  inputs. State which. The word alone is not a privacy guarantee.
- **Fidelity checked:** name the verifier, artifacts, endpoints, invariants, and
  runtime measurements. Do not shorten this to performance equivalence.
- **Privacy certified** or **bank-grade:** do not use as product guarantees.
  Name the implemented control, attacker, residual disclosure, evaluator, and
  date instead.

## Adoption and stop rules

Package a minimal offline capture, fio, and verification path without PyTorch,
model downloads, or network access. Measure capture overhead. Require an
approved disposable replay target. Have a second operator reproduce a public
fixture from the documentation before expanding scope.

Stop trace relocation when the permitted transform cannot preserve the storage
decision or its residual disclosure is not approvable. Keep the bank-local
results workflow. Stop differential-privacy work when the protected unit and
sensitivity cannot be justified at useful accuracy. An institution that gets a
useful internal result without releasing its trace is a successful user.

Implementation work and required evidence remain tracked in
[`TODO.md`](TODO.md).
