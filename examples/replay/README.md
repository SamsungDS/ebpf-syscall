# Device-stream replay and object attribution

Tools for turning a device-level capture into an exact hardware replay,
and for grading any replay against its capture at the layer that
matters — the NVMe command stream.

## The problem these tools exist for

A trace-driven replay can be faithful at one layer and wrong at
another. A syscall-level replayer can reissue every `read`/`write` an
application made, byte-for-byte, and the storage device can still
receive a materially different workload — because between the syscalls
and the device sit the page cache, readahead, and writeback, and they
regenerate the command stream nondeterministically on every run.

We measured how large that gap is. On a disposable bare-metal box we
captured two buffered fio workloads at the device level with
`nvme_tp_monitor`, then replayed each two ways and refereed all runs
with the same monitor:

- **Replay A (file level)**: fio's own `write_iolog` — a *perfect*
  file-level operation log, better than any capture tool can produce —
  replayed under identical filesystem conditions.
- **Replay B (device level)**: the captured NVMe command stream itself,
  converted by `mk_dev_iolog.py` and replayed by the same fio, raw and
  `--direct=1`.

| workload | replay A (file level) | replay B (device level) |
|---|---|---|
| 16 KiB buffered writes + fsync | +0.4% commands | **+0.0%** |
| 8 KiB buffered mixed r/w, free-running | **−87.8% commands, −85% bytes, size mix mangled** | **+0.0%, size mix identical** |

The fsync-pinned workload replays fine from the file level — each
write is forced out before the next, so the device stream is nearly
determined by the syscall stream. The free-running page-cache workload
is the structural failure: a *perfect* file-level log produced a
device workload with 8× fewer commands moving 85% less data, because
cache state and writeback timing — not the log — decide what the
device sees. No file-level replayer can close that; the information
does not exist at that layer. If the claim you need is "the device
experienced the same workload," the replay entries must *be* the
device commands.

## The tools

- **`mk_dev_iolog.py`** — capture → replay. Converts an
  `nvme_tp_monitor` JSONL capture into a fio version-3 iolog: one
  entry per captured NVMe command, with its byte offset, length, and
  relative timestamp. `fio --read_iolog=<out> --direct=1` against the
  raw namespace then reissues exactly the captured stream.
- **`compare_streams.py`** — the referee. Takes N tp-monitor JSONLs
  (a capture plus any number of replays) and prints the comparison:
  command counts and inflation percentages, bytes, size distribution,
  and completion latency percentiles from the in-kernel pairing. It
  replaces eyeballing two blkparse texts against each other.
- **`demo_replay_ab.sh`** — the experiment above, end to end, on a
  disposable machine with an empty NVMe namespace (it mkfs's the
  target; it refuses devices carrying a filesystem signature).

Known gap, stated where it counts: in our runs fio replayed the
device iolog flat-out instead of pacing by the v3 timestamps, so
command-*stream* fidelity (count, sizes, offsets: 0.0% deviation) is
validated while command-*timing* reproduction is not yet.

## Object attribution: the offset-join

Reproducing the stream is half the story; the other half is knowing
which command served which object. Two witnesses record every
workload: the application layer knows *meaning* (this KV block, these
file offsets, this time window) and the device layer knows *physics*
(this command, this LBA, this completion latency). Joining them needs
a key present in both streams — and the offset-join builds that key
out of the two coordinates no IO can avoid carrying: **where** and
**when**. A command belongs to an object when its byte offset falls in
the object's recorded range and its timestamp falls in the object's
operation window; disjoint ranges make the spatial match unique, time
windows disambiguate reuse, and store/load direction breaks the one
remaining tie.

This is implemented as `--join-by-offset` in
`../lmcache/kvio2perfetto.py`, and it is validated rather than
asserted: on a live serving capture where every command *also* carried
a cooperative user_data tag, both joins ran side by side and the
offset-join agreed with the tag on **111,435 of 111,435 commands
(100.00%)** — and that parity check re-runs automatically during any
conversion where both signals are present.

What it means practically: initiators that cannot tag — POSIX,
buffered IO, cuFile/GDS, unmodified third-party software — get exact
per-object device attribution from records they already produce
(name, offset, size, timestamp). A capture pipeline whose files are
content-addressed gets object identity for free from the filename.
For attribution at the *device* level on file-backed stores, one
FIEMAP snapshot per file (taken once, after writing — nothing on the
IO path) translates file offsets to disk offsets. And for mmap-based
IO the offset-join is not an optimization but the only option: mapped
data movement produces no syscalls at all, so a device-level capture
joined by extents is the only place that IO is even visible.
