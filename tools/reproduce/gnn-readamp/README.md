# GNN read-amplification: capture, visualize, and payload-free replay

This reproduces the read-amplification A/B in the
[value showcase](../../../docs/gnn-readamp.html): a GNN reading node
features from an SSD, captured at the NVMe device layer with eBPF, shown
on a Perfetto timeline, and replayed from a data-free fio iolog.

The workload is the public **DGraphFin** financial-fraud graph
(3.7M nodes, 17 features/node) served through knlp's force-SSD feature
store (`make defconfig-gnn-dgraphfin-force-ssd`). DGraphFin is a public
dataset — it stands in here for the *confidential* graph a third party
would actually run. The device capture, iolog, and visualization carry IO
shape — offsets, lengths, timing — without carrying feature values. This
minimizes the data, but exact IO metadata is not automatically anonymous.

## The one idea

Every storage workload has two witnesses. The **application** knows
*intent* — "these 2.6 MB of node features are what I actually consume."
The **device** knows *mechanism* — "1140 MB of 4 KiB pages crossed the
PCIe bus." Read amplification is the gap between them. `drive_ssd.py`
emits the intent on a `CLOCK_MONOTONIC` axis; `nvme_tp_monitor` records
the mechanism on the same clock; `readamp2perfetto.py` lays them on one
timeline so the gap is something you look at.

## Prerequisites

- A host with the store's disk on a real NVMe namespace (we used a
  Samsung 9100 PRO Gen5, `/dev/nvme0n1`, kernel 7.0.10). `sudo` for eBPF.
- `nvme_tp_monitor` built from this tree (`make nvme_tp_monitor`).
- knlp's gnn tree (`/data/knlp`) with `dgraphfin.npz` fetched. Copy
  `drive_ssd.py` into it (it imports knlp's `benchmark_ssd`).
- `pip install perfetto matplotlib` (a venv is fine).

## 1. Capture both arms at the device layer

```sh
cp drive_ssd.py /data/knlp/
# arm A: naive NeighborLoader.  arm B: page-aware (the knlp read-amp fix)
NVME_TP=/path/to/nvme_tp_monitor ./cap_ssd.sh neighbor natural 12 /tmp/nbr
NVME_TP=/path/to/nvme_tp_monitor ./cap_ssd.sh page     natural 12 /tmp/page
```

Each run writes `<prefix>.jsonl` (device commands) and `<prefix>.phase.txt`
(intent markers). O_DIRECT bypasses the page cache, and the independent eBPF
and store counters agreed at 240,698 reads in the naive arm. That agreement is
the evidence for this run; O_DIRECT alone is not a general completeness proof.

Measured (12 s each):

| arm | useful (intent) | device read (eBPF) | RA_signal | RA_fetch |
|---|---:|---:|---:|---:|
| NeighborLoader (naive) | 2.65 MB | 1140 MB / 240,698 reads | **431×** | ~57× |
| Page-Aware (knlp fix)  | 58.3 MB | 502 MB / 61,498 reads | **8.6×** | ~2× |

`RA_signal` = device bytes / useful feature bytes. `RA_fetch` = device
bytes / minimal pages needed (the store's own `ra_physical`). Same data,
same SSD; one architectural change to the *access pattern* reduces
`RA_signal` about 50×, device bytes about 2.3×, and commands about 3.9×.
The page-aware arm also consumes more useful feature bytes, so these ratios
must not be presented as the same result.

## 2. Visualize the A/B on Perfetto

```sh
python3 ../../../examples/replay/readamp2perfetto.py \
  --arm "NeighborLoader (naive):/tmp/nbr.jsonl:/tmp/nbr.phase.txt" \
  --arm "Page-Aware (knlp read-amp fix):/tmp/page.jsonl:/tmp/page.phase.txt" \
  -o gnn_readamp_ab.pftrace
```

Drag `gnn_readamp_ab.pftrace` onto <https://ui.perfetto.dev>. Each arm is
a process group; the *useful MB* counter sits far under the *device MB*
counter and the gap is the amplification. `plot_readamp.py` renders the
same data as a static A/B PNG.

## 3. Payload-free replay

The capture becomes a fio v3 iolog that carries only op/offset/length/time:

```sh
# reads only, in the access phase -- never a write against a raw device
python3 - "$(grep PHASE_START /tmp/nbr.phase.txt | grep -oE 'mono_ns=[0-9]+' | cut -d= -f2)" \
         "$(grep PHASE_END   /tmp/nbr.phase.txt | grep -oE 'mono_ns=[0-9]+' | cut -d= -f2)" <<'PY'
import json,sys
S,E=int(sys.argv[1]),int(sys.argv[2])
records=[json.loads(ln) for ln in open("/tmp/nbr.jsonl")]
meta=[r for r in records if r.get("event_type")=="capture_meta"]
drops=[r for r in records if r.get("event_type")=="drops"]
if not meta or not drops:
    raise SystemExit("source capture lacks metadata or final drop accounting")
with open("/tmp/nbr_reads.jsonl","w") as out:
    out.write(json.dumps(meta[-1])+"\n")
    for r in records:
        if (r.get("event_type")=="nvme_cmd" and
            r.get("op_name")=="read" and S<=int(r["ts"])<=E):
            out.write(json.dumps(r)+"\n")
    out.write(json.dumps(drops[-1])+"\n")
PY
python3 ../../../examples/replay/mk_dev_iolog.py \
  /tmp/nbr_reads.jsonl /dev/source --bundle-dir nbr-replay
../../../kvio fio-certify nbr-replay

# replay it read-only; capture the replay; grade the two streams
sudo nvme_tp_monitor --disk nvme0n1 --dur 60 --jsonl /tmp/replay.jsonl &
monitor_pid=$!
sleep 1
sudo KVIO_TARGET=/dev/nvme0n1 fio nbr-replay/replay-block.fio
wait "$monitor_pid"
../../../kvio compare dgraphfin:/tmp/nbr_reads.jsonl:/tmp/replay.jsonl
```

The iolog action lines use fio v3 microseconds and contain operation, exact
byte offset, and byte length. They contain no features, node IDs, or graph
contents. The historical replay matched rounded command count, total bytes,
and request-size counts. It did **not** validate ordered offsets, and its old
exporter compressed timing by 1,000. Repeat the hardware run with the fixed
bundle and `kvio compare` before claiming ordered-stream or timing fidelity.

Exact offsets and timing still reveal access patterns. Treat this artifact as
payload-free and data-minimized, not proven anonymous. The sanitization and
fidelity work left open is listed in `../../kvio/TODO.md`; the precise replay
guarantees are in `../../../examples/replay/README.md` and `kvio(1)`.

## Files

- `drive_ssd.py` — drive one access pattern, emit intent markers.
- `cap_ssd.sh` — run the driver under `nvme_tp_monitor`.
- `plot_readamp.py` — render the static A/B PNG.
- converter `examples/replay/readamp2perfetto.py`; iolog + referee
  `examples/replay/mk_dev_iolog.py`, `compare_streams.py`.
