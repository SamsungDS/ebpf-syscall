# GNN read-amplification: capture, visualize, and privacy-preserving replay

This reproduces the read-amplification A/B in the
[value showcase](../../../docs/gnn-readamp.html): a GNN reading node
features from an SSD, captured at the NVMe device layer with eBPF, shown
on a Perfetto timeline, and replayed from a data-free fio iolog.

The workload is the public **DGraphFin** financial-fraud graph
(3.7M nodes, 17 features/node) served through knlp's force-SSD feature
store (`make defconfig-gnn-dgraphfin-force-ssd`). DGraphFin is a public
dataset — it stands in here for the *confidential* graph a third party
would actually run. The point of the pipeline is that everything we
publish (the capture, the iolog, the trace) carries only IO shape —
offsets, lengths, timing — never a single feature value.

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
(intent markers). O_DIRECT guarantees every logical read reaches the
device, so the eBPF capture is exact — it matched the driver's own read
count to the command (240,698 vs 240,698 reads; 100%).

Measured (12 s each):

| arm | useful (intent) | device read (eBPF) | RA_signal | RA_fetch |
|---|---:|---:|---:|---:|
| NeighborLoader (naive) | 2.65 MB | 1140 MB / 240,698 reads | **431×** | ~57× |
| Page-Aware (knlp fix)  | 58.3 MB | 502 MB / 61,498 reads | **8.6×** | ~2× |

`RA_signal` = device bytes / useful feature bytes. `RA_fetch` = device
bytes / minimal pages needed (the store's own `ra_physical`). Same data,
same SSD; one architectural change to the *access pattern* cuts device
traffic ~50× for the identical GNN signal.

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

## 3. Privacy-preserving replay (the payoff)

The capture becomes a fio v3 iolog that carries only op/offset/length/time:

```sh
# reads only, in the access phase -- never a write against a raw device
python3 - "$(grep PHASE_START /tmp/nbr.phase.txt | grep -oE 'mono_ns=[0-9]+' | cut -d= -f2)" \
         "$(grep PHASE_END   /tmp/nbr.phase.txt | grep -oE 'mono_ns=[0-9]+' | cut -d= -f2)" <<'PY'
import json,sys
S,E=int(sys.argv[1]),int(sys.argv[2])
out=open("/tmp/nbr_reads.jsonl","w")
for ln in open("/tmp/nbr.jsonl"):
    r=json.loads(ln)
    if r.get("event_type")=="nvme_cmd" and r.get("op_name")=="read" and S<=int(r["ts"])<=E:
        out.write(ln)
PY
python3 ../../../examples/replay/mk_dev_iolog.py /tmp/nbr_reads.jsonl /dev/nvme0n1 > nbr.iolog

# replay it read-only; capture the replay; grade the two streams
sudo nvme_tp_monitor --disk nvme0n1 --lba-size 512 --jsonl /tmp/replay.jsonl &
sudo fio --name=replay --filename=/dev/nvme0n1 --readonly --direct=1 \
         --ioengine=psync --read_iolog=nbr.iolog
```

The iolog holds 240,698 lines of `<ms> /dev/nvme0n1 read <offset> <len>`
and nothing else — no features, no node ids, no graph. Replaying it
reproduced the capture at **+0.0% commands, +0.0% bytes, identical size
mix, 100% of commands at identical offset+size**. That is the whole
value: a third party runs a confidential GNN, hands you this iolog, and
you reproduce and visualize its exact device read pattern without ever
seeing their data. (Command-stream fidelity is validated; fio's v3
timestamp pacing is not — see `../../../examples/replay/README.md`.)

## Files

- `drive_ssd.py` — drive one access pattern, emit intent markers.
- `cap_ssd.sh` — run the driver under `nvme_tp_monitor`.
- `plot_readamp.py` — render the static A/B PNG.
- converter `examples/replay/readamp2perfetto.py`; iolog + referee
  `examples/replay/mk_dev_iolog.py`, `compare_streams.py`.
