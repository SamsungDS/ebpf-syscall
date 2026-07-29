#!/bin/bash
# Capture one force-SSD GNN access phase at the NVMe device layer.
#
# Runs drive_ssd.py (one access pattern) while nvme_tp_monitor records
# every device command on the store's disk. The driver prints
# CLOCK_MONOTONIC phase/progress markers; nvme_tp_monitor stamps commands
# on the same clock, so <OUT>.jsonl (mechanism) and <OUT>.phase.txt
# (intent) join directly. Feed both to readamp2perfetto.py.
#
# usage: cap_ssd.sh <neighbor|page> <natural|random|bfs|metis> <seconds> <out-prefix>
# env:   KNLP_DIR   knlp gnn tree with drive_ssd.py     (default /data/knlp)
#        NVME_TP    path to the built nvme_tp_monitor    (default nvme_tp_monitor in PATH)
#        DISK       nvme disk backing the store          (default nvme0n1)
set -eu
ACC=$1; LAY=$2; T=$3; OUT=$4
KNLP_DIR=${KNLP_DIR:-/data/knlp}
NVME_TP=${NVME_TP:-nvme_tp_monitor}
DISK=${DISK:-nvme0n1}

cd "$KNLP_DIR"
sudo "$NVME_TP" --disk "$DISK" --lba-size 512 --jsonl "${OUT}.jsonl" > "${OUT}.tp.log" 2>&1 &
sleep 2
python3 drive_ssd.py "$ACC" "$LAY" "$T" > "${OUT}.phase.txt" 2>"${OUT}.drv.log"
sleep 1
sudo pkill -INT nvme_tp_monitor 2>/dev/null || true
sleep 1
echo "=== phase markers (intent) ==="; grep -E "PHASE_(START|END)" "${OUT}.phase.txt"
echo "=== device reads captured (mechanism) ==="; grep -c '"op_name":"read"' "${OUT}.jsonl" || true
