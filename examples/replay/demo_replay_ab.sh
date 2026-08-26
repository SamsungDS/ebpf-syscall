#!/bin/bash
# Replay-fidelity A/B on a disposable box:
#   capture: buffered fio workload on xfs, device stream via nvme_tp_monitor
#   replay A (file-level): fio --read_iolog of fio's own write_iolog (a
#     PERFECT file-level log -- best case for syscall-level replay)
#   replay B (device-level): fio v3 iolog generated from the tp-monitor
#     capture, replayed raw against the namespace
# Referee for all runs: nvme_tp_monitor.
set -e
# DESTRUCTIVE: this demo mkfs's the target device. It takes the device
# explicitly and refuses anything that carries a filesystem signature or
# a mount -- device names are NOT stable across boots, never hardcode one.
DEV=${1:?usage: demo_replay_ab.sh /dev/nvmeXnY (an EMPTY namespace)}
DISK=$(basename "$DEV")
if sudo blkid "$DEV" >/dev/null 2>&1 || lsblk -no MOUNTPOINTS "$DEV" | grep -q /; then
    echo "$DEV carries a filesystem signature or mount -- refusing" >&2
    exit 1
fi
MNT=/mnt/replay_ab_demo
sudo mkdir -p $MNT && sudo chown $(id -u):$(id -g) $MNT
TP=~/tracer/nvme_tp_monitor
OUT=~/replayab
mkdir -p $OUT $MNT

run_traced() { # name cmd...
  local NAME=$1; shift
  sudo $TP --disk $DISK --jsonl $OUT/$NAME.jsonl --dur 3600 &
  local MON=$!
  sleep 2
  "$@" > $OUT/$NAME.fio.log 2>&1 || true
  sleep 2
  sudo kill $MON 2>/dev/null; wait $MON 2>/dev/null || true
}

fresh_fs() {
  sudo umount $MNT 2>/dev/null || true
  sudo mkfs.xfs -f -q $DEV
  sudo mount $DEV $MNT
  sudo chmod 777 $MNT
}

job() { # name bs extra...
  local NAME=$1 BS=$2; shift 2
  cat > $OUT/$NAME.fio <<EOF
[global]
filename=$MNT/fio_testfile
size=1G
runtime=20
time_based
group_reporting
[$NAME]
ioengine=libaio
bs=$BS
direct=0
numjobs=1
$@
EOF
}

echo "=== workload captures (buffered, on xfs) ==="
job sync_heavy 16k "rw=write
iodepth=1
fsync=1"
fresh_fs
run_traced cap_sync fio $OUT/sync_heavy.fio --write_iolog=$OUT/sync_heavy.iolog

job mixed_buf 8k "rw=randrw
rwmixread=70
iodepth=16"
fresh_fs
run_traced cap_mixed fio $OUT/mixed_buf.fio --write_iolog=$OUT/mixed_buf.iolog

echo "=== replay A: file-level iolog, same fs conditions ==="
fresh_fs
run_traced repA_sync fio --name=repA --read_iolog=$OUT/sync_heavy.iolog --ioengine=libaio --direct=0
fresh_fs
run_traced repA_mixed fio --name=repA --read_iolog=$OUT/mixed_buf.iolog --ioengine=libaio --direct=0

echo "=== replay B: device-level iolog from tp capture, raw namespace ==="
sudo umount $MNT
python3 ~/mk_dev_iolog.py $OUT/cap_sync.jsonl $DEV > $OUT/dev_sync.iolog
python3 ~/mk_dev_iolog.py $OUT/cap_mixed.jsonl $DEV > $OUT/dev_mixed.iolog
run_traced repB_sync sudo fio --name=repB --read_iolog=$OUT/dev_sync.iolog --ioengine=io_uring --direct=1 --iodepth=128
run_traced repB_mixed sudo fio --name=repB --read_iolog=$OUT/dev_mixed.iolog --ioengine=io_uring --direct=1 --iodepth=128

echo "=== referee comparison ==="
python3 ~/compare_streams.py \
  sync:$OUT/cap_sync.jsonl:$OUT/repA_sync.jsonl:$OUT/repB_sync.jsonl \
  mixed:$OUT/cap_mixed.jsonl:$OUT/repA_mixed.jsonl:$OUT/repB_mixed.jsonl
echo DONE
