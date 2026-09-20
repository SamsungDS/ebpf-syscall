#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Replay one intent per stored KV representation on one raw NVMe namespace,
# with the device's command stream recorded around each timed phase.
#
# The three representations of one chunk (plain BF16 K/V, complete K16/V8,
# V8-only split-tier) are different objects with different byte counts. This
# runs each of them through the same engine on the same drive in the same
# session, at each command size and stream count, so the only thing that
# differs between arms is the object the engine was asked to store.
#
#   DEV=/dev/disk/by-id/nvme-... OUTROOT=out bash sweep_representations.sh
#   STREAMS="1 4 8" SIZES="131072 2097152 33554432" REPEATS=3 ...
#
# The device is named by its persistent id, never by /dev/nvmeXnY: the kernel
# renumbers namespaces across boots. It must be an unmounted, signature-free
# namespace that nothing else uses; every store writes to it.
#
# Each cell brackets the replay with the driver-level tracer, started before
# the phase gate opens and stopped after the timed phases end, so the capture
# holds the commands of the timed store and load and nothing else.
set -u
TOP=${TOP:-$(cd "$(dirname "$0")/../../.." && pwd)}
KVIO=$TOP/tools/kvio
PYTHON=${PYTHON:-python3}
DEV=${DEV:?set DEV to the /dev/disk/by-id path of the namespace}
OUTROOT=${OUTROOT:?set OUTROOT to a new output directory}
TRACER=${TRACER:-$TOP/nvme_tp_monitor}
MODEL=${MODEL:-meta-llama/Llama-3.1-8B-Instruct}
CHUNK=${CHUNK:-256}
NUM_CHUNKS=${NUM_CHUNKS:-8}
ITERS=${ITERS:-3}
WARMUP=${WARMUP:-1}
STREAMS=${STREAMS:-"1 4 8"}
SIZES=${SIZES:-"131072 2097152 8388608 33554432"}
KIND=${KIND:-udmabuf}
REPEATS=${REPEATS:-3}
CAPACITY_GB=${CAPACITY_GB:-64}
RING_DEPTH=${RING_DEPTH:-256}
ADVERTISED_MDTS_BYTES=${ADVERTISED_MDTS_BYTES:?set to the controller MDTS in bytes, 0 for none}
CONTROL_SIZE=${CONTROL_SIZE:-131072}   # the classic per-command-mapping arm
PAD=${PAD:-0}   # 1: round encoded objects up to the block size (charged as padding)

NS=$(basename "$(readlink -f "$DEV")")
[ -b "/dev/$NS" ] || { echo "$DEV does not resolve to a block device" >&2; exit 1; }
if findmnt -rn -S "/dev/$NS" >/dev/null 2>&1 || [ -n "$(sudo wipefs -n "/dev/$NS" 2>/dev/null)" ]; then
  echo "refusing $DEV ($NS): mounted or carries a signature" >&2; exit 1
fi
[ -x "$TRACER" ] || { echo "tracer $TRACER is not built" >&2; exit 1; }
# Align to the namespace's physical block, not its logical one: O_DIRECT only
# demands the logical size, but the physical size is the drive's preferred
# write granularity, and on a 16 KiB indirection-unit drive it is 16 KiB.
BLOCK_ALIGN=${BLOCK_ALIGN:-$(cat "/sys/block/$NS/queue/physical_block_size")}
mkdir "$OUTROOT" || exit 1
echo "@@@ ALIGN physical_block_size=$BLOCK_ALIGN" >> "$OUTROOT/cells.log"

resolve_python() { "$PYTHON" -c 'import sys; print(sys.executable)'; }
PY=$(resolve_python)

wait_marker() {  # path timeout-seconds
  local deadline=$((SECONDS + $2))
  while [ ! -e "$1" ]; do
    [ $SECONDS -lt $deadline ] || return 1
    sleep 0.05
  done
}

run_cell() {  # rep-name intent size streams replica dmabuf-kind
  local rep=$1 intent=$2 size=$3 streams=$4 replica=$5 kind=$6
  local out="$OUTROOT/$rep/s${streams}/c${size}-${kind}/r${replica}"
  local tracer_pid launcher_pid
  mkdir -p "$out/gate" || return 1
  local dmabuf_opts=()
  [ "$kind" = none ] || dmabuf_opts=(--dmabuf "$kind" --dma-ceiling-bytes "$size")
  sudo "$TRACER" --disk "$NS" --jsonl "$out/device.jsonl" --dur 3600 \
    > "$out/tracer.log" 2>&1 &
  tracer_pid=$!
  sleep 0.5
  sudo -E env PYTHONPATH="$KVIO/vendor/lmcache:$KVIO/build:$KVIO" \
    timeout --foreground --signal=TERM --kill-after=10s 600 \
    "$PY" "$KVIO/intent.py" replay "$intent" \
      --device "$DEV" --engine io_uring --odirect \
      --mdts-bytes "$size" "${dmabuf_opts[@]}" \
      --capacity-gb "$CAPACITY_GB" --ring-depth "$RING_DEPTH" \
      --block-align "$BLOCK_ALIGN" \
      --advertised-mdts-bytes "$ADVERTISED_MDTS_BYTES" \
      --target-plan "$out/target-plan.json" \
      --target-manifest "$out/target-run.json" \
      --phase-gate-dir "$out/gate" --phase-gate-timeout-seconds 120 \
      --phase-gate-close \
      > "$out/replay.log" 2>&1 &
  launcher_pid=$!
  if wait_marker "$out/gate/READY" 120; then
    touch "$out/gate/GO"
    wait_marker "$out/gate/DONE" 600 || echo "DONE never appeared" >> "$out/replay.log"
  else
    echo "READY never appeared" >> "$out/replay.log"
  fi
  sleep 0.5
  sudo kill -INT "$tracer_pid" 2>/dev/null
  wait "$tracer_pid" 2>/dev/null
  touch "$out/gate/CLOSE"
  wait "$launcher_pid"
  local rc=$?
  printf 'replay_status=%s\n' "$rc" > "$out/status.txt"
  echo "@@@ CELL rep=$rep streams=$streams size=$size kind=$kind replica=$replica rc=$rc" >> "$OUTROOT/cells.log"
}

for streams in $STREAMS; do
  setdir="$OUTROOT/sets/s$streams"
  pad_opt=()
  [ "$PAD" = 1 ] && pad_opt=(--pad-to-block-align)
  "$PY" "$KVIO/kv_representation.py" --model "$MODEL" --chunk-tokens "$CHUNK" \
    --num-chunks "$NUM_CHUNKS" --streams "$streams" --iters "$ITERS" \
    --warmup "$WARMUP" --block-align "$BLOCK_ALIGN" "${pad_opt[@]}" --out-dir "$setdir" > "$OUTROOT/sets-s$streams.log" 2>&1 \
    || { echo "representation set failed for streams=$streams" >&2; exit 1; }
  for rep in bf16_kv k16_v8 v8_only; do
    intent="$setdir/$rep.intent.json"
    for replica in $(seq 1 "$REPEATS"); do
      run_cell "$rep" "$intent" "$CONTROL_SIZE" "$streams" "$replica" none
      for size in $SIZES; do
        run_cell "$rep" "$intent" "$size" "$streams" "$replica" "$KIND"
      done
    done
  done
done
echo "@@@ SWEEP_DONE" >> "$OUTROOT/cells.log"
