#!/bin/bash
# Sweep KV-offload object size with the staging buffer mapped once as a dma-buf.
#
# The other sweep drives NVMe passthrough on a /dev/ng character device, where
# every command is mapped for DMA at submission and the size that reaches the
# drive is bounded by max_segments times the page size. This one drives the
# block device with io_uring instead and registers the staging buffer as a
# dma-buf, so the kernel maps it to the device once and each fixed read or
# write can be one command up to the device's dma-buf ceiling.
#
# Passthrough cannot import a dma-buf registration, which is why this is a
# separate script against a different device node rather than another arm of
# the same loop.
#
#   DEV=/dev/nvme1n1 bash sweep_dmabuf.sh              # an EMPTY spare namespace
#   KINDS="udmabuf system_heap" HUGEPAGE=1 bash sweep_dmabuf.sh
#
# Needs a kernel carrying io_uring dma-buf registered buffers and the dma-buf
# size ceiling. Without them the engine logs that the registration was refused
# and falls back to per-command mapping, which is the classic arm and is run
# here as KINDS=none for comparison.
#
# Read max_hw_dmabuf_sectors_kb for the ceiling this drive publishes:
#   cat /sys/block/$(basename "$DEV")/queue/max_hw_dmabuf_sectors_kb
set -u
KVIO=${KVIO:-$(cd "$(dirname "$0")/../../kvio" && pwd)}
PYTHON=${PYTHON:-python3}
DEV=${DEV:-/dev/nvme1n1}
OUT=${OUT:-$PWD/kvio_sweep_dmabuf.txt}
INTENT_DIR=${INTENT_DIR:-}
MODELS=${MODELS:-"meta-llama/Llama-3.1-8B-Instruct"}
CHUNKS=${CHUNKS:-"16 64 256"}
MDTS=${MDTS:-"131072 2097152 8388608"}
KINDS=${KINDS:-"none udmabuf system_heap"}
EXTRA=${HUGEPAGE:+--hugepage}
PP=$KVIO/build:$KVIO/vendor/lmcache${PYTHONPATH:+:$PYTHONPATH}
: > "$OUT"
if [ -n "$INTENT_DIR" ]; then
  mkdir -p "$INTENT_DIR" || exit 1
  # Intent is deliberately invariant across target MDTS and exporter. Emit one
  # artifact for each logical model/chunk workload, not misleading duplicates
  # labelled with a source arm's device properties.
  for M in $MODELS; do for C in $CHUNKS; do
    SAFE_MODEL=${M//\//_}
    INTENT_PATH="$INTENT_DIR/${SAFE_MODEL}-chunk${C}.intent.json"
    if ! env PYTHONPATH="$PP" "$PYTHON" "$KVIO/run_kv_offload_io.py" \
        --model "$M" --dtype bfloat16 --chunk-tokens "$C" --num-chunks 4 \
        --intent-out "$INTENT_PATH" --intent-only >> "$OUT" 2>&1; then
      echo "@@@ INTENT_FAIL model=$M chunk=$C" >> "$OUT"
      exit 1
    fi
    echo "@@@ INTENT model=$M chunk=$C path=$INTENT_PATH" >> "$OUT"
  done; done
fi
for M in $MODELS; do for C in $CHUNKS; do for X in $MDTS; do for K in $KINDS; do
  [ "$K" = none ] && DB= || DB="--dmabuf $K"
  echo "@@@ RUN model=$M chunk=$C mdts=$X dmabuf=$K hugepage=${HUGEPAGE:-0}" >> "$OUT"
  timeout 300 sudo -E env PYTHONPATH="$PP" "$PYTHON" "$KVIO/run_kv_offload_io.py" \
    --model "$M" --dtype bfloat16 --chunk-tokens "$C" --num-chunks 4 \
    --device "$DEV" --engine io_uring --mdts-bytes "$X" $DB $EXTRA >> "$OUT" 2>&1
  rc=$?
  [ $rc -eq 0 ] || echo "@@@ FAIL model=$M chunk=$C mdts=$X dmabuf=$K rc=$rc" >> "$OUT"
done; done; done; done
echo "@@@ SWEEP_DONE" >> "$OUT"
