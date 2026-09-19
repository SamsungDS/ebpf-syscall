#!/bin/bash
# Sweep KV-offload object size x per-command size on one NVMe namespace.
#
# Every run's exit status is recorded. The tool exits 2 when any store or load
# failed and parse.py blanks those rows, so a command size the kernel cannot map
# shows up as a failed run -- never as a throughput number.
#
#   DEV=/dev/ng1n1 bash sweep.sh                     # an EMPTY spare namespace
#   HUGEPAGE=1 MDTS="0 2097152 4194304" bash sweep.sh  # THP buffers, custom sizes
#
# MDTS=0 resolves the kernel's cap for 4 KiB-page buffers, min(max_hw_sectors_kb,
# max_segments*page). Sizes above it need HUGEPAGE=1 and are still bounded by
# max_hw_sectors_kb; the tool warns up front when a size cannot be mapped.
set -u
KVIO=${KVIO:-$(cd "$(dirname "$0")/../../kvio" && pwd)}
PYTHON=${PYTHON:-python3}
DEV=${DEV:-/dev/ng1n1}
OUT=${OUT:-$PWD/kvio_sweep.txt}
MODELS=${MODELS:-"meta-llama/Llama-3.2-1B-Instruct meta-llama/Llama-3.1-8B-Instruct meta-llama/Llama-3.1-70B-Instruct meta-llama/Llama-3.1-405B deepseek-ai/DeepSeek-V3"}
CHUNKS=${CHUNKS:-"16 64 256 512"}
MDTS=${MDTS:-"131072 0"}
EXTRA=${HUGEPAGE:+--hugepage}
PP=$KVIO/build:$KVIO/vendor/lmcache${PYTHONPATH:+:$PYTHONPATH}
: > "$OUT"
for M in $MODELS; do for C in $CHUNKS; do for X in $MDTS; do
  echo "@@@ RUN model=$M chunk=$C mdts=$X dtype=bfloat16 hugepage=${HUGEPAGE:-0}" >> "$OUT"
  timeout 300 sudo -E env PYTHONPATH="$PP" "$PYTHON" "$KVIO/run_kv_offload_io.py" \
    --model "$M" --dtype bfloat16 --chunk-tokens "$C" --num-chunks 4 \
    --device "$DEV" --engine uring_cmd --mdts-bytes "$X" $EXTRA >> "$OUT" 2>&1
  rc=$?
  [ $rc -eq 0 ] || echo "@@@ FAIL model=$M chunk=$C mdts=$X rc=$rc" >> "$OUT"
done; done; done
echo "@@@ SWEEP_DONE" >> "$OUT"
