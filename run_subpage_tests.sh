#!/bin/bash
#
# run_subpage_tests.sh — Automated test runner for sub-page granularity capture
#
# Exercises subpage_validate (writer) + pagemon_viz mode 6/7 (observer)
# across all write patterns and granularity levels.
#
# Requirements: root (sudo), both binaries compiled in the same directory.
#
# Usage:
#   sudo ./run_subpage_tests.sh [output_dir]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/subpage_test_results}"
VALIDATE="${SCRIPT_DIR}/subpage_validate"
PAGEMON="${SCRIPT_DIR}/pagemon_viz"
READY_FILE="/mnt/drives/nvme0n1/.subpage_ready"
TEST_FILE="/mnt/drives/nvme0n1/subpage_test.dat"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root (sudo)${NC}"
        exit 1
    fi
}

check_binaries() {
    for bin in "$VALIDATE" "$PAGEMON"; do
        if [ ! -x "$bin" ]; then
            echo -e "${RED}ERROR: $bin not found or not executable${NC}"
            echo "Build with:"
            echo "  gcc -O0 -o subpage_validate subpage_validate.c"
            echo "  gcc -O2 -o pagemon_viz pagemon_viz.c -lm"
            exit 1
        fi
    done
}

wait_for_ready() {
    local timeout=10
    local elapsed=0
    while [ ! -f "$READY_FILE" ] && [ $elapsed -lt $timeout ]; do
        sleep 0.2
        elapsed=$((elapsed + 1))
    done
    if [ ! -f "$READY_FILE" ]; then
        echo -e "${RED}  TIMEOUT: ready file not created${NC}"
        return 1
    fi
    return 0
}

parse_ready() {
    # Extract PID and address from ready file
    VPID=$(grep 'pid=' "$READY_FILE" | cut -d= -f2)
    VADDR=$(grep 'addr=' "$READY_FILE" | cut -d= -f2 | sed 's/0x//')
    VADDR_END=$(printf '%x' $((16#$VADDR + 4096)))
    echo -e "${CYAN}  Writer PID: $VPID, Addr: 0x$VADDR–0x$VADDR_END${NC}"
}

cleanup_writer() {
    if [ -n "${WRITER_PID:-}" ] && kill -0 "$WRITER_PID" 2>/dev/null; then
        kill "$WRITER_PID" 2>/dev/null || true
        wait "$WRITER_PID" 2>/dev/null || true
    fi
    rm -f "$READY_FILE" "$TEST_FILE"
}

# ══════════════════════════════════════════════════════════════════════
# Test functions
# ══════════════════════════════════════════════════════════════════════

run_test() {
    local test_name="$1"
    local writer_mode="$2"
    local pagemon_mode="$3"
    local interval_ms="$4"
    local iterations="$5"
    local sub_block="$6"
    local out_file="${OUTPUT_DIR}/${test_name}.json"

    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  TEST: ${test_name}${NC}"
    echo -e "${YELLOW}  Writer mode: ${writer_mode}, Pagemon mode: ${pagemon_mode}${NC}"
    echo -e "${YELLOW}  Interval: ${interval_ms}ms, Iterations: ${iterations}, Sub-block: ${sub_block}${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Start writer in background
    rm -f "$READY_FILE"
    "$VALIDATE" "$writer_mode" "$TEST_FILE" > "${OUTPUT_DIR}/${test_name}_writer.log" 2>&1 &
    WRITER_PID=$!

    # Wait for writer to signal readiness
    if ! wait_for_ready; then
        echo -e "${RED}  FAIL: writer did not start${NC}"
        cleanup_writer
        return 1
    fi
    parse_ready

    # Run pagemon_viz
    echo -e "${CYAN}  Running: pagemon_viz $VPID $pagemon_mode 0x$VADDR 0x$VADDR_END $interval_ms $iterations $sub_block${NC}"

    "$PAGEMON" "$VPID" "$pagemon_mode" "$VADDR" "$VADDR_END" \
        "$interval_ms" "$iterations" "$sub_block" \
        > "$out_file" 2>"${OUTPUT_DIR}/${test_name}_stderr.log"

    local exit_code=$?

    # Wait for writer to finish
    wait "$WRITER_PID" 2>/dev/null || true
    WRITER_PID=""

    # Validate output
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}  FAIL: pagemon_viz exited with code $exit_code${NC}"
        cat "${OUTPUT_DIR}/${test_name}_stderr.log"
        return 1
    fi

    if [ ! -s "$out_file" ]; then
        echo -e "${RED}  FAIL: empty output${NC}"
        return 1
    fi

    # Check JSON validity
    if python3 -c "import json; json.load(open('$out_file'))" 2>/dev/null; then
        echo -e "${GREEN}  JSON: valid${NC}"
    else
        echo -e "${RED}  FAIL: invalid JSON${NC}"
        head -5 "$out_file"
        return 1
    fi

    # Extract key metrics
    if [ "$pagemon_mode" = "6" ]; then
        local total_bytes=$(python3 -c "
import json
d = json.load(open('$out_file'))
snaps = d.get('snapshots', [])
total = sum(s.get('total_changed_bytes', 0) for s in snaps)
pages = sum(s.get('total_changed_pages', 0) for s in snaps)
print(f'Changed: {total} bytes across {pages} dirty-page captures')
# Overhead
overheads = [s.get('overhead', {}) for s in snaps if 'overhead' in s]
if overheads:
    avg_wall = sum(o.get('wall_ms', 0) for o in overheads) / len(overheads)
    avg_cpu  = sum(o.get('cpu_pct', 0) for o in overheads) / len(overheads)
    peak_rss = max(o.get('peak_rss_kb', 0) for o in overheads)
    avg_read = sum(o.get('bytes_read', 0) for o in overheads) / len(overheads)
    print(f'Overhead: wall={avg_wall:.1f}ms cpu={avg_cpu:.1f}% rss={peak_rss}KB read={avg_read:.0f}B/iter')
" 2>/dev/null)
        echo -e "${GREEN}  $total_bytes${NC}"
    fi

    if [ "$pagemon_mode" = "7" ]; then
        python3 -c "
import json
d = json.load(open('$out_file'))
for b in d.get('benchmarks', []):
    label = b.get('label', '?')
    wall  = b.get('wall_ms', 0)
    cpu   = b.get('cpu_pct', 0)
    rss   = b.get('peak_rss_kb', 0)
    bread = b.get('bytes_read', 0)
    print(f'  {label:25s}  wall={wall:8.2f}ms  cpu={cpu:5.1f}%  rss={rss:6d}KB  read={bread:8d}B')
" 2>/dev/null
    fi

    echo -e "${GREEN}  PASS → $out_file${NC}"
    return 0
}

# ══════════════════════════════════════════════════════════════════════
# Main test matrix
# ══════════════════════════════════════════════════════════════════════

main() {
    check_root
    check_binaries

    mkdir -p "$OUTPUT_DIR"
    echo -e "${CYAN}Output directory: $OUTPUT_DIR${NC}"
    echo ""

    local pass=0
    local fail=0
    local total=0

    # ── Test 1: Sequential writes, byte-level diff (1 byte granularity) ──
    total=$((total + 1))
    if run_test "01_sequential_byte" 0 6 100 40 1; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 2: Sequential writes, 8-byte (word) granularity ──
    total=$((total + 1))
    if run_test "02_sequential_word8" 0 6 100 40 8; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 3: Sequential writes, 64-byte (cache-line) granularity ──
    total=$((total + 1))
    if run_test "03_sequential_cacheline" 0 6 100 40 64; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 4: Strided writes (1 byte per cache line) ──
    total=$((total + 1))
    if run_test "04_strided_byte" 1 6 80 30 1; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 5: Sparse writes (4 known offsets) ──
    total=$((total + 1))
    if run_test "05_sparse_byte" 2 6 150 15 1; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 6: Burst write (256 bytes at offset 1024) ──
    total=$((total + 1))
    if run_test "06_burst_byte" 3 6 200 8 1; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 7: Burst write at 8-byte granularity ──
    total=$((total + 1))
    if run_test "07_burst_word8" 3 6 200 8 8; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 8: Page-level pagemap baseline (mode 1, soft-dirty) ──
    total=$((total + 1))
    if run_test "08_pagemap_softdirty" 0 1 100 20 0; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 9: Overhead benchmark (mode 7) ──
    total=$((total + 1))
    if run_test "09_overhead_bench" 0 7 200 5 0; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ── Test 10: Sequential at 256-byte sub-blocks ──
    total=$((total + 1))
    if run_test "10_sequential_256B" 0 6 100 30 256; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    # ══════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  TEST RESULTS: $pass/$total passed, $fail failed${NC}"
    echo -e "${CYAN}  Output: $OUTPUT_DIR/${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

    # Generate summary report
    echo ""
    echo "Generating overhead comparison report..."
    python3 -c "
import json, os, glob

out_dir = '$OUTPUT_DIR'
print()
print('┌─────────────────────────────────────────────────────────────────┐')
print('│               SUB-PAGE GRANULARITY TEST REPORT                 │')
print('├─────────────────────────────────────────────────────────────────┤')

# Mode 6 results
print('│                                                                 │')
print('│  Sub-Page Diff Results (mode 6):                                │')
print('│  Test                       Bytes  Pages  Avg Wall  Avg CPU%    │')
print('│  ─────────────────────────────────────────────────────────────  │')

for f in sorted(glob.glob(os.path.join(out_dir, '*.json'))):
    name = os.path.basename(f).replace('.json', '')
    try:
        d = json.load(open(f))
    except:
        continue
    mode = d.get('mode', '')
    if mode == 'sub_page_diff':
        snaps = d.get('snapshots', [])
        total_bytes = sum(s.get('total_changed_bytes', 0) for s in snaps)
        total_pages = sum(s.get('total_changed_pages', 0) for s in snaps)
        overheads = [s['overhead'] for s in snaps if 'overhead' in s]
        avg_wall = sum(o.get('wall_ms', 0) for o in overheads) / max(1, len(overheads))
        avg_cpu  = sum(o.get('cpu_pct', 0) for o in overheads) / max(1, len(overheads))
        print(f'│  {name:26s} {total_bytes:6d} {total_pages:6d} {avg_wall:8.1f}ms {avg_cpu:6.1f}%    │')

# Mode 7 overhead comparison
for f in sorted(glob.glob(os.path.join(out_dir, '*.json'))):
    try:
        d = json.load(open(f))
    except:
        continue
    if d.get('mode') == 'overhead_bench':
        print('│                                                                 │')
        print('│  Overhead Comparison (mode 7):                                  │')
        print('│  Method                  Wall ms    CPU%     RSS KB   Read B     │')
        print('│  ─────────────────────────────────────────────────────────────  │')
        for b in d.get('benchmarks', []):
            label = b.get('label', '?')
            wall  = b.get('wall_ms', 0)
            cpu   = b.get('cpu_pct', 0)
            rss   = b.get('peak_rss_kb', 0)
            bread = b.get('bytes_read', 0)
            print(f'│  {label:24s} {wall:8.2f} {cpu:7.1f}  {rss:8d} {bread:8d}     │')

print('│                                                                 │')
print('└─────────────────────────────────────────────────────────────────┘')
" 2>/dev/null || echo "(python3 report generation skipped)"

    echo ""
    echo "Individual JSON results in: $OUTPUT_DIR/"
    ls -la "$OUTPUT_DIR"/*.json 2>/dev/null || true

    cleanup_writer
    return $fail
}

trap cleanup_writer EXIT
main "$@"
