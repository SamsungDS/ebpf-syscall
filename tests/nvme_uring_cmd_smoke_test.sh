#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

cc_bin=${CC:-cc}
cflags="-std=gnu11 -O2 -g -Wall -Wextra -Werror"
tool="$tmp_dir/nvme_uring_cmd_smoke"
unit="$tmp_dir/nvme_uring_cmd_smoke_unit"

# Deliberately build outside the repository: a user-owned untracked binary may
# already exist at the normal Makefile target path.
# shellcheck disable=SC2086
$cc_bin $cflags "$repo_dir/nvme_uring_cmd_smoke.c" -luring -o "$tool"
# shellcheck disable=SC2086
$cc_bin $cflags "$script_dir/nvme_uring_cmd_smoke_unit.c" -luring -o "$unit"

"$unit"
"$unit" --emit-json >"$tmp_dir/result.json"
python3 -c '
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["schema"] == "nvme_uring_cmd_smoke/v1"
assert record["status"] == "ok"
assert record["device"] == "test-\"device"
assert record["successful_commands"] == 1
assert record["cmds_per_obj"] == 1
assert record["premap_requested"] is False
assert "premapped" not in record
assert record["dma_mapping_intent"] == "per-command"
assert record["slot_validation"]["passed"] is True
assert record["slot_validation"]["scheduler"] == "fifo-free-slot"
assert record["barrier"]["enabled"] is False
assert record["barrier"]["complete"] is True
assert record["ring_counters"]["passed"] is True
assert record["backing_proof"]["smaps"]["vmflag_nh"] is True
' "$tmp_dir/result.json"
"$tool" --help >"$tmp_dir/help"
grep -q -- "--fixed" "$tmp_dir/help"
grep -q -- "--slots S" "$tmp_dir/help"
grep -q -- "--buffer-len B" "$tmp_dir/help"
grep -q -- "ready-S-done-F-v1\|ready.*done" "$tmp_dir/help"

expect_usage_failure()
{
	set +e
	"$tool" "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"
	actual_rc=$?
	set -e
	if [ "$actual_rc" -ne 2 ]; then
		echo "expected usage exit 2, got $actual_rc: $*" >&2
		return 1
	fi
	if [ -s "$tmp_dir/stdout" ]; then
		echo "usage failure polluted machine-readable stdout: $*" >&2
		return 1
	fi
}

expect_usage_failure --fixed --premap
expect_usage_failure --hugepage --premap
expect_usage_failure --qd 64 --slots 32
expect_usage_failure --len 131072 --buffer-len 4096
expect_usage_failure --len 4096 --lba-size 520
expect_usage_failure --buffer-len 512
expect_usage_failure --count 4194305
expect_usage_failure --ready-fd 3
expect_usage_failure --count 2 --cmds-per-obj 1 --trace-base 4294967295

echo "nvme_uring_cmd_smoke CLI tests: PASS"
