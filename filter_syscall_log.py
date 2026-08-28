#!/usr/bin/env python3
"""
filter_syscall_log.py — filter and correlate syscall entry/exit pairs.

Fix in this version:
  - Does NOT rewrite write/pwrite records across PIDs.
  - Deferred writes are keyed by (pid, fd), not just fd.
  - Look-ahead only accepts a future openat exit from the same pid returning
    the same fd. This preserves process/thread ownership for concurrent replay.

Why:
  Cross-PID write rewriting destroys the original worker ownership, which is
  exactly the signal needed by a process/thread-aware replayer to reproduce
  block-layer plugging, merge windows, and queued write size behavior.
"""

import argparse
import json
from collections import defaultdict, deque

EXIT_FD = 4294967295       # -1 cast to uint32
EXIT_SIZE = 1              # generic exit tracepoint size marker
DEFAULT_LOOKAHEAD = 250
OPENAT_NR = 257
CLOSE_NR = 3
WRITE_NRS = {1, 18}        # write, pwrite64


def rec_pid(r):
    """Return the stable process owner used by the existing trace format."""
    return r.get("pid", r.get("tgid", r.get("tid")))


def is_generic_exit(r):
    """Non-openat exit tracepoint records carrying no useful payload."""
    return (
        r.get("syscall_nr") != OPENAT_NR
        and (r.get("fd", 0) == -1 or r.get("fd", 0) == EXIT_FD)
        and r.get("size", 0) == EXIT_SIZE
    )


def is_openat_exit(r):
    """openat EXIT records have an empty filename field in this monitor format."""
    return r.get("syscall_nr") == OPENAT_NR and r.get("filename", "") == ""


def is_openat_entry(r):
    return r.get("syscall_nr") == OPENAT_NR and r.get("filename", "") != ""


def same_owner_openat_exit_for_fd(rec, owner_pid, cap_fd):
    return (
        is_openat_exit(rec)
        and rec_pid(rec) == owner_pid
        and rec.get("ret") == cap_fd
    )


def filter_log(input_file, output_file, target_process=None, target_pid=None,
               lookahead=DEFAULT_LOOKAHEAD):
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Process / PID filters.
    if target_process:
        process_set = set(target_process)
        data = [r for r in data if r.get("process_name") in process_set]
    if target_pid is not None:
        data = [r for r in data if rec_pid(r) == target_pid]

    print(f"[filter] records after process/pid filter: {len(data)}")

    # Pass 1: collect openat exit return values in FIFO order per pid.
    openat_exit_queue = defaultdict(deque)
    for r in data:
        if is_openat_exit(r):
            pid = rec_pid(r)
            openat_exit_queue[pid].append(r.get("ret", -1))

    print("[filter] openat exit records found:   "
          f"{sum(len(q) for q in openat_exit_queue.values())}")

    kept = []
    skipped_exit = 0
    skipped_openat_exit = 0
    openat_patched = 0

    # pid_registered[pid] = set of capture fds currently open for that pid.
    pid_registered = defaultdict(set)

    # IMPORTANT: key by (pid, fd). Never key only by fd and never flush a
    # write into another pid's fd namespace.
    deferred_writes = defaultdict(list)
    deferred_count = 0
    flushed_count = 0
    emitted_unregistered = 0

    for idx, r in enumerate(data):
        nr = r.get("syscall_nr")
        pid = rec_pid(r)

        # Drop openat exit records after their ret values have been used.
        if is_openat_exit(r):
            skipped_openat_exit += 1
            continue

        # Drop generic syscall exit records.
        if is_generic_exit(r):
            skipped_exit += 1
            continue

        # Patch openat entry with the matching openat exit return fd.
        if is_openat_entry(r):
            queue = openat_exit_queue.get(pid)
            if queue:
                exit_ret = queue.popleft()
                if exit_ret is not None and exit_ret >= 0:
                    r = dict(r)
                    r["ret"] = exit_ret
                    openat_patched += 1

            cap_fd = r.get("ret", -1)
            if cap_fd is not None and cap_fd >= 0:
                pid_registered[pid].add(cap_fd)

            kept.append(r)

            # Flush only writes from the same pid/fd namespace.
            key = (pid, cap_fd)
            pending = deferred_writes.pop(key, [])
            for dw in pending:
                dw.pop("_deferred_reason", None)
                kept.append(dw)
                flushed_count += 1
            continue

        # close entry: fd is no longer valid for this pid. This lets a later
        # recycled fd trigger the same-pid look-ahead path.
        if nr == CLOSE_NR:
            cap_fd = r.get("fd", -1)
            if cap_fd not in (-1, EXIT_FD):
                pid_registered[pid].discard(cap_fd)
            kept.append(r)
            continue

        # write / pwrite64 entry.
        if nr in WRITE_NRS:
            cap_fd = r.get("fd", -1)

            if cap_fd not in pid_registered[pid]:
                # Same-pid look-ahead only. This handles per-CPU ring-buffer
                # reordering without corrupting inter-process concurrency.
                window = data[idx + 1: idx + 1 + lookahead]
                has_same_pid_openat = any(
                    same_owner_openat_exit_for_fd(rec, pid, cap_fd)
                    for rec in window
                )

                if has_same_pid_openat:
                    dw = dict(r)
                    dw["_deferred_reason"] = "same-pid-openat-exit-lookahead"
                    deferred_writes[(pid, cap_fd)].append(dw)
                    deferred_count += 1
                    continue

                # Pre-capture fd or genuinely missing openat. Emit unchanged;
                # the replayer can skip it if no fd_map entry exists.
                emitted_unregistered += 1

            kept.append(r)
            continue

        kept.append(r)

    # Do not drop deferred writes that never found an openat. Emit unchanged at
    # the end so the failure mode is visible in replay logs instead of hidden.
    late_deferred = 0
    for key in sorted(deferred_writes):
        pending = deferred_writes[key]
        late_deferred += len(pending)
        for dw in pending:
            dw.pop("_deferred_reason", None)
            kept.append(dw)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(kept, f, indent=2)

    print(f"[filter] total input              : {len(data)}")
    print(f"[filter] kept                     : {len(kept)}")
    print(f"[filter] generic exits dropped    : {skipped_exit}")
    print(f"[filter] openat exits dropped     : {skipped_openat_exit}")
    print(f"[filter] openat entries patched   : {openat_patched}")
    print(f"[filter] writes deferred same-pid : {deferred_count}")
    print(f"[filter] writes flushed same-pid  : {flushed_count}")
    print(f"[filter] writes emitted unreg fd  : {emitted_unregistered}")
    print(f"[filter] late deferred emitted    : {late_deferred}")
    print(f"[filter] lookahead records        : {lookahead}")
    if target_process:
        print(f"[filter] process filter           : {', '.join(target_process)}")
    if target_pid is not None:
        print(f"[filter] pid filter               : {target_pid}")


def main():
    parser = argparse.ArgumentParser(
        description="Filter eBPF syscall JSON while preserving process ownership."
    )
    parser.add_argument("input", help="Raw syscall JSON from eBPF monitor")
    parser.add_argument("output", help="Filtered JSON for syscall_replayer")
    parser.add_argument(
        "--process", "-p", nargs="+",
        help="Filter by process name(s), e.g. --process python3 VLLM::Worker_TP"
    )
    parser.add_argument("--pid", type=int, help="Filter by one pid/tgid")
    parser.add_argument(
        "--lookahead", type=int, default=DEFAULT_LOOKAHEAD,
        help=f"Same-pid openat-exit lookahead window; default {DEFAULT_LOOKAHEAD}"
    )
    args = parser.parse_args()
    filter_log(args.input, args.output, args.process, args.pid, args.lookahead)


if __name__ == "__main__":
    main()
