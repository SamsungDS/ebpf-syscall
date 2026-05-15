#!/usr/bin/env python3
"""
filter_syscall_log.py — filter and correlate syscall entry/exit pairs.

Patches openat entry/exit pairs:
  - openat (nr=257): sets entry ret = exit ret (the real fd number assigned
                     by the kernel). Write/pwrite64 exit records are dropped
                     as noise — the replayer treats ret=-1 on write as
                     "attempt and mark OK regardless of byte count".

Cross-pid / close-before-write look-ahead fix:
  The eBPF per-CPU ring-buffer causes two ordering problems:

  1. SAME-PID close-before-write:
     open(fd=283) → write(fd=283) → close(fd=283) → open(fd=283) → ...
     The eBPF log may show: close → open(exit delayed) → write → open(entry)
     The replayer processes close first → removes fd_map entry → write SKIP.
     Fix: track closes in pid_registered so the recycled fd looks
     unregistered, then use look-ahead to detect the upcoming openat.

  2. CROSS-PID write-before-openat:
     pid=X writes fd=283 before pid=Y's openat(ret=283) is flushed.
     Fix: same look-ahead mechanism — defer the write, flush after openat.

  Algorithm:
   - pid_registered tracks which fds are currently open per pid.
   - On close(fd), pid_registered removes fd immediately.
   - On write(fd) with fd absent from pid_registered: scan the next
     LOOKAHEAD raw records for an openat EXIT returning fd (any pid).
     If found → defer the write (keyed on cap_fd).
     If not found → emit as-is (pre-capture fd, will SKIP in replayer).
   - On openat(ret=fd) processed: flush all deferred writes for fd,
     rewriting their pid to match the openat's pid.
"""
import json
import argparse
from collections import defaultdict, deque


EXIT_FD   = 4294967295   # -1 cast to uint32 — fd field of all exit records
EXIT_SIZE = 1            # size field of all exit records
LOOKAHEAD = 250           # records to scan ahead for an upcoming openat exit


def _is_generic_exit(r):
    """Non-openat exit tracepoint records carrying no useful payload."""
    return (
        r['syscall_nr'] != 257
        and (r.get('fd', 0) == -1 or r.get('fd', 0) == EXIT_FD)
        and r.get('size', 0) == EXIT_SIZE
    )


def _is_openat_exit(r):
    """openat EXIT records have an empty filename field."""
    return r['syscall_nr'] == 257 and r.get('filename', '') == ''


def filter_log(input_file, output_file, target_process=None, target_pid=None):
    with open(input_file) as f:
        data = json.load(f)

    # ── process / pid filter ─────────────────────────────────────────────
    if target_process:
        process_set = (
            set(target_process)
            if isinstance(target_process, (list, set))
            else {target_process}
        )
        data = [r for r in data if r.get('process_name') in process_set]
    if target_pid:
        data = [r for r in data if r.get('pid') == target_pid]

    print(f"[filter] records after process filter: {len(data)}")

    # ── pass 1: build per-pid openat exit queues (FIFO order per pid) ──────
    openat_exit_queue = defaultdict(deque)

    for r in data:
        pid = r['pid']
        if _is_openat_exit(r):
            openat_exit_queue[pid].append(r.get('ret', -1))

    print(f"[filter] openat exit records found:   "
          f"{sum(len(q) for q in openat_exit_queue.values())}")

    # ── pass 2: build output ──────────────────────────────────────────────
    kept                 = []
    skipped_exit         = 0
    skipped_openat_exit  = 0
    openat_patched       = 0

    # pid_registered[pid] = set of cap_fds currently open for this pid.
    # Updated on openat (add) AND close (remove) so fd recycling is tracked.
    pid_registered = defaultdict(set)

    # deferred_writes[cap_fd] = write records waiting for the openat of
    # cap_fd to appear. Keyed only on cap_fd (any pid) so cross-pid writes
    # are flushed when any pid opens that fd number.
    deferred_writes = defaultdict(list)
    deferred_count  = 0   # total records deferred
    flushed_count   = 0   # total records flushed after openat arrived
    dropped_count   = 0   # total records dropped (openat never arrived)

    for idx, r in enumerate(data):
        nr  = r['syscall_nr']
        pid = r['pid']

        # ── drop openat exit records ──────────────────────────────────────
        if _is_openat_exit(r):
            skipped_openat_exit += 1
            continue

        # ── drop all other generic exit tracepoint records ────────────────
        if _is_generic_exit(r):
            skipped_exit += 1
            continue

        # ── patch openat entry ────────────────────────────────────────────
        if nr == 257 and r.get('filename', '') != '':
            queue = openat_exit_queue.get(pid)
            if queue:
                exit_ret = queue.popleft()
                if exit_ret >= 0:
                    r = dict(r)
                    r['ret'] = exit_ret
                    openat_patched += 1
                    print(f"[filter] openat   pid={pid} "
                          f"'{r['filename']}' ret=-1 → ret={exit_ret}")

            cap_fd = r.get('ret', -1)
            if cap_fd >= 0:
                pid_registered[pid].add(cap_fd)   # mark fd as open

            kept.append(r)

            # ── flush deferred writes for this cap_fd ─────────────────────
            # Writes that arrived before this openat (same-pid close-before-
            # write, or cross-pid ring-buffer reordering) are emitted now,
            # immediately after the openat, with pid patched to this pid so
            # the replayer fd_map lookup finds the replay_fd just registered.
            if cap_fd in deferred_writes:
                pending = deferred_writes.pop(cap_fd)
                for dw in pending:
                    pw = dict(dw)
                    orig_pid = pw.pop('_orig_pid')   # remove internal marker
                    pw['pid'] = pid                   # patch to openat owner
                    kept.append(pw)
                    flushed_count += 1
                    print(f"[filter] deferred write flushed: "
                          f"pid {orig_pid}→{pid}  cap_fd={cap_fd}")
            continue

        # ── close entry — update pid_registered ──────────────────────────
        # Removing the fd on close means the NEXT write on this recycled
        # fd number (for a new file in the next KV cycle) will correctly
        # look unregistered and trigger the look-ahead defer path.
        if nr == 3:
            cap_fd = r.get('fd', -1)
            if cap_fd not in (EXIT_FD, -1):         # skip close exit records
                pid_registered[pid].discard(cap_fd)  # mark fd as closed
            kept.append(r)
            continue

        # ── write / pwrite64 entry — look-ahead defer or emit ────────────
        # Defer the write ONLY if:
        #   (a) fd is not currently registered for this pid (newly opened
        #       fd whose openat hasn't arrived yet), AND
        #   (b) an openat EXIT record returning this fd is visible within
        #       the next LOOKAHEAD raw records (any pid).
        #
        # Condition (b) prevents pre-capture fds (fd=2, fd=247, fd=250,
        # fd=292 etc.) from being deferred into the buffer and dropped —
        # those fds never have an openat and should go straight to the
        # replayer where they become expected SKIP-FDMAP entries.
        if nr in (1, 18):
            cap_fd = r['fd']
            if cap_fd not in pid_registered[pid]:
                # look-ahead: is there an openat exit returning cap_fd soon?
                window = data[idx + 1: idx + 1 + LOOKAHEAD]
                has_upcoming_openat = any(
                    rec['syscall_nr'] == 257
                    and rec.get('filename', '') == ''   # openat exit record
                    and rec.get('ret') == cap_fd
                    for rec in window
                )
                if has_upcoming_openat:
                    r = dict(r)
                    r['_orig_pid'] = pid
                    deferred_writes[cap_fd].append(r)
                    deferred_count += 1
                    continue
            kept.append(r)
            continue

        kept.append(r)

    # ── report deferred writes whose openat never arrived ────────────────
    for cap_fd, pending in deferred_writes.items():
        dropped_count += len(pending)
        pids = sorted({dw.get('_orig_pid', '?') for dw in pending})
        print(f"[filter] deferred write DROPPED (openat never arrived): "
              f"cap_fd={cap_fd}  count={len(pending)}  pids={pids}")

    with open(output_file, 'w') as f:
        json.dump(kept, f, indent=2)

    # ── summary ───────────────────────────────────────────────────────────
    print(f"[filter] total input      : {len(data)}")
    print(f"[filter] kept             : {len(kept)}")
    print(f"[filter] exit records     : {skipped_exit}")
    print(f"[filter] openat exits     : {skipped_openat_exit}")
    print(f"[filter] openat patched   : {openat_patched}")
    print(f"[filter] writes deferred  : {deferred_count}  "
          f"(cross-pid look-ahead)")
    print(f"[filter] writes flushed   : {flushed_count}  "
          f"(openat arrived, pid patched)")
    print(f"[filter] writes dropped   : {dropped_count}  "
          f"(openat never arrived, pre-capture)")
    if target_process:
        procs = (
            ', '.join(sorted(target_process))
            if isinstance(target_process, (list, set))
            else target_process
        )
        print(f"[filter] process filter   : {procs}")
    if target_pid:
        print(f"[filter] pid filter       : {target_pid}")


def main():
    parser = argparse.ArgumentParser(
        description="Filter eBPF syscall log and patch entry/exit pairs."
    )
    parser.add_argument("input",  help="Raw syscall JSON from eBPF monitor")
    parser.add_argument("output", help="Filtered JSON for syscall_replayer")
    parser.add_argument(
        "--process", "-p",
        nargs="+",
        help="Filter by process name(s), e.g. --process minio python3"
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="Filter by a single PID"
    )
    args = parser.parse_args()
    filter_log(args.input, args.output, args.process, args.pid)


if __name__ == "__main__":
    main()