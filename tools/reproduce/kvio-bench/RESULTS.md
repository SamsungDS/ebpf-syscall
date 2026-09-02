# Latitude bare-metal smoke — 2026-09-02

This is a functional smoke of the kvspill integration, not a storage comparison
campaign. It used one repetition and short five-second measurement windows to
exercise every command path before commit.

## Platform gate

- Latitude server: `sv_gXQvNenz35zpb` (deleted after the run; GET verified 404)
- plan/site: `m4-metal-medium`, ASH
- kernel: Ubuntu `7.0.0-30-generic`
- target: `/dev/nvme2n1`, Samsung PM9A3 `MZQL21T9HCJR-00A07`
- serial/firmware: `S64GNJ0WA01201`, `GDC5A02Q`
- namespace state before testing: `nuse=0`, no partition, signature, mount, or
  holder; the Micron `nvme0n1`/`nvme1n1` RAID1 OS pair was not used
- target geometry: 512-byte logical, 4096-byte physical, `mdts=9` (2 MiB
  controller MDTS), kernel `max_hw_sectors_kb=128`
- fio: 3.36

Before using the PM9A3, the destructive command was aimed at the OS disk as a
negative test. kvio refused it at `nvme0n1p1` and created no output directory.

## All-profile smoke

```sh
sudo ./kvio bench /dev/nvme2n1 \
    --yes-really-use-device --size 4GiB \
    --runtime 5 --ramp-time 1 --reps 1 \
    --output-dir /tmp/kvio-all
```

| case/result | bandwidth | p50 | p99 |
|---|---:|---:|---:|
| restore, 2 MiB × 16 jobs × QD2 | 6373.5 MiB/s | 7.832 ms | 23.724 ms |
| calibrated restore, 7,340,032 B × 4 × QD1 | 6469.7 MiB/s | 4.293 ms | 4.882 ms |
| prefix, 1 MiB × 8 × QD4 | 6448.8 MiB/s | 4.882 ms | 6.783 ms |
| synthetic QoS bulk, four-job sum | 6341.5 MiB/s | — | — |
| synthetic QoS 4 KiB reader, median of two jobs | 14.2 MiB/s | 4.358 ms | 4.948 ms |
| evict write, 2 MiB × 4 × QD8 | 2679.9 MiB/s | 23.986 ms | 25.035 ms |

The run emitted all expected fio JSON, generated profiles, `results.jsonl`, and
RESULT lines. `max_sectors_kb` was 128 before and after; hugepages were 0 before
and after.

The QoS rows came from the built-in synthetic `qos-sustain-4k` shape. They
prove that the runner exercised both streams; they do not make that shape a
trace-backed serving workload.

## Calibrated override, tuning, and comparison smoke

```sh
sudo ./kvio bench /dev/nvme2n1 \
    --yes-really-use-device --cases restore-calibrated \
    --calibrated-block-size 32MiB --size 4GiB \
    --runtime 5 --ramp-time 1 --reps 1 --skip-precondition \
    --max-sectors-kb 64 --output-dir /tmp/kvio-32m

./kvio bench-compare /tmp/kvio-all/results.jsonl \
                     /tmp/kvio-32m/results.jsonl
```

The 32 MiB case reported 6479.1 MiB/s, 16.450 ms p50, and 26.870 ms p99.
`bench-compare` selected only the common calibrated case and printed all six
shared metrics. The temporary queue cap returned from 64 to 128 KiB and the
hugepage count returned to zero.

These measurements establish working execution, parsing, isolation, comparison,
and cleanup on real NVMe. The changed object size and queue cap are deliberately
confounded, so their deltas must not be used as an A/B performance conclusion.
