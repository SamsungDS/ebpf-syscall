# Reproduce the kvio storage-tier benchmark

The benchmark profiles originate in Davidlohr Bueso's
[kvspill](https://github.com/davidlohr/kvspill) and are integrated with
permission. This recipe validates the launcher locally and runs the destructive
portion only on a separately verified disposable NVMe namespace.

## Offline gate

```sh
make kvio-test
./kvio doctor
./kvio bench --list-profiles
./kvio bench --help
```

## Bare-metal gate

Record `lsblk -o NAME,SIZE,MODEL,SERIAL,TYPE,FSTYPE,MOUNTPOINTS` and
`nvme list` first. Replace the example target only after proving it is not the
OS disk, is unmounted, has no holders or partitions, and is disposable.

```sh
sudo ./kvio bench /dev/nvmeXnY \
    --yes-really-use-device \
    --size 8GiB --runtime 10 --ramp-time 2 --reps 1 \
    --output-dir /tmp/kvio-bench-smoke
```

Expected artifacts are `gates.json`, `run.json`, the generated fio profiles,
raw fio JSON, `precondition.txt`, `results.jsonl`, and `results.log`. Confirm
after the run that the target's queue `max_sectors_kb` and
`/proc/sys/vm/nr_hugepages` equal their recorded pre-run values.

For a controlled A/B, run identical arguments before and after the one change
under test, then compare:

```sh
./kvio bench-compare baseline/results.jsonl candidate/results.jsonl
```

Do not interpret this closed-loop fio test as a serving-trace replay. See
`docs/kvspill.rst` for the fidelity boundary.

The built-in `qos-sustain-4k` case is a synthetic interference test, not a
captured LMCache workload. Use `--profile FILE` to load a sustained workload
derived from a new capture. The JSON must name the evidence kind and source;
the resolved profile is copied into `run.json` with the results.
