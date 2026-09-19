#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Parse a kv-offload-io sweep log (sweep.sh output) into one CSV row per run:
model, chunk_tok, mdts_bytes, obj_bytes, store_cmds, store_MBps, load_MBps,
store_failed, load_failed.

Each run block starts with a `@@@ RUN ...` line and carries the tool's
`per object: store N cmds / M B ... (max_xfer=K KiB/cmd ...)` geometry and its
`store:/load: p50 ... MB/s ... F/T failed` result lines. mdts_bytes is the size
the tool actually used (so `mdts=0`, auto, reports the resolved cap). Throughput
is blank (`x`) when the run failed, timed out, or reported any failed operation:
a failed store never reaches the device and a load of a key that never landed is
a no-op, so a partial run's numbers do not describe the device."""
import re
import sys

txt = open(sys.argv[1]).read()
print("model,chunk_tok,mdts_bytes,obj_bytes,store_cmds,store_MBps,load_MBps,"
      "store_failed,load_failed")
for b in txt.split("@@@ RUN ")[1:]:
    m = dict(re.findall(r'(\w+)=(\S+)', b.splitlines()[0]))
    obj = re.search(r'KV block = (\d+) B', b)
    po = re.search(r'per object: store (\d+) cmds .*max_xfer=(\d+) KiB/cmd', b)
    st = re.search(r'store: p50\s+[\d.]+ ms.*?\|\s+([\d.]+) MB/s.*?(\d+)/\d+ failed', b)
    ld = re.search(r'load : p50\s+[\d.]+ ms.*?\|\s+([\d.]+) MB/s.*?(\d+)/\d+ failed', b)
    sf = int(st.group(2)) if st else -1
    lf = int(ld.group(2)) if ld else -1
    failed = "@@@ FAIL" in b or sf != 0 or lf != 0
    print(f"{m.get('model', '').split('/')[-1]},{m.get('chunk', 0)},"
          f"{int(po.group(2)) * 1024 if po else m.get('mdts', 0)},"
          f"{obj.group(1) if obj else 0},{po.group(1) if po else 0},"
          f"{'x' if failed else st.group(1)},{'x' if failed else ld.group(1)},"
          f"{sf},{lf}")
