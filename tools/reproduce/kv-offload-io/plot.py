#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plot a parse.py CSV: KV load throughput vs per-command size for the 256-token
(LMCache chunk) object size per model, and commands per object vs per-command
size for Llama-3.1-8B across the object sizes.

    python3 plot.py results.csv mdts_effect.png

Rows whose throughput is `x` (failed runs) are skipped, so a size the kernel
could not map leaves a gap rather than a point."""
import csv
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

src, out = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(src)))
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
models = ['Llama-3.2-1B-Instruct', 'Llama-3.1-8B-Instruct', 'Llama-3.1-70B-Instruct',
          'Llama-3.1-405B', 'DeepSeek-V3']
col = {'Llama-3.2-1B-Instruct': '#8ecae6', 'Llama-3.1-8B-Instruct': '#219ebc',
       'Llama-3.1-70B-Instruct': '#023047', 'Llama-3.1-405B': '#fb8500',
       'DeepSeek-V3': '#c1121f'}
for mdl in models:
    pts = sorted([(int(r['mdts_bytes']), float(r['load_MBps']))
                  for r in rows if r['model'] == mdl and r['chunk_tok'] == '256'
                  and r['load_MBps'] != 'x'])
    if not pts:
        continue
    ax1.plot([p[0] / 1048576 for p in pts], [p[1] / 1000 for p in pts], 'o-',
             color=col[mdl], label=mdl.replace('-Instruct', ''), lw=2)
ax1.set_xscale('log', base=2)
ax1.set_xlabel('per-command size (MiB, log)')
ax1.set_ylabel('KV load throughput (GB/s)')
ax1.set_title('KV restore (load) vs per-command size — 256-tok chunk\n'
              '/dev/ng passthrough, QD1, failed runs omitted')
ax1.grid(alpha=.3)
ax1.legend(fontsize=8)
for c, mk in [('16', 's'), ('64', '^'), ('256', 'o'), ('512', 'D')]:
    pts = sorted([(int(r['mdts_bytes']), int(r['store_cmds'])) for r in rows
                  if r['model'] == 'Llama-3.1-8B-Instruct' and r['chunk_tok'] == c])
    ax2.plot([p[0] / 1048576 for p in pts], [p[1] for p in pts], mk + '-', lw=2,
             label=f'{c}-tok chunk')
ax2.set_xscale('log', base=2)
ax2.set_yscale('log')
ax2.set_xlabel('per-command size (MiB, log)')
ax2.set_ylabel('NVMe commands per KV object (log)')
ax2.set_title('Commands per object — Llama-3.1-8B\n'
              '(16=MAX block, 64=Strata page, 256/512=LMCache chunk)')
ax2.grid(alpha=.3, which='both')
ax2.legend(fontsize=8)
fig.tight_layout()
fig.savefig(out, dpi=130)
print(f"wrote {out}")
