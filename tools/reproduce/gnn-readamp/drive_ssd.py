#!/usr/bin/env python3
# Drive ONE force-SSD access pattern. Emit CLOCK_MONOTONIC phase + progress
# markers so an external nvme tracer (bpf_ktime_get_ns == CLOCK_MONOTONIC) can
# be joined to the intent: PROGRESS carries cumulative signal_bytes (the useful
# feature bytes the GNN actually needs) and the store-side bytes/pages read.
import sys, os, time, numpy as np
sys.path.insert(0, "gnn"); sys.path.insert(0, "gnn/scripts")
import benchmark_ssd as B
from ssd_feature_store import SSDFeatureReader, write_feature_file, PAGE_SIZE

access = sys.argv[1]; layout = sys.argv[2]; tlimit = float(sys.argv[3])
from datasets import load_dataset
data = load_dataset("dgraphfin", ".")
x = data.x.numpy(); edge_index = data.edge_index.numpy(); train_mask = data.train_mask.numpy()
num_nodes, f = x.shape
nodes_per_page = max(1, PAGE_SIZE // (f * 4))
indptr, indices = B.build_csr(edge_index, num_nodes)
train_idx = np.where(train_mask)[0]
node_order, page_id = B.build_layout(layout, edge_index, num_nodes, nodes_per_page, 0)
groups = B.page_node_groups(page_id)
os.makedirs("./gnn_ssd_store", exist_ok=True)
path = os.path.join("./gnn_ssd_store", layout + ".bin")
meta = write_feature_file(x, node_order, path)
reader = SSDFeatureReader(path, node_order, meta, direct=True, evict=False)
it = (B.neighbor_batches(train_idx, indptr, indices, 1024, [10, 5], 0) if access == "neighbor"
      else B.page_batches(groups, page_id, train_mask, 32, 0))
print("PHASE_START access=%s layout=%s nodes_per_page=%d feat_bytes=%d mono_ns=%d"
      % (access, layout, nodes_per_page, f*4, int(time.monotonic()*1e9)), flush=True)
reader.reset_stats()
signal_bytes = 0; t0 = time.time(); n = 0
for nodes, num_signal in it:
    reader.read_nodes(nodes)
    signal_bytes += int(num_signal) * reader.FB
    n += 1
    # One marker per batch: the intent curve the eBPF device capture joins to.
    print("PROGRESS mono_ns=%d signal_bytes=%d store_bytes=%d store_pages=%d batch=%d"
          % (int(time.monotonic()*1e9), signal_bytes, reader.bytes_read,
             reader.pages_read, n), flush=True)
    if time.time() - t0 > tlimit:
        break
st = reader.stats()
# ra_signal = device bytes / useful feature bytes (vs what the GNN consumes)
# ra_fetch  = device bytes / minimal pages needed (the store's own RA_physical)
ra_signal = reader.bytes_read / signal_bytes if signal_bytes else 0
print("PHASE_END mono_ns=%d ra_signal=%.3f ra_fetch=%.3f signal_bytes=%d "
      "store_bytes=%d store_pages=%d read_ops=%d"
      % (int(time.monotonic()*1e9), ra_signal, st["ra_physical"],
         signal_bytes, reader.bytes_read, reader.pages_read, st["read_ops"]), flush=True)
reader.close()
