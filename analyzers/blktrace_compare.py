#!/usr/bin/env python3
"""
blktrace Capture vs Replay Comparison Tool
===========================================
Loads two blkparse text files (original capture + replay) and generates
side-by-side time-series charts to visualize fidelity of the replay.

Designed for validating eBPF syscall replayer or fio-based replay tools
against original block-layer traces.

Usage:
    python3 blktrace_compare.py capture.txt replay.txt
    python3 blktrace_compare.py capture.txt replay.txt --time-bucket 0.05
    python3 blktrace_compare.py capture.txt replay.txt --lbs 512 --iu-size 4096
    python3 blktrace_compare.py capture.txt replay.txt --output-dir ./compare_results

Charts generated:
    01_q_event_rate.png       Q event arrival rate overlay + residual
    02_io_size_comparison.png I/O size distributions side-by-side
    03_lba_heatmaps.png       LBA heatmaps + difference heatmap
    04_queue_depth.png        Queue depth overlay + residual
    05_throughput_iops.png    Throughput & IOPS overlay + residual
    06_latency_cdf.png        Latency CDF overlay (Q→C, D→C)
    07_cumulative_drift.png   Cumulative I/O count + bytes drift
    08_fidelity_dashboard.png Single-page fidelity summary

Fidelity metrics computed:
    - Pearson correlation (time-series similarity)
    - sMAPE (Symmetric Mean Absolute Percentage Error)
    - JSD (Jensen-Shannon Divergence for distributions)
    - KS statistic (Kolmogorov-Smirnov for CDF comparison)
    - Cumulative drift (divergence in total I/O count over time)

DETAILS
================
Timeline normalization: Both traces are rebased to t=0 (first event timestamp
subtracted). Comparison uses the SHORTER of the two durations as the common
time range. Events beyond the shorter trace's duration are included in the
longer trace's analysis but excluded from residual/difference calculations.

Bucket alignment: Both traces use identical time_bucket width and LBA bin
count so per-bucket metrics are directly comparable.

Q-event basis: Most comparisons use Q (queue) events because they represent
the application's original I/O requests — the "ground truth" that the replayer
should reproduce. D and C events are affected by scheduler merging and
completion timing which can differ between capture and replay environments.
"""

import sys
import os
import argparse
import warnings
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
from matplotlib.colors import LogNorm, SymLogNorm

warnings.filterwarnings("ignore", category=UserWarning)

# Import from the main analyzer
from blktrace_analyzer import (
    load_trace, BlktraceAnalyzer, SSDGeometry,
    SECTOR_SIZE, KB, MB, GB,
    ACTION_QUEUE, ACTION_ISSUE, ACTION_COMPLETE,
    COLORS, setup_ax,
)

# ─── Colors for capture vs replay ─────────────────────────────────────────────
C_CAP  = "#1565C0"   # dark blue for capture (original)
C_REP  = "#E65100"   # dark orange for replay
C_DIFF = "#7B1FA2"   # purple for difference/residual
C_BAND = "#E0E0E0"   # tolerance band

# ─── Fidelity Metrics ─────────────────────────────────────────────────────────

def pearson_r(a, b):
    """Pearson correlation coefficient between two arrays."""
    if len(a) < 2 or len(b) < 2:
        return 0.0
    n = min(len(a), len(b))
    a, b = a[:n], b[:n]
    if np.std(a) == 0 or np.std(b) == 0:
        return 1.0 if np.array_equal(a, b) else 0.0
    return float(np.corrcoef(a, b)[0, 1])


def smape(a, b):
    """Symmetric Mean Absolute Percentage Error (0=identical, 2=maximum)."""
    n = min(len(a), len(b))
    a, b = np.array(a[:n], dtype=float), np.array(b[:n], dtype=float)
    denom = np.abs(a) + np.abs(b)
    mask = denom > 0
    if not mask.any():
        return 0.0
    return float(np.mean(2.0 * np.abs(a[mask] - b[mask]) / denom[mask]))


def jsd(p, q, n_bins=100):
    """Jensen-Shannon Divergence between two sample arrays.

    Discretizes both into n_bins histogram bins over the shared range,
    then computes JSD. Range: 0 (identical) to ln(2) ≈ 0.693 (maximally different).
    """
    if len(p) == 0 or len(q) == 0:
        return 0.693  # maximum divergence
    lo = min(p.min(), q.min())
    hi = max(p.max(), q.max())
    if lo == hi:
        return 0.0
    bins = np.linspace(lo, hi, n_bins + 1)
    p_hist, _ = np.histogram(p, bins=bins, density=True)
    q_hist, _ = np.histogram(q, bins=bins, density=True)
    # Normalize to proper probability distributions
    p_hist = p_hist / (p_hist.sum() + 1e-12)
    q_hist = q_hist / (q_hist.sum() + 1e-12)
    m = 0.5 * (p_hist + q_hist)
    # KL divergence with epsilon for numerical stability
    eps = 1e-12
    kl_pm = np.sum(p_hist * np.log((p_hist + eps) / (m + eps)))
    kl_qm = np.sum(q_hist * np.log((q_hist + eps) / (m + eps)))
    return float(0.5 * kl_pm + 0.5 * kl_qm)


def ks_stat(a, b):
    """Kolmogorov-Smirnov statistic: max absolute CDF difference.

    Range: 0 (identical distributions) to 1 (completely non-overlapping).
    """
    if len(a) == 0 or len(b) == 0:
        return 1.0
    combined = np.sort(np.concatenate([a, b]))
    cdf_a = np.searchsorted(np.sort(a), combined, side='right') / len(a)
    cdf_b = np.searchsorted(np.sort(b), combined, side='right') / len(b)
    return float(np.max(np.abs(cdf_a - cdf_b)))


# ─── Per-bucket extraction helpers ────────────────────────────────────────────

def extract_q_event_rate(events, t0, duration, time_bucket):
    """Count Q events per time bucket, separately for reads and writes."""
    n = max(1, int(np.ceil(duration / time_bucket)))
    r_count = np.zeros(n)
    w_count = np.zeros(n)
    for ev in events:
        if ev.action != ACTION_QUEUE or ev.nblocks <= 0:
            continue
        idx = min(int((ev.timestamp - t0) / time_bucket), n - 1)
        if ev.is_read:
            r_count[idx] += 1
        elif ev.is_write:
            w_count[idx] += 1
    times = np.arange(n) * time_bucket
    return times, r_count / time_bucket, w_count / time_bucket  # events/sec


def extract_io_sizes(events):
    """Extract I/O sizes from Q events."""
    return np.array([e.size_bytes for e in events
                     if e.action == ACTION_QUEUE and e.nblocks > 0])


def extract_io_sizes_by_type(events):
    """Extract I/O sizes split by read/write from Q events."""
    r = [e.size_bytes for e in events if e.action == ACTION_QUEUE and e.nblocks > 0 and e.is_read]
    w = [e.size_bytes for e in events if e.action == ACTION_QUEUE and e.nblocks > 0 and e.is_write]
    return np.array(r), np.array(w)


def extract_cumulative_ios(events, t0, duration, time_bucket):
    """Cumulative Q-event count and bytes over time."""
    n = max(1, int(np.ceil(duration / time_bucket)))
    count = np.zeros(n)
    bytez = np.zeros(n)
    for ev in events:
        if ev.action != ACTION_QUEUE or ev.nblocks <= 0:
            continue
        idx = min(int((ev.timestamp - t0) / time_bucket), n - 1)
        count[idx] += 1
        bytez[idx] += ev.size_bytes
    times = np.arange(n) * time_bucket
    return times, np.cumsum(count), np.cumsum(bytez)


def extract_lba_heatmap(events, t0, duration, time_bucket, lba_bins, max_sector):
    """Build LBA heatmap from Q events using a shared max_sector for alignment."""
    n_time = max(1, min(200, int(duration / time_bucket)))
    hm = np.zeros((lba_bins, n_time))
    for ev in events:
        if ev.action != ACTION_QUEUE or ev.nblocks <= 0 or ev.sector <= 0:
            continue
        ti = min(int((ev.timestamp - t0) / duration * n_time), n_time - 1)
        si = min(int(ev.sector / (max_sector + 1) * lba_bins), lba_bins - 1)
        hm[si, ti] += 1
    return hm


def extract_rw_ratio_over_time(events, t0, duration, time_bucket):
    """Read/write ratio per time bucket from Q events."""
    n = max(1, int(np.ceil(duration / time_bucket)))
    rc = np.zeros(n)
    wc = np.zeros(n)
    for ev in events:
        if ev.action != ACTION_QUEUE or ev.nblocks <= 0:
            continue
        idx = min(int((ev.timestamp - t0) / time_bucket), n - 1)
        if ev.is_read:
            rc[idx] += 1
        elif ev.is_write:
            wc[idx] += 1
    with np.errstate(divide='ignore', invalid='ignore'):
        ratio = np.where((rc + wc) > 0, rc / (rc + wc), 0.5)
    return np.arange(n) * time_bucket, ratio


# ─── Chart Functions ──────────────────────────────────────────────────────────

def plot_q_event_rate(cap_events, rep_events, cap_t0, rep_t0,
                      common_dur, time_bucket, od):
    """Chart 01: Q event arrival rate overlay + residual."""
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(16, 12),
                                         height_ratios=[2, 2, 1])
    fig.suptitle("Q Event Rate: Capture vs Replay", fontsize=15, fontweight="bold")

    tc, rc_r, rc_w = extract_q_event_rate(cap_events, cap_t0, common_dur, time_bucket)
    tr, rr_r, rr_w = extract_q_event_rate(rep_events, rep_t0, common_dur, time_bucket)
    n = min(len(tc), len(tr))
    tc, rc_r, rc_w = tc[:n], rc_r[:n], rc_w[:n]
    tr, rr_r, rr_w = tr[:n], rr_r[:n], rr_w[:n]

    # Read rate overlay
    ax1.plot(tc, rc_r, color=C_CAP, linewidth=1, label="Capture reads", alpha=0.8)
    ax1.plot(tr, rr_r, color=C_REP, linewidth=1, label="Replay reads", alpha=0.8,
             linestyle="--")
    ax1.fill_between(tc, rc_r, rr_r, alpha=0.15, color=C_DIFF)
    corr_r = pearson_r(rc_r, rr_r)
    setup_ax(ax1, f"Read Q-Event Rate  (r={corr_r:.4f})", "", "Events/s")
    ax1.legend(fontsize=9)

    # Write rate overlay
    ax2.plot(tc, rc_w, color=C_CAP, linewidth=1, label="Capture writes", alpha=0.8)
    ax2.plot(tr, rr_w, color=C_REP, linewidth=1, label="Replay writes", alpha=0.8,
             linestyle="--")
    ax2.fill_between(tc, rc_w, rr_w, alpha=0.15, color=C_DIFF)
    corr_w = pearson_r(rc_w, rr_w)
    setup_ax(ax2, f"Write Q-Event Rate  (r={corr_w:.4f})", "", "Events/s")
    ax2.legend(fontsize=9)

    # Residual (capture - replay)
    total_c = rc_r + rc_w
    total_r = rr_r + rr_w
    residual = total_c - total_r
    ax3.bar(tc, residual, width=time_bucket * 0.9, color=C_DIFF, alpha=0.6)
    ax3.axhline(0, color="black", linewidth=0.5)
    smape_val = smape(total_c, total_r)
    setup_ax(ax3, f"Residual (capture − replay)  sMAPE={smape_val:.4f}",
             "Time (s)", "Δ Events/s")

    fig.tight_layout()
    fig.savefig(os.path.join(od, "01_q_event_rate.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 01_q_event_rate.png")
    return {'q_rate_corr_read': corr_r, 'q_rate_corr_write': corr_w,
            'q_rate_smape': smape_val}


def plot_io_size_comparison(cap_events, rep_events, od):
    """Chart 02: I/O size distribution comparison."""
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle("I/O Size Distribution: Capture vs Replay", fontsize=15, fontweight="bold")

    cap_r, cap_w = extract_io_sizes_by_type(cap_events)
    rep_r, rep_w = extract_io_sizes_by_type(rep_events)
    cap_all = extract_io_sizes(cap_events)
    rep_all = extract_io_sizes(rep_events)

    datasets = [
        (cap_all, rep_all, "All I/O"),
        (cap_r, rep_r, "Reads"),
        (cap_w, rep_w, "Writes"),
    ]

    metrics = {}
    for col, (cap_d, rep_d, label) in enumerate(datasets):
        # Histogram
        ax = axes[0, col]
        if len(cap_d) > 0 and len(rep_d) > 0:
            all_sizes = np.concatenate([cap_d, rep_d])
            bins = np.logspace(np.log10(max(1, all_sizes.min())),
                               np.log10(all_sizes.max()), 30)
            ax.hist(cap_d, bins=bins, alpha=0.6, color=C_CAP,
                    label=f"Capture (n={len(cap_d):,})", density=True)
            ax.hist(rep_d, bins=bins, alpha=0.6, color=C_REP,
                    label=f"Replay (n={len(rep_d):,})", density=True)
            ax.set_xscale('log')
            jsd_val = jsd(cap_d, rep_d)
            metrics[f'size_jsd_{label.lower().replace(" ","_")}'] = jsd_val
            setup_ax(ax, f"{label} Size Histogram\nJSD={jsd_val:.4f}",
                     "I/O Size (bytes)", "Density")
        else:
            setup_ax(ax, f"{label} Size Histogram", "I/O Size (bytes)", "Density")
        ax.legend(fontsize=8)

        # CDF
        ax = axes[1, col]
        if len(cap_d) > 0 and len(rep_d) > 0:
            sc = np.sort(cap_d)
            sr = np.sort(rep_d)
            ax.plot(sc, np.arange(1, len(sc)+1)/len(sc)*100,
                    color=C_CAP, linewidth=1.5, label="Capture")
            ax.plot(sr, np.arange(1, len(sr)+1)/len(sr)*100,
                    color=C_REP, linewidth=1.5, linestyle="--", label="Replay")
            ks_val = ks_stat(cap_d, rep_d)
            metrics[f'size_ks_{label.lower().replace(" ","_")}'] = ks_val
            setup_ax(ax, f"{label} Size CDF\nKS={ks_val:.4f}",
                     "I/O Size (bytes)", "Percentile (%)")
            ax.set_xscale('log')
        else:
            setup_ax(ax, f"{label} Size CDF", "I/O Size (bytes)", "Percentile (%)")
        ax.legend(fontsize=8)
        ax.set_ylim(0, 100)

    fig.tight_layout()
    fig.savefig(os.path.join(od, "02_io_size_comparison.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 02_io_size_comparison.png")
    return metrics


def plot_lba_heatmaps(cap_events, rep_events, cap_t0, rep_t0,
                      common_dur, time_bucket, lba_bins, od):
    """Chart 03: LBA heatmaps side-by-side + difference heatmap."""
    fig = plt.figure(figsize=(18, 12))
    gs = GridSpec(2, 3, figure=fig, hspace=0.35, wspace=0.3)
    fig.suptitle("LBA Access Pattern: Capture vs Replay", fontsize=15, fontweight="bold")

    # Shared max_sector across both traces
    cap_sectors = [e.sector for e in cap_events if e.action == ACTION_QUEUE and e.sector > 0]
    rep_sectors = [e.sector for e in rep_events if e.action == ACTION_QUEUE and e.sector > 0]
    max_sector = max(max(cap_sectors) if cap_sectors else 0,
                     max(rep_sectors) if rep_sectors else 0)
    if max_sector == 0:
        plt.close(fig)
        return {}

    gb_max = max_sector * SECTOR_SIZE / GB

    cap_hm = extract_lba_heatmap(cap_events, cap_t0, common_dur, time_bucket,
                                  lba_bins, max_sector)
    rep_hm = extract_lba_heatmap(rep_events, rep_t0, common_dur, time_bucket,
                                  lba_bins, max_sector)

    # Make both the same shape
    nt = min(cap_hm.shape[1], rep_hm.shape[1])
    cap_hm = cap_hm[:, :nt]
    rep_hm = rep_hm[:, :nt]

    n_yticks = min(6, lba_bins)
    ytick_pos = np.linspace(0, lba_bins - 1, n_yticks)
    ytick_labels = [f"{v:.0f}G" for v in np.linspace(0, gb_max, n_yticks)]

    # Capture heatmap
    ax = fig.add_subplot(gs[0, 0])
    vmax = max(cap_hm.max(), rep_hm.max(), 1)
    if cap_hm.max() > 0:
        im = ax.imshow(cap_hm, aspect="auto", origin="lower",
                        norm=LogNorm(vmin=1, vmax=vmax),
                        cmap="Blues", interpolation="nearest")
        plt.colorbar(im, ax=ax, shrink=0.8)
    ax.set_yticks(ytick_pos); ax.set_yticklabels(ytick_labels, fontsize=7)
    setup_ax(ax, "Capture", "Time →", "LBA →")

    # Replay heatmap
    ax = fig.add_subplot(gs[0, 1])
    if rep_hm.max() > 0:
        im = ax.imshow(rep_hm, aspect="auto", origin="lower",
                        norm=LogNorm(vmin=1, vmax=vmax),
                        cmap="Oranges", interpolation="nearest")
        plt.colorbar(im, ax=ax, shrink=0.8)
    ax.set_yticks(ytick_pos); ax.set_yticklabels(ytick_labels, fontsize=7)
    setup_ax(ax, "Replay", "Time →", "LBA →")

    # Difference heatmap (capture - replay, symmetric log scale)
    ax = fig.add_subplot(gs[0, 2])
    diff = cap_hm - rep_hm
    if np.any(diff != 0):
        abs_max = max(abs(diff.min()), abs(diff.max()), 1)
        im = ax.imshow(diff, aspect="auto", origin="lower",
                        norm=SymLogNorm(linthresh=1, vmin=-abs_max, vmax=abs_max),
                        cmap="RdBu_r", interpolation="nearest")
        plt.colorbar(im, ax=ax, label="Cap − Rep", shrink=0.8)
    ax.set_yticks(ytick_pos); ax.set_yticklabels(ytick_labels, fontsize=7)
    setup_ax(ax, "Difference (Cap − Rep)", "Time →", "LBA →")

    # LBA frequency comparison (1D)
    ax = fig.add_subplot(gs[1, 0:2])
    cap_freq = cap_hm.sum(axis=1)
    rep_freq = rep_hm.sum(axis=1)
    lba_gb = np.linspace(0, gb_max, lba_bins)
    ax.fill_between(lba_gb, cap_freq, alpha=0.3, color=C_CAP)
    ax.plot(lba_gb, cap_freq, color=C_CAP, linewidth=1, label="Capture")
    ax.fill_between(lba_gb, rep_freq, alpha=0.3, color=C_REP)
    ax.plot(lba_gb, rep_freq, color=C_REP, linewidth=1, linestyle="--", label="Replay")
    corr_lba = pearson_r(cap_freq, rep_freq)
    setup_ax(ax, f"LBA Frequency Profile  (r={corr_lba:.4f})",
             "LBA Offset (GB)", "I/O Count")
    ax.legend(fontsize=9)

    # Per-bin difference bar
    ax = fig.add_subplot(gs[1, 2])
    diff_freq = cap_freq - rep_freq
    pos = diff_freq >= 0
    ax.bar(lba_gb[pos], diff_freq[pos], width=(lba_gb[1]-lba_gb[0])*0.9,
           color=C_CAP, alpha=0.6, label="Cap > Rep")
    ax.bar(lba_gb[~pos], diff_freq[~pos], width=(lba_gb[1]-lba_gb[0])*0.9,
           color=C_REP, alpha=0.6, label="Rep > Cap")
    ax.axhline(0, color="black", linewidth=0.5)
    setup_ax(ax, "LBA Frequency Difference", "LBA Offset (GB)", "Δ I/O Count")
    ax.legend(fontsize=8)

    fig.savefig(os.path.join(od, "03_lba_heatmaps.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 03_lba_heatmaps.png")
    return {'lba_freq_corr': corr_lba}


def plot_queue_depth_comparison(cap_analyzer, rep_analyzer, common_dur, od):
    """Chart 04: Queue depth overlay + residual."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), height_ratios=[3, 1])
    fig.suptitle("Queue Depth: Capture vs Replay", fontsize=15, fontweight="bold")

    bt_c, avg_c, _, _ = cap_analyzer.compute_queue_depth_bucketed()
    bt_r, avg_r, _, _ = rep_analyzer.compute_queue_depth_bucketed()
    n = min(len(bt_c), len(bt_r))
    bt, qc, qr = bt_c[:n], avg_c[:n], avg_r[:n]

    ax1.plot(bt, qc, color=C_CAP, linewidth=1, label="Capture")
    ax1.plot(bt, qr, color=C_REP, linewidth=1, linestyle="--", label="Replay")
    ax1.fill_between(bt, qc, qr, alpha=0.15, color=C_DIFF)
    corr = pearson_r(qc, qr)
    setup_ax(ax1, f"Average Queue Depth  (r={corr:.4f})", "", "QD")
    ax1.legend(fontsize=9)

    residual = qc - qr
    ax2.bar(bt, residual, width=cap_analyzer.time_bucket * 0.9, color=C_DIFF, alpha=0.6)
    ax2.axhline(0, color="black", linewidth=0.5)
    setup_ax(ax2, "Residual (Cap − Rep)", "Time (s)", "Δ QD")

    fig.tight_layout()
    fig.savefig(os.path.join(od, "04_queue_depth.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 04_queue_depth.png")
    return {'qd_corr': corr, 'qd_smape': smape(qc, qr)}


def plot_throughput_iops_comparison(cap_analyzer, rep_analyzer, common_dur, od):
    """Chart 05: Throughput and IOPS overlay + residuals."""
    fig = plt.figure(figsize=(16, 14))
    gs = GridSpec(4, 1, figure=fig, hspace=0.4,
                  height_ratios=[2, 1, 2, 1])
    fig.suptitle("Throughput & IOPS: Capture vs Replay", fontsize=15, fontweight="bold")

    # Throughput
    bt_c, r_c, w_c = cap_analyzer.compute_throughput()
    bt_r, r_r, w_r = rep_analyzer.compute_throughput()
    n = min(len(bt_c), len(bt_r))
    bt = bt_c[:n]

    ax = fig.add_subplot(gs[0])
    total_c = r_c[:n] + w_c[:n]
    total_r = r_r[:n] + w_r[:n]
    ax.plot(bt, total_c, color=C_CAP, linewidth=1, label="Capture total")
    ax.plot(bt, total_r, color=C_REP, linewidth=1, linestyle="--", label="Replay total")
    ax.fill_between(bt, total_c, total_r, alpha=0.12, color=C_DIFF)
    corr_tp = pearson_r(total_c, total_r)
    setup_ax(ax, f"Throughput  (r={corr_tp:.4f})", "", "MB/s")
    ax.legend(fontsize=9)

    ax = fig.add_subplot(gs[1])
    ax.bar(bt, total_c - total_r, width=cap_analyzer.time_bucket * 0.9,
           color=C_DIFF, alpha=0.6)
    ax.axhline(0, color="black", linewidth=0.5)
    setup_ax(ax, "", "Time (s)", "Δ MB/s")

    # IOPS
    bt_c, ri_c, wi_c = cap_analyzer.compute_iops()
    bt_r, ri_r, wi_r = rep_analyzer.compute_iops()
    n = min(len(bt_c), len(bt_r))
    bt = bt_c[:n]

    ax = fig.add_subplot(gs[2])
    iops_c = ri_c[:n] + wi_c[:n]
    iops_r = ri_r[:n] + wi_r[:n]
    ax.plot(bt, iops_c, color=C_CAP, linewidth=1, label="Capture IOPS")
    ax.plot(bt, iops_r, color=C_REP, linewidth=1, linestyle="--", label="Replay IOPS")
    ax.fill_between(bt, iops_c, iops_r, alpha=0.12, color=C_DIFF)
    corr_iops = pearson_r(iops_c, iops_r)
    setup_ax(ax, f"IOPS  (r={corr_iops:.4f})", "", "IOPS")
    ax.legend(fontsize=9)

    ax = fig.add_subplot(gs[3])
    ax.bar(bt, iops_c - iops_r, width=cap_analyzer.time_bucket * 0.9,
           color=C_DIFF, alpha=0.6)
    ax.axhline(0, color="black", linewidth=0.5)
    setup_ax(ax, "", "Time (s)", "Δ IOPS")

    fig.savefig(os.path.join(od, "05_throughput_iops.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 05_throughput_iops.png")
    return {'tp_corr': corr_tp, 'tp_smape': smape(total_c, total_r),
            'iops_corr': corr_iops, 'iops_smape': smape(iops_c, iops_r)}


def plot_latency_cdf_comparison(cap_analyzer, rep_analyzer, od):
    """Chart 06: Latency CDF overlay (D→C and Q→C)."""
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("Latency CDF: Capture vs Replay", fontsize=15, fontweight="bold")

    cap_lats = cap_analyzer.compute_latency_distributions()
    rep_lats = rep_analyzer.compute_latency_distributions()

    metrics = {}
    for row, prefix in enumerate(["d2c", "q2c"]):
        for col, rw in enumerate(["read", "write"]):
            ax = axes[row, col]
            key = f"{prefix}_{rw}"
            c_data = cap_lats[key]
            r_data = rep_lats[key]

            if len(c_data) > 0:
                sc = np.sort(c_data)
                ax.plot(sc, np.arange(1, len(sc)+1)/len(sc)*100,
                        color=C_CAP, linewidth=1.5, label=f"Capture (n={len(c_data):,})")
            if len(r_data) > 0:
                sr = np.sort(r_data)
                ax.plot(sr, np.arange(1, len(sr)+1)/len(sr)*100,
                        color=C_REP, linewidth=1.5, linestyle="--",
                        label=f"Replay (n={len(r_data):,})")

            if len(c_data) > 0 and len(r_data) > 0:
                ks = ks_stat(c_data, r_data)
                j = jsd(c_data, r_data)
                metrics[f'lat_{key}_ks'] = ks
                metrics[f'lat_{key}_jsd'] = j
                title = f"{prefix.upper()} {rw.title()}\nKS={ks:.4f}  JSD={j:.4f}"
            else:
                title = f"{prefix.upper()} {rw.title()}"

            setup_ax(ax, title, "Latency (µs)", "Percentile (%)")
            ax.legend(fontsize=8)
            ax.set_ylim(0, 100)

    fig.tight_layout()
    fig.savefig(os.path.join(od, "06_latency_cdf.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 06_latency_cdf.png")
    return metrics


def plot_cumulative_drift(cap_events, rep_events, cap_t0, rep_t0,
                          common_dur, time_bucket, od):
    """Chart 07: Cumulative I/O count and bytes — drift over time."""
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(16, 12),
                                         height_ratios=[2, 2, 1])
    fig.suptitle("Cumulative I/O Drift: Capture vs Replay", fontsize=15, fontweight="bold")

    tc, cc, cb = extract_cumulative_ios(cap_events, cap_t0, common_dur, time_bucket)
    tr, rc, rb = extract_cumulative_ios(rep_events, rep_t0, common_dur, time_bucket)
    n = min(len(tc), len(tr))
    t = tc[:n]

    # Cumulative I/O count
    ax1.plot(t, cc[:n], color=C_CAP, linewidth=1.5, label="Capture")
    ax1.plot(t, rc[:n], color=C_REP, linewidth=1.5, linestyle="--", label="Replay")
    final_drift_count = cc[n-1] - rc[n-1] if n > 0 else 0
    setup_ax(ax1, f"Cumulative I/O Count  (final drift: {final_drift_count:+,.0f})",
             "", "Total I/Os")
    ax1.legend(fontsize=9)

    # Cumulative bytes
    ax2.plot(t, cb[:n] / GB, color=C_CAP, linewidth=1.5, label="Capture")
    ax2.plot(t, rb[:n] / GB, color=C_REP, linewidth=1.5, linestyle="--", label="Replay")
    final_drift_bytes = (cb[n-1] - rb[n-1]) / MB if n > 0 else 0
    setup_ax(ax2, f"Cumulative Bytes  (final drift: {final_drift_bytes:+,.1f} MB)",
             "", "Total (GB)")
    ax2.legend(fontsize=9)

    # Percentage drift
    with np.errstate(divide='ignore', invalid='ignore'):
        pct_drift = np.where(cc[:n] > 0,
                              (cc[:n] - rc[:n]) / cc[:n] * 100, 0)
    ax3.fill_between(t, pct_drift, alpha=0.3, color=C_DIFF)
    ax3.plot(t, pct_drift, color=C_DIFF, linewidth=1)
    ax3.axhline(0, color="black", linewidth=0.5)
    ax3.axhspan(-5, 5, alpha=0.1, color=COLORS["aligned"], label="±5% band")
    setup_ax(ax3, "I/O Count Drift (%)", "Time (s)", "Drift %")
    ax3.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(os.path.join(od, "07_cumulative_drift.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 07_cumulative_drift.png")
    return {'final_count_drift': final_drift_count,
            'final_bytes_drift_mb': final_drift_bytes}


def plot_fidelity_dashboard(all_metrics, cap_analyzer, rep_analyzer,
                            common_dur, od):
    """Chart 08: Single-page fidelity summary dashboard."""
    fig = plt.figure(figsize=(18, 10))
    gs = GridSpec(2, 3, figure=fig, hspace=0.4, wspace=0.35)
    fig.suptitle("Replay Fidelity Dashboard", fontsize=16, fontweight="bold")

    # ── Correlation bar chart ────────────────────────────────────────────
    ax = fig.add_subplot(gs[0, 0])
    corr_keys = [(k, v) for k, v in all_metrics.items() if 'corr' in k and v is not None]
    if corr_keys:
        labels = [k.replace('_corr', '').replace('_', ' ').title() for k, _ in corr_keys]
        vals = [v for _, v in corr_keys]
        colors_bar = [COLORS["aligned"] if v > 0.9 else
                      COLORS["misaligned"] if v > 0.7 else
                      COLORS["unsafe"] for v in vals]
        y_pos = np.arange(len(labels))
        ax.barh(y_pos, vals, color=colors_bar, alpha=0.8)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlim(0, 1.05)
        ax.axvline(0.95, color=COLORS["aligned"], linestyle="--", alpha=0.5, label="0.95")
        ax.axvline(0.90, color=COLORS["misaligned"], linestyle=":", alpha=0.5, label="0.90")
        for i, v in enumerate(vals):
            ax.text(v + 0.01, i, f"{v:.3f}", va='center', fontsize=8)
    setup_ax(ax, "Pearson Correlation", "r", "")
    ax.legend(fontsize=7)

    # ── sMAPE bar chart ──────────────────────────────────────────────────
    ax = fig.add_subplot(gs[0, 1])
    smape_keys = [(k, v) for k, v in all_metrics.items() if 'smape' in k and v is not None]
    if smape_keys:
        labels = [k.replace('_smape', '').replace('_', ' ').title() for k, _ in smape_keys]
        vals = [v for _, v in smape_keys]
        colors_bar = [COLORS["aligned"] if v < 0.1 else
                      COLORS["misaligned"] if v < 0.3 else
                      COLORS["unsafe"] for v in vals]
        y_pos = np.arange(len(labels))
        ax.barh(y_pos, vals, color=colors_bar, alpha=0.8)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=9)
        for i, v in enumerate(vals):
            ax.text(v + 0.005, i, f"{v:.4f}", va='center', fontsize=8)
    setup_ax(ax, "sMAPE (lower = better)", "sMAPE", "")

    # ── KS / JSD bars ───────────────────────────────────────────────────
    ax = fig.add_subplot(gs[0, 2])
    dist_keys = [(k, v) for k, v in all_metrics.items()
                 if ('ks' in k or 'jsd' in k) and v is not None]
    if dist_keys:
        labels = [k.replace('lat_', '').replace('size_', 'sz ')
                    .replace('_', ' ').upper() for k, _ in dist_keys]
        vals = [v for _, v in dist_keys]
        colors_bar = [COLORS["aligned"] if v < 0.1 else
                      COLORS["misaligned"] if v < 0.3 else
                      COLORS["unsafe"] for v in vals]
        y_pos = np.arange(len(labels))
        ax.barh(y_pos, vals, color=colors_bar, alpha=0.8)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=7)
        for i, v in enumerate(vals):
            ax.text(v + 0.005, i, f"{v:.4f}", va='center', fontsize=7)
    setup_ax(ax, "Distribution Metrics (KS / JSD)", "Value", "")

    # ── Summary table ────────────────────────────────────────────────────
    ax = fig.add_subplot(gs[1, 0:2])
    ax.axis("off")

    # Compute summary stats
    cap_ce = [e for e in cap_analyzer.events if e.action == ACTION_COMPLETE]
    rep_ce = [e for e in rep_analyzer.events if e.action == ACTION_COMPLETE]
    cap_q = [e for e in cap_analyzer.events if e.action == ACTION_QUEUE and e.nblocks > 0]
    rep_q = [e for e in rep_analyzer.events if e.action == ACTION_QUEUE and e.nblocks > 0]

    td = [
        ["Common duration", f"{common_dur:.3f} s", ""],
        ["Q events", f"{len(cap_q):,}", f"{len(rep_q):,}"],
        ["Completed I/Os", f"{len(cap_analyzer.completed_ios):,}",
         f"{len(rep_analyzer.completed_ios):,}"],
        ["Total bytes (Q)", f"{sum(e.size_bytes for e in cap_q)/GB:.2f} GB",
         f"{sum(e.size_bytes for e in rep_q)/GB:.2f} GB"],
        ["Read Q events", f"{sum(1 for e in cap_q if e.is_read):,}",
         f"{sum(1 for e in rep_q if e.is_read):,}"],
        ["Write Q events", f"{sum(1 for e in cap_q if e.is_write):,}",
         f"{sum(1 for e in rep_q if e.is_write):,}"],
    ]

    # Add latency stats if available
    cap_d2c = cap_analyzer.compute_latency_distributions().get('d2c_write', np.array([]))
    rep_d2c = rep_analyzer.compute_latency_distributions().get('d2c_write', np.array([]))
    if len(cap_d2c) > 0 and len(rep_d2c) > 0:
        td.append(["Write D2C p50",
                    f"{np.median(cap_d2c):.0f} µs", f"{np.median(rep_d2c):.0f} µs"])
        td.append(["Write D2C p99",
                    f"{np.percentile(cap_d2c, 99):.0f} µs",
                    f"{np.percentile(rep_d2c, 99):.0f} µs"])

    table = ax.table(cellText=td, colLabels=["Metric", "Capture", "Replay"],
                     loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.6)
    for (r, c), cell in table.get_celld().items():
        if r == 0:
            cell.set_facecolor("#E0E0E0")
            cell.set_text_props(fontweight="bold")
    ax.set_title("Trace Comparison Summary", fontsize=13, fontweight="bold", pad=15)

    # ── Overall fidelity score ───────────────────────────────────────────
    ax = fig.add_subplot(gs[1, 2])
    ax.axis("off")

    # Compute weighted fidelity score
    corr_vals = [v for k, v in all_metrics.items() if 'corr' in k and v is not None]
    smape_vals = [v for k, v in all_metrics.items() if 'smape' in k and v is not None]
    ks_vals = [v for k, v in all_metrics.items() if '_ks' in k and v is not None]

    scores = []
    if corr_vals:
        scores.append(("Correlation", np.mean(corr_vals)))
    if smape_vals:
        scores.append(("1 − sMAPE", 1 - np.mean(smape_vals)))
    if ks_vals:
        scores.append(("1 − KS", 1 - np.mean(ks_vals)))

    if scores:
        overall = np.mean([s for _, s in scores])
        grade = ("EXCELLENT" if overall > 0.95 else
                 "GOOD" if overall > 0.90 else
                 "FAIR" if overall > 0.80 else
                 "POOR")
        grade_color = (COLORS["aligned"] if overall > 0.95 else
                       "#FFC107" if overall > 0.90 else
                       COLORS["misaligned"] if overall > 0.80 else
                       COLORS["unsafe"])

        ax.text(0.5, 0.75, f"{overall:.1%}", transform=ax.transAxes,
                fontsize=48, fontweight="bold", ha="center", va="center",
                color=grade_color)
        ax.text(0.5, 0.50, grade, transform=ax.transAxes,
                fontsize=20, fontweight="bold", ha="center", va="center",
                color=grade_color)
        detail = "\n".join([f"  {name}: {val:.3f}" for name, val in scores])
        ax.text(0.5, 0.25, detail, transform=ax.transAxes,
                fontsize=10, ha="center", va="center", fontfamily="monospace")
    ax.set_title("Overall Fidelity Score", fontsize=13, fontweight="bold", pad=10)

    fig.savefig(os.path.join(od, "08_fidelity_dashboard.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved: 08_fidelity_dashboard.png")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="blktrace Capture vs Replay Comparison Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 blktrace_compare.py capture.txt replay.txt
  python3 blktrace_compare.py capture.txt replay.txt --time-bucket 0.05
  python3 blktrace_compare.py capture.txt replay.txt --lbs 512 --iu-size 4096
        """)
    parser.add_argument("capture_file", help="Path to capture blkparse text output")
    parser.add_argument("replay_file", help="Path to replay blkparse text output")
    parser.add_argument("--time-bucket", type=float, default=0.1,
                        help="Time bucket seconds (default: 0.1)")
    parser.add_argument("--lba-bins", type=int, default=256,
                        help="LBA bins for heatmap (default: 256)")
    parser.add_argument("--lbs", type=int, default=512,
                        help="Logical Block Size bytes (default: 512)")
    parser.add_argument("--iu-size", type=int, default=0)
    parser.add_argument("--npwg", type=int, default=0)
    parser.add_argument("--awun", type=int, default=0)
    parser.add_argument("--output-dir", default="./compare_results",
                        help="Output directory (default: ./compare_results)")
    args = parser.parse_args()

    # Update sector size
    import blktrace_analyzer
    blktrace_analyzer.SECTOR_SIZE = args.lbs

    geom = SSDGeometry(lbs=args.lbs, iu_size=args.iu_size,
                        npwg=args.npwg, awun=args.awun)

    print(f"\n{'='*72}")
    print(f"  blktrace Capture vs Replay Comparison")
    print(f"{'='*72}")

    print(f"\n  Loading CAPTURE: {args.capture_file}")
    cap_events = load_trace(args.capture_file)
    print(f"\n  Loading REPLAY:  {args.replay_file}")
    rep_events = load_trace(args.replay_file)

    if not cap_events or not rep_events:
        print("\n  ERROR: One or both traces have no parseable events.")
        sys.exit(1)

    # Normalize timelines to t=0
    cap_t0 = cap_events[0].timestamp
    rep_t0 = rep_events[0].timestamp
    cap_dur = cap_events[-1].timestamp - cap_t0
    rep_dur = rep_events[-1].timestamp - rep_t0
    common_dur = min(cap_dur, rep_dur)

    print(f"\n  Capture duration : {cap_dur:.3f} s  ({len(cap_events):,} events)")
    print(f"  Replay duration  : {rep_dur:.3f} s  ({len(rep_events):,} events)")
    print(f"  Common duration  : {common_dur:.3f} s")

    # Build analyzers
    cap_analyzer = BlktraceAnalyzer(cap_events, time_bucket=args.time_bucket,
                                     lba_bins=args.lba_bins, geometry=geom)
    rep_analyzer = BlktraceAnalyzer(rep_events, time_bucket=args.time_bucket,
                                     lba_bins=args.lba_bins, geometry=geom)

    os.makedirs(args.output_dir, exist_ok=True)
    print(f"\n  Generating comparison charts in: {args.output_dir}/\n")

    # Generate all charts, collecting metrics
    all_metrics = {}

    m = plot_q_event_rate(cap_events, rep_events, cap_t0, rep_t0,
                          common_dur, args.time_bucket, args.output_dir)
    all_metrics.update(m)

    m = plot_io_size_comparison(cap_events, rep_events, args.output_dir)
    all_metrics.update(m)

    m = plot_lba_heatmaps(cap_events, rep_events, cap_t0, rep_t0,
                          common_dur, args.time_bucket, args.lba_bins,
                          args.output_dir)
    all_metrics.update(m)

    m = plot_queue_depth_comparison(cap_analyzer, rep_analyzer,
                                    common_dur, args.output_dir)
    all_metrics.update(m)

    m = plot_throughput_iops_comparison(cap_analyzer, rep_analyzer,
                                        common_dur, args.output_dir)
    all_metrics.update(m)

    m = plot_latency_cdf_comparison(cap_analyzer, rep_analyzer, args.output_dir)
    all_metrics.update(m)

    m = plot_cumulative_drift(cap_events, rep_events, cap_t0, rep_t0,
                              common_dur, args.time_bucket, args.output_dir)
    all_metrics.update(m)

    plot_fidelity_dashboard(all_metrics, cap_analyzer, rep_analyzer,
                            common_dur, args.output_dir)

    # Print fidelity summary
    print(f"\n{'='*72}")
    print(f"  FIDELITY METRICS SUMMARY")
    print(f"{'='*72}")
    for k, v in sorted(all_metrics.items()):
        if v is not None:
            print(f"    {k:30s} : {v:.6f}" if isinstance(v, float) else
                  f"    {k:30s} : {v}")
    print(f"{'='*72}\n")

    print(f"  All charts saved to: {args.output_dir}/")
    for f in sorted(os.listdir(args.output_dir)):
        if f.endswith(".png"):
            sz = os.path.getsize(os.path.join(args.output_dir, f)) / 1024
            print(f"    {f} ({sz:.0f} KB)")
    print()


if __name__ == "__main__":
    main()
