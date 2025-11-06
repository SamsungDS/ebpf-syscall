#!/usr/bin/env python3

import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import Rectangle
import seaborn as sns
from datetime import datetime

class SyscallVisualizer:
    def __init__(self, json_file):
        """Initialize visualizer with JSON data file"""
        self.json_file = json_file
        self.data = None
        self.events = []
        self.processes = {}
        self.load_data()
        
    def load_data(self):
        """Load and parse JSON data"""
        try:
            with open(self.json_file, 'r') as f:
                self.data = json.load(f)
            
            self.events = self.data.get('raw_events', [])
            
            if not self.events:
                print("Warning: No raw events found in JSON file.")
                print("Make sure you ran the monitor with detailed logging enabled.")
                sys.exit(1)
            
            # Parse process information
            for event in self.events:
                pid = event['pid']
                if pid not in self.processes:
                    self.processes[pid] = {
                        'name': event['process_name'],
                        'events': []
                    }
                self.processes[pid]['events'].append(event)
            
            print(f"Loaded {len(self.events)} events from {len(self.processes)} processes")
            
        except FileNotFoundError:
            print(f"Error: File '{self.json_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format - {e}")
            sys.exit(1)
    
    def get_io_size_bucket(self, size):
        """Categorize I/O size into granular buckets"""
        if size == 0:
            return "0 B"
        elif size == 1:
            return "1 B"
        elif size <= 4:
            return "2-4 B"
        elif size <= 8:
            return "5-8 B"
        elif size <= 16:
            return "9-16 B"
        elif size <= 32:
            return "17-32 B"
        elif size <= 64:
            return "33-64 B"
        elif size <= 128:
            return "65-128 B"
        elif size <= 256:
            return "129-256 B"
        elif size <= 512:
            return "257-512 B"
        elif size < 1024:
            return "513-1023 B"
        elif size < 2 * 1024:
            return "1-2 KB"
        elif size < 4 * 1024:
            return "2-4 KB"
        elif size < 8 * 1024:
            return "4-8 KB"
        elif size < 16 * 1024:
            return "8-16 KB"
        elif size < 32 * 1024:
            return "16-32 KB"
        elif size < 64 * 1024:
            return "32-64 KB"
        elif size < 128 * 1024:
            return "64-128 KB"
        elif size < 256 * 1024:
            return "128-256 KB"
        elif size < 512 * 1024:
            return "256-512 KB"
        elif size < 1024 * 1024:
            return "512KB-1MB"
        elif size < 2 * 1024 * 1024:
            return "1-2 MB"
        elif size < 4 * 1024 * 1024:
            return "2-4 MB"
        elif size < 8 * 1024 * 1024:
            return "4-8 MB"
        elif size < 16 * 1024 * 1024:
            return "8-16 MB"
        else:
            return "> 16 MB"
    
    def get_top_processes(self, n=10):
        """Get top N processes by event count"""
        sorted_procs = sorted(
            self.processes.items(),
            key=lambda x: len(x[1]['events']),
            reverse=True
        )
        return sorted_procs[:n]
    
    def plot_process_io_timeseries(self, output_file=None):
        """Plot process-wise I/O size time series"""
        top_procs = self.get_top_processes(10)
        
        if not top_procs:
            print("No process data available")
            return
        
        # Calculate grid layout
        n_processes = len(top_procs)
        n_cols = 2
        n_rows = (n_processes + 1) // 2
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 4 * n_rows))
        fig.suptitle('Process-wise I/O Size Time Series', fontsize=16, fontweight='bold')
        
        if n_processes == 1:
            axes = [[axes]]
        elif n_rows == 1:
            axes = [axes]
        
        for idx, (pid, proc_data) in enumerate(top_procs):
            row = idx // n_cols
            col = idx % n_cols
            ax = axes[row][col]
            
            # Extract timestamps and sizes
            events = proc_data['events']
            timestamps = [e['timestamp_ms'] for e in events]
            sizes = [e['size'] for e in events]
            syscalls = [e['syscall_name'] for e in events]
            
            # Normalize timestamps to start from 0
            if timestamps:
                min_ts = min(timestamps)
                timestamps = [(t - min_ts) / 1000.0 for t in timestamps]  # Convert to seconds
            
            # Create color map for different syscalls
            unique_syscalls = list(set(syscalls))
            colors = plt.cm.tab10(np.linspace(0, 1, len(unique_syscalls)))
            syscall_colors = {sc: colors[i] for i, sc in enumerate(unique_syscalls)}
            
            # Plot with different colors for different syscalls
            for syscall in unique_syscalls:
                sc_timestamps = [timestamps[i] for i in range(len(syscalls)) if syscalls[i] == syscall]
                sc_sizes = [sizes[i] for i in range(len(syscalls)) if syscalls[i] == syscall]
                ax.scatter(sc_timestamps, sc_sizes, alpha=0.6, s=20, 
                          label=syscall, color=syscall_colors[syscall])
            
            ax.set_xlabel('Time (seconds)', fontsize=10)
            ax.set_ylabel('I/O Size (bytes)', fontsize=10)
            ax.set_title(f'{proc_data["name"]} (PID: {pid})\n{len(events)} events', 
                        fontsize=11, fontweight='bold')
            ax.legend(fontsize=8, loc='upper right')
            ax.grid(True, alpha=0.3)
            ax.set_yscale('log')
            
        # Remove empty subplots
        for idx in range(len(top_procs), n_rows * n_cols):
            row = idx // n_cols
            col = idx % n_cols
            fig.delaxes(axes[row][col])
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved process I/O time series to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_io_size_buckets(self, output_file=None):
        """Plot I/O size distribution in buckets for each process"""
        top_procs = self.get_top_processes(10)
        
        fig, axes = plt.subplots(3, 1, figsize=(16, 14))
        fig.suptitle('I/O Size Distribution by Process', fontsize=16, fontweight='bold')
        
        # Define all bucket orders
        bucket_order_all = [
            "0 B", "1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
            "65-128 B", "129-256 B", "257-512 B", "513-1023 B",
            "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB", "32-64 KB",
            "64-128 KB", "128-256 KB", "256-512 KB", "512KB-1MB",
            "1-2 MB", "2-4 MB", "4-8 MB", "8-16 MB", "> 16 MB"
        ]
        
        # Sub-1KB buckets for detailed view
        bucket_order_small = [
            "0 B", "1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
            "65-128 B", "129-256 B", "257-512 B", "513-1023 B"
        ]
        
        # KB and larger buckets
        bucket_order_large = [
            "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB", "32-64 KB",
            "64-128 KB", "128-256 KB", "256-512 KB", "512KB-1MB",
            "1-2 MB", "2-4 MB", "4-8 MB", "8-16 MB", "> 16 MB"
        ]
        
        process_names = []
        bucket_data_all = {bucket: [] for bucket in bucket_order_all}
        
        for pid, proc_data in top_procs:
            process_names.append(f"{proc_data['name']}\n({pid})")
            
            # Count events in each bucket
            bucket_counts = defaultdict(int)
            for event in proc_data['events']:
                bucket = self.get_io_size_bucket(event['size'])
                bucket_counts[bucket] += 1
            
            # Add counts to data structure
            for bucket in bucket_order_all:
                bucket_data_all[bucket].append(bucket_counts.get(bucket, 0))
        
        # Plot 1: Sub-1KB granular view (stacked bar)
        ax1 = axes[0]
        x_pos = np.arange(len(process_names))
        bottom = np.zeros(len(process_names))
        
        colors_small = plt.cm.YlOrRd(np.linspace(0.2, 1, len(bucket_order_small)))
        
        for idx, bucket in enumerate(bucket_order_small):
            values = bucket_data_all[bucket]
            if sum(values) > 0:  # Only plot if there's data
                ax1.bar(x_pos, values, bottom=bottom, 
                       label=bucket, color=colors_small[idx], 
                       edgecolor='black', linewidth=0.5)
                bottom += values
        
        ax1.set_xlabel('Process', fontsize=12)
        ax1.set_ylabel('Number of Events', fontsize=12)
        ax1.set_title('Sub-1KB I/O Size Distribution (Granular)', fontsize=13, fontweight='bold')
        ax1.set_xticks(x_pos)
        ax1.set_xticklabels(process_names, rotation=45, ha='right', fontsize=9)
        ax1.legend(title='I/O Size', bbox_to_anchor=(1.05, 1), loc='upper left', 
                  fontsize=8, ncol=1)
        ax1.grid(axis='y', alpha=0.3)
        
        # Plot 2: KB and larger sizes (stacked bar)
        ax2 = axes[1]
        bottom = np.zeros(len(process_names))
        
        colors_large = plt.cm.viridis(np.linspace(0, 1, len(bucket_order_large)))
        
        for idx, bucket in enumerate(bucket_order_large):
            values = bucket_data_all[bucket]
            if sum(values) > 0:  # Only plot if there's data
                ax2.bar(x_pos, values, bottom=bottom, 
                       label=bucket, color=colors_large[idx], 
                       edgecolor='black', linewidth=0.5)
                bottom += values
        
        ax2.set_xlabel('Process', fontsize=12)
        ax2.set_ylabel('Number of Events', fontsize=12)
        ax2.set_title('KB-MB Range I/O Size Distribution', fontsize=13, fontweight='bold')
        ax2.set_xticks(x_pos)
        ax2.set_xticklabels(process_names, rotation=45, ha='right', fontsize=9)
        ax2.legend(title='I/O Size', bbox_to_anchor=(1.05, 1), loc='upper left', 
                  fontsize=8, ncol=1)
        ax2.grid(axis='y', alpha=0.3)
        
        # Plot 3: Heatmap of all buckets (filtered to show only populated buckets)
        ax3 = axes[2]
        
        # Filter out empty buckets for cleaner heatmap
        populated_buckets = [b for b in bucket_order_all 
                            if sum(bucket_data_all[b]) > 0]
        
        # Create matrix for heatmap
        heatmap_data = []
        for bucket in populated_buckets:
            heatmap_data.append(bucket_data_all[bucket])
        
        if heatmap_data:
            heatmap_data = np.array(heatmap_data)
            
            im = ax3.imshow(heatmap_data, cmap='YlOrRd', aspect='auto', 
                           interpolation='nearest')
            
            # Set ticks and labels
            ax3.set_xticks(np.arange(len(process_names)))
            ax3.set_yticks(np.arange(len(populated_buckets)))
            ax3.set_xticklabels(process_names, rotation=45, ha='right', fontsize=9)
            ax3.set_yticklabels(populated_buckets, fontsize=8)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax3)
            cbar.set_label('Event Count', rotation=270, labelpad=20, fontsize=11)
            
            # Add text annotations (only for non-zero values)
            for i in range(len(populated_buckets)):
                for j in range(len(process_names)):
                    value = int(heatmap_data[i, j])
                    if value > 0:
                        # Choose text color based on background
                        text_color = "white" if value > heatmap_data.max() * 0.6 else "black"
                        ax3.text(j, i, value, ha="center", va="center", 
                               color=text_color, fontsize=7, fontweight='bold')
            
            ax3.set_title('Complete I/O Size Distribution Heatmap', 
                         fontsize=13, fontweight='bold')
            ax3.set_xlabel('Process', fontsize=12)
            ax3.set_ylabel('I/O Size Bucket', fontsize=12)
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved I/O size bucket analysis to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_fd_analysis(self, output_file=None):
        """Plot file descriptor usage patterns"""
        top_procs = self.get_top_processes(6)
        
        n_processes = len(top_procs)
        n_cols = 2
        n_rows = (n_processes + 1) // 2
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 5 * n_rows))
        fig.suptitle('File Descriptor Usage Analysis', fontsize=16, fontweight='bold')
        
        if n_processes == 1:
            axes = [[axes]]
        elif n_rows == 1:
            axes = [axes]
        
        for idx, (pid, proc_data) in enumerate(top_procs):
            row = idx // n_cols
            col = idx % n_cols
            ax = axes[row][col]
            
            # Collect FD statistics
            fd_stats = defaultdict(lambda: {'count': 0, 'total_size': 0, 'syscalls': set()})
            
            for event in proc_data['events']:
                fd = event.get('fd')
                if fd is not None and fd != 4294967295:  # Exclude invalid FDs
                    fd_stats[fd]['count'] += 1
                    fd_stats[fd]['total_size'] += event['size']
                    fd_stats[fd]['syscalls'].add(event['syscall_name'])
            
            if not fd_stats:
                ax.text(0.5, 0.5, 'No valid FD data', 
                       ha='center', va='center', transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} (PID: {pid})', 
                           fontsize=11, fontweight='bold')
                continue
            
            # Sort FDs by usage
            sorted_fds = sorted(fd_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:20]
            
            fds = [f"FD {fd}" for fd, _ in sorted_fds]
            counts = [stats['count'] for _, stats in sorted_fds]
            sizes = [stats['total_size'] / 1024 for _, stats in sorted_fds]  # Convert to KB
            
            # Create dual-axis plot
            x_pos = np.arange(len(fds))
            
            ax_twin = ax.twinx()
            
            bar1 = ax.bar(x_pos - 0.2, counts, 0.4, label='Event Count', 
                         color='steelblue', alpha=0.7)
            bar2 = ax_twin.bar(x_pos + 0.2, sizes, 0.4, label='Total Size (KB)', 
                              color='coral', alpha=0.7)
            
            ax.set_xlabel('File Descriptor', fontsize=10)
            ax.set_ylabel('Event Count', fontsize=10, color='steelblue')
            ax_twin.set_ylabel('Total Size (KB)', fontsize=10, color='coral')
            ax.set_title(f'{proc_data["name"]} (PID: {pid})', 
                        fontsize=11, fontweight='bold')
            ax.set_xticks(x_pos)
            ax.set_xticklabels(fds, rotation=45, ha='right', fontsize=8)
            ax.tick_params(axis='y', labelcolor='steelblue')
            ax_twin.tick_params(axis='y', labelcolor='coral')
            ax.grid(axis='y', alpha=0.3)
            
            # Combined legend
            lines1, labels1 = ax.get_legend_handles_labels()
            lines2, labels2 = ax_twin.get_legend_handles_labels()
            ax.legend(lines1 + lines2, labels1 + labels2, loc='upper right', fontsize=8)
        
        # Remove empty subplots
        for idx in range(len(top_procs), n_rows * n_cols):
            row = idx // n_cols
            col = idx % n_cols
            fig.delaxes(axes[row][col])
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved FD analysis to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_offset_patterns(self, output_file=None):
        """Plot file offset patterns for sequential vs random I/O"""
        top_procs = self.get_top_processes(6)
        
        n_processes = len(top_procs)
        n_cols = 2
        n_rows = (n_processes + 1) // 2
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 5 * n_rows))
        fig.suptitle('File Offset Access Patterns', fontsize=16, fontweight='bold')
        
        if n_processes == 1:
            axes = [[axes]]
        elif n_rows == 1:
            axes = [axes]
        
        for idx, (pid, proc_data) in enumerate(top_procs):
            row = idx // n_cols
            col = idx % n_cols
            ax = axes[row][col]
            
            # Collect offset data for positioned I/O syscalls
            positioned_io = [e for e in proc_data['events'] 
                           if e['syscall_name'] in ['pread64', 'pwrite64', 'lseek'] 
                           and e.get('offset', 0) != 0]
            
            if not positioned_io:
                ax.text(0.5, 0.5, 'No offset data available', 
                       ha='center', va='center', transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} (PID: {pid})', 
                           fontsize=11, fontweight='bold')
                continue
            
            # Group by FD
            fd_offsets = defaultdict(list)
            for event in positioned_io:
                fd = event.get('fd')
                if fd is not None and fd != 4294967295:
                    timestamp = (event['timestamp_ms'] - positioned_io[0]['timestamp_ms']) / 1000.0
                    fd_offsets[fd].append({
                        'time': timestamp,
                        'offset': event['offset'],
                        'syscall': event['syscall_name']
                    })
            
            # Plot top 5 FDs
            top_fds = sorted(fd_offsets.items(), key=lambda x: len(x[1]), reverse=True)[:5]
            
            colors = plt.cm.tab10(np.linspace(0, 1, len(top_fds)))
            
            for fd_idx, (fd, accesses) in enumerate(top_fds):
                times = [a['time'] for a in accesses]
                offsets = [a['offset'] for a in accesses]
                
                ax.scatter(times, offsets, alpha=0.6, s=30, 
                          label=f'FD {fd} ({len(accesses)} ops)',
                          color=colors[fd_idx])
                
                # Draw lines to show sequential access
                ax.plot(times, offsets, alpha=0.3, linewidth=1, color=colors[fd_idx])
            
            ax.set_xlabel('Time (seconds)', fontsize=10)
            ax.set_ylabel('File Offset (bytes)', fontsize=10)
            ax.set_title(f'{proc_data["name"]} (PID: {pid})\nOffset Access Pattern', 
                        fontsize=11, fontweight='bold')
            ax.legend(fontsize=8, loc='best')
            ax.grid(True, alpha=0.3)
            
            # Use log scale if offsets span multiple orders of magnitude
            if offsets:
                offset_range = max(offsets) - min(offsets)
                if offset_range > 10000:
                    ax.set_yscale('log')
        
        # Remove empty subplots
        for idx in range(len(top_procs), n_rows * n_cols):
            row = idx // n_cols
            col = idx % n_cols
            fig.delaxes(axes[row][col])
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved offset pattern analysis to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_comprehensive_dashboard(self, output_file=None):
        """Create a comprehensive dashboard with multiple visualizations"""
        top_procs = self.get_top_processes(4)
        
        fig = plt.figure(figsize=(20, 12))
        gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.3, wspace=0.3)
        
        fig.suptitle('Syscall Monitor Comprehensive Dashboard', 
                    fontsize=18, fontweight='bold', y=0.995)
        
        # Plot 1: Overall syscall distribution (top-left, spanning 2 cols)
        ax1 = fig.add_subplot(gs[0, :2])
        syscall_counts = defaultdict(int)
        for event in self.events:
            syscall_counts[event['syscall_name']] += 1
        
        sorted_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        syscalls, counts = zip(*sorted_syscalls)
        
        colors_sc = plt.cm.Set3(np.linspace(0, 1, len(syscalls)))
        bars = ax1.barh(syscalls, counts, color=colors_sc, edgecolor='black', linewidth=1)
        ax1.set_xlabel('Count', fontsize=11, fontweight='bold')
        ax1.set_title('Top 10 Syscalls (All Processes)', fontsize=12, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for bar, count in zip(bars, counts):
            ax1.text(bar.get_width(), bar.get_y() + bar.get_height()/2, 
                    f' {count}', va='center', fontsize=9)
        
        # Plot 2: Process activity (top-right)
        ax2 = fig.add_subplot(gs[0, 2])
        proc_events = [(proc_data['name'], len(proc_data['events'])) 
                      for pid, proc_data in self.get_top_processes(8)]
        proc_names, event_counts = zip(*proc_events)
        
        colors_proc = plt.cm.viridis(np.linspace(0, 1, len(proc_names)))
        ax2.pie(event_counts, labels=proc_names, autopct='%1.1f%%',
               colors=colors_proc, startangle=90, textprops={'fontsize': 8})
        ax2.set_title('Process Activity Distribution', fontsize=12, fontweight='bold')
        
        # Plot 3 & 4: Time series for top 2 processes
        for proc_idx in range(min(2, len(top_procs))):
            pid, proc_data = top_procs[proc_idx]
            ax = fig.add_subplot(gs[1, proc_idx])
            
            events = proc_data['events']
            timestamps = [e['timestamp_ms'] for e in events]
            sizes = [e['size'] for e in events]
            
            if timestamps:
                min_ts = min(timestamps)
                timestamps = [(t - min_ts) / 1000.0 for t in timestamps]
            
            ax.scatter(timestamps, sizes, alpha=0.5, s=15, color='darkblue')
            ax.set_xlabel('Time (s)', fontsize=10)
            ax.set_ylabel('I/O Size (bytes)', fontsize=10)
            ax.set_title(f'{proc_data["name"]} (PID: {pid})', fontsize=11, fontweight='bold')
            ax.set_yscale('log')
            ax.grid(True, alpha=0.3)
        
        # Plot 5: I/O size bucket distribution
        ax5 = fig.add_subplot(gs[1, 2])
        
        # Use more granular buckets for dashboard
        bucket_order = ["1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
                       "65-128 B", "129-256 B", "257-512 B", "513-1023 B",
                       "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB",
                       "32-64 KB", "64-128 KB", "128-256 KB"]
        bucket_counts = defaultdict(int)
        
        for event in self.events:
            bucket = self.get_io_size_bucket(event['size'])
            if bucket != "0 B":  # Exclude zero-size operations
                bucket_counts[bucket] += 1
        
        # Filter to top 12 buckets for readability
        sorted_buckets = sorted(bucket_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        buckets = [b[0] for b in sorted_buckets]
        counts = [b[1] for b in sorted_buckets]
        
        if buckets:
            colors_bucket = plt.cm.RdYlGn_r(np.linspace(0.2, 0.9, len(buckets)))
            bars = ax5.bar(range(len(buckets)), counts, color=colors_bucket, edgecolor='black')
            ax5.set_xticks(range(len(buckets)))
            ax5.set_xticklabels(buckets, rotation=45, ha='right', fontsize=7)
            ax5.set_ylabel('Count', fontsize=10)
            ax5.set_title('Top I/O Size Buckets', fontsize=11, fontweight='bold')
            ax5.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars for top 5
            for i, (bar, count) in enumerate(zip(bars[:5], counts[:5])):
                ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                        f'{count}', ha='center', va='bottom', fontsize=7)
        else:
            ax5.text(0.5, 0.5, 'No I/O data', ha='center', va='center',
                    transform=ax5.transAxes)
        
        # Plot 6-8: FD usage for top 3 processes
        for proc_idx in range(min(3, len(top_procs))):
            pid, proc_data = top_procs[proc_idx]
            ax = fig.add_subplot(gs[2, proc_idx])
            
            fd_stats = defaultdict(int)
            for event in proc_data['events']:
                fd = event.get('fd')
                if fd is not None and fd != 4294967295 and fd < 1000:
                    fd_stats[fd] += 1
            
            if fd_stats:
                sorted_fds = sorted(fd_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                fds, counts = zip(*sorted_fds)
                
                colors_fd = plt.cm.plasma(np.linspace(0, 1, len(fds)))
                ax.bar([str(fd) for fd in fds], counts, color=colors_fd, edgecolor='black')
                ax.set_xlabel('File Descriptor', fontsize=10)
                ax.set_ylabel('Operations', fontsize=10)
                ax.set_title(f'{proc_data["name"]} - FD Usage', fontsize=10, fontweight='bold')
                ax.grid(axis='y', alpha=0.3)
                ax.tick_params(axis='x', rotation=45, labelsize=8)
            else:
                ax.text(0.5, 0.5, 'No FD data', ha='center', va='center', 
                       transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} - FD Usage', fontsize=10, fontweight='bold')
        
        # Add metadata text
        metadata_text = f"Total Events: {len(self.events)} | "
        metadata_text += f"Processes: {len(self.processes)} | "
        metadata_text += f"Duration: {self.data['metadata'].get('monitoring_duration', 'N/A')}s"
        fig.text(0.5, 0.01, metadata_text, ha='center', fontsize=10, 
                style='italic', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved comprehensive dashboard to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_syscall_io_distribution(self, output_file=None):
        """Plot I/O size distribution per syscall per process"""
        top_procs = self.get_top_processes(6)
        
        n_processes = len(top_procs)
        n_cols = 2
        n_rows = (n_processes + 1) // 2
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(18, 6 * n_rows))
        fig.suptitle('I/O Size Distribution by Syscall (Per Process)', 
                    fontsize=16, fontweight='bold')
        
        if n_processes == 1:
            axes = [[axes]]
        elif n_rows == 1:
            axes = [axes]
        
        # Define bucket order for this analysis (simplified for readability)
        bucket_order = [
            "1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
            "65-128 B", "129-256 B", "257-512 B", "513-1023 B",
            "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB", "32-64 KB",
            "64-128 KB", "128-256 KB", "256-512 KB", "512KB-1MB",
            "1-2 MB", "2-4 MB", "> 4 MB"
        ]
        
        for idx, (pid, proc_data) in enumerate(top_procs):
            row = idx // n_cols
            col = idx % n_cols
            ax = axes[row][col]
            
            # Collect data: syscall -> bucket -> count
            syscall_bucket_data = defaultdict(lambda: defaultdict(int))
            
            for event in proc_data['events']:
                syscall = event['syscall_name']
                bucket = self.get_io_size_bucket(event['size'])
                if bucket != "0 B":  # Exclude zero-size
                    syscall_bucket_data[syscall][bucket] += 1
            
            if not syscall_bucket_data:
                ax.text(0.5, 0.5, 'No I/O data', ha='center', va='center',
                       transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} (PID: {pid})', 
                           fontsize=11, fontweight='bold')
                continue
            
            # Get unique syscalls and filter to populated buckets
            syscalls = sorted(syscall_bucket_data.keys())
            populated_buckets = []
            for bucket in bucket_order:
                if any(syscall_bucket_data[sc][bucket] > 0 for sc in syscalls):
                    populated_buckets.append(bucket)
            
            # Create matrix for heatmap
            heatmap_data = []
            for syscall in syscalls:
                row_data = [syscall_bucket_data[syscall][bucket] 
                           for bucket in populated_buckets]
                heatmap_data.append(row_data)
            
            if heatmap_data and populated_buckets:
                heatmap_data = np.array(heatmap_data)
                
                # Create heatmap
                im = ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto',
                             interpolation='nearest')
                
                # Set ticks and labels
                ax.set_xticks(np.arange(len(populated_buckets)))
                ax.set_yticks(np.arange(len(syscalls)))
                ax.set_xticklabels(populated_buckets, rotation=45, ha='right', fontsize=7)
                ax.set_yticklabels(syscalls, fontsize=9)
                
                # Add text annotations for significant values
                max_val = heatmap_data.max()
                for i in range(len(syscalls)):
                    for j in range(len(populated_buckets)):
                        value = int(heatmap_data[i, j])
                        if value > 0 and value > max_val * 0.05:  # Show only significant values
                            text_color = "white" if value > max_val * 0.6 else "black"
                            ax.text(j, i, value, ha="center", va="center",
                                  color=text_color, fontsize=6, fontweight='bold')
                
                ax.set_title(f'{proc_data["name"]} (PID: {pid})\n'
                           f'Syscall vs I/O Size Distribution',
                           fontsize=11, fontweight='bold')
                ax.set_xlabel('I/O Size Bucket', fontsize=9)
                ax.set_ylabel('Syscall', fontsize=9)
                
                # Add colorbar
                cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
                cbar.set_label('Count', rotation=270, labelpad=15, fontsize=8)
                cbar.ax.tick_params(labelsize=7)
        
        # Remove empty subplots
        for idx in range(len(top_procs), n_rows * n_cols):
            row = idx // n_cols
            col = idx % n_cols
            fig.delaxes(axes[row][col])
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved syscall I/O distribution to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_syscall_timeseries_per_process(self, output_file=None):
        """Plot syscall time series (count over time) for each process"""
        top_procs = self.get_top_processes(6)
        
        n_processes = len(top_procs)
        n_cols = 2
        n_rows = (n_processes + 1) // 2
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(18, 5 * n_rows))
        fig.suptitle('Syscall Activity Timeline (Per Process)', 
                    fontsize=16, fontweight='bold')
        
        if n_processes == 1:
            axes = [[axes]]
        elif n_rows == 1:
            axes = [axes]
        
        for idx, (pid, proc_data) in enumerate(top_procs):
            row = idx // n_cols
            col = idx % n_cols
            ax = axes[row][col]
            
            events = proc_data['events']
            
            if not events:
                ax.text(0.5, 0.5, 'No events', ha='center', va='center',
                       transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} (PID: {pid})', 
                           fontsize=11, fontweight='bold')
                continue
            
            # Group events by syscall
            syscall_events = defaultdict(list)
            for event in events:
                syscall_events[event['syscall_name']].append(event)
            
            # Normalize timestamps
            min_ts = min(e['timestamp_ms'] for e in events)
            
            # Create time bins (100ms bins)
            max_ts = max(e['timestamp_ms'] for e in events)
            duration_ms = max_ts - min_ts
            n_bins = min(int(duration_ms / 100) + 1, 200)  # Max 200 bins
            
            # Get unique syscalls and assign colors
            unique_syscalls = sorted(syscall_events.keys())
            colors = plt.cm.tab10(np.linspace(0, 1, len(unique_syscalls)))
            syscall_colors = {sc: colors[i] for i, sc in enumerate(unique_syscalls)}
            
            # Plot stacked area chart
            time_bins = np.linspace(0, duration_ms / 1000.0, n_bins)  # Convert to seconds
            bin_width = (duration_ms / 1000.0) / n_bins
            
            # Calculate counts per bin for each syscall
            syscall_counts = {}
            for syscall, sc_events in syscall_events.items():
                counts = np.zeros(n_bins)
                for event in sc_events:
                    time_sec = (event['timestamp_ms'] - min_ts) / 1000.0
                    bin_idx = int(time_sec / bin_width)
                    if bin_idx < n_bins:
                        counts[bin_idx] += 1
                syscall_counts[syscall] = counts
            
            # Stack the areas
            bottom = np.zeros(n_bins)
            for syscall in unique_syscalls:
                counts = syscall_counts[syscall]
                ax.fill_between(time_bins, bottom, bottom + counts,
                               label=syscall, color=syscall_colors[syscall],
                               alpha=0.7, linewidth=0)
                bottom += counts
            
            ax.set_xlabel('Time (seconds)', fontsize=10)
            ax.set_ylabel('Syscall Count per Bin', fontsize=10)
            ax.set_title(f'{proc_data["name"]} (PID: {pid})\n'
                        f'Syscall Activity Over Time',
                        fontsize=11, fontweight='bold')
            ax.legend(fontsize=8, loc='upper left', ncol=2)
            ax.grid(True, alpha=0.3, axis='y')
            ax.set_xlim(0, duration_ms / 1000.0)
        
        # Remove empty subplots
        for idx in range(len(top_procs), n_rows * n_cols):
            row = idx // n_cols
            col = idx % n_cols
            fig.delaxes(axes[row][col])
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved syscall timeline to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_detailed_syscall_analysis(self, output_file=None):
        """Comprehensive syscall analysis: distribution + timeline combined"""
        top_procs = self.get_top_processes(4)
        
        fig = plt.figure(figsize=(20, 14))
        gs = gridspec.GridSpec(4, 2, figure=fig, hspace=0.35, wspace=0.3)
        
        fig.suptitle('Detailed Syscall Analysis by Process', 
                    fontsize=18, fontweight='bold')
        
        bucket_order = [
            "1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
            "65-128 B", "129-256 B", "257-512 B", "513-1023 B",
            "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB", "32-64 KB"
        ]
        
        for proc_idx, (pid, proc_data) in enumerate(top_procs):
            # Left column: Syscall I/O size distribution (heatmap)
            ax_heat = fig.add_subplot(gs[proc_idx, 0])
            
            # Collect syscall -> bucket data
            syscall_bucket_data = defaultdict(lambda: defaultdict(int))
            for event in proc_data['events']:
                syscall = event['syscall_name']
                bucket = self.get_io_size_bucket(event['size'])
                if bucket != "0 B":
                    syscall_bucket_data[syscall][bucket] += 1
            
            if syscall_bucket_data:
                syscalls = sorted(syscall_bucket_data.keys())
                populated_buckets = [b for b in bucket_order 
                                   if any(syscall_bucket_data[sc][b] > 0 for sc in syscalls)]
                
                if populated_buckets:
                    heatmap_data = np.array([[syscall_bucket_data[sc][b] 
                                            for b in populated_buckets] 
                                           for sc in syscalls])
                    
                    im = ax_heat.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
                    ax_heat.set_xticks(np.arange(len(populated_buckets)))
                    ax_heat.set_yticks(np.arange(len(syscalls)))
                    ax_heat.set_xticklabels(populated_buckets, rotation=45, 
                                          ha='right', fontsize=7)
                    ax_heat.set_yticklabels(syscalls, fontsize=8)
                    
                    # Annotations
                    max_val = heatmap_data.max()
                    for i in range(len(syscalls)):
                        for j in range(len(populated_buckets)):
                            value = int(heatmap_data[i, j])
                            if value > max_val * 0.1:
                                color = "white" if value > max_val * 0.6 else "black"
                                ax_heat.text(j, i, value, ha="center", va="center",
                                           color=color, fontsize=6, fontweight='bold')
                    
                    plt.colorbar(im, ax=ax_heat, fraction=0.046, pad=0.04)
            
            ax_heat.set_title(f'{proc_data["name"]} (PID: {pid})\n'
                            f'I/O Size by Syscall',
                            fontsize=10, fontweight='bold')
            ax_heat.set_xlabel('I/O Size', fontsize=9)
            ax_heat.set_ylabel('Syscall', fontsize=9)
            
            # Right column: Syscall timeline
            ax_time = fig.add_subplot(gs[proc_idx, 1])
            
            events = proc_data['events']
            if events:
                syscall_events = defaultdict(list)
                for event in events:
                    syscall_events[event['syscall_name']].append(event)
                
                min_ts = min(e['timestamp_ms'] for e in events)
                max_ts = max(e['timestamp_ms'] for e in events)
                duration_ms = max_ts - min_ts
                
                n_bins = min(int(duration_ms / 100) + 1, 150)
                time_bins = np.linspace(0, duration_ms / 1000.0, n_bins)
                bin_width = (duration_ms / 1000.0) / n_bins
                
                unique_syscalls = sorted(syscall_events.keys())
                colors = plt.cm.tab10(np.linspace(0, 1, len(unique_syscalls)))
                
                bottom = np.zeros(n_bins)
                for sc_idx, syscall in enumerate(unique_syscalls):
                    counts = np.zeros(n_bins)
                    for event in syscall_events[syscall]:
                        time_sec = (event['timestamp_ms'] - min_ts) / 1000.0
                        bin_idx = int(time_sec / bin_width)
                        if bin_idx < n_bins:
                            counts[bin_idx] += 1
                    
                    ax_time.fill_between(time_bins, bottom, bottom + counts,
                                        label=syscall, color=colors[sc_idx],
                                        alpha=0.7)
                    bottom += counts
                
                ax_time.legend(fontsize=7, loc='upper left', ncol=2)
                ax_time.grid(True, alpha=0.3, axis='y')
            
            ax_time.set_title(f'{proc_data["name"]} (PID: {pid})\n'
                            f'Syscall Timeline',
                            fontsize=10, fontweight='bold')
            ax_time.set_xlabel('Time (seconds)', fontsize=9)
            ax_time.set_ylabel('Syscalls per Bin', fontsize=9)
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved detailed syscall analysis to {output_file}")
        else:
            plt.show()
        
        plt.close()
        """Create a comprehensive dashboard with multiple visualizations"""
        top_procs = self.get_top_processes(4)
        
        fig = plt.figure(figsize=(20, 12))
        gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.3, wspace=0.3)
        
        fig.suptitle('Syscall Monitor Comprehensive Dashboard', 
                    fontsize=18, fontweight='bold', y=0.995)
        
        # Plot 1: Overall syscall distribution (top-left, spanning 2 cols)
        ax1 = fig.add_subplot(gs[0, :2])
        syscall_counts = defaultdict(int)
        for event in self.events:
            syscall_counts[event['syscall_name']] += 1
        
        sorted_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        syscalls, counts = zip(*sorted_syscalls)
        
        colors_sc = plt.cm.Set3(np.linspace(0, 1, len(syscalls)))
        bars = ax1.barh(syscalls, counts, color=colors_sc, edgecolor='black', linewidth=1)
        ax1.set_xlabel('Count', fontsize=11, fontweight='bold')
        ax1.set_title('Top 10 Syscalls (All Processes)', fontsize=12, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for bar, count in zip(bars, counts):
            ax1.text(bar.get_width(), bar.get_y() + bar.get_height()/2, 
                    f' {count}', va='center', fontsize=9)
        
        # Plot 2: Process activity (top-right)
        ax2 = fig.add_subplot(gs[0, 2])
        proc_events = [(proc_data['name'], len(proc_data['events'])) 
                      for pid, proc_data in self.get_top_processes(8)]
        proc_names, event_counts = zip(*proc_events)
        
        colors_proc = plt.cm.viridis(np.linspace(0, 1, len(proc_names)))
        ax2.pie(event_counts, labels=proc_names, autopct='%1.1f%%',
               colors=colors_proc, startangle=90, textprops={'fontsize': 8})
        ax2.set_title('Process Activity Distribution', fontsize=12, fontweight='bold')
        
        # Plot 3 & 4: Time series for top 2 processes
        for proc_idx in range(min(2, len(top_procs))):
            pid, proc_data = top_procs[proc_idx]
            ax = fig.add_subplot(gs[1, proc_idx])
            
            events = proc_data['events']
            timestamps = [e['timestamp_ms'] for e in events]
            sizes = [e['size'] for e in events]
            
            if timestamps:
                min_ts = min(timestamps)
                timestamps = [(t - min_ts) / 1000.0 for t in timestamps]
            
            ax.scatter(timestamps, sizes, alpha=0.5, s=15, color='darkblue')
            ax.set_xlabel('Time (s)', fontsize=10)
            ax.set_ylabel('I/O Size (bytes)', fontsize=10)
            ax.set_title(f'{proc_data["name"]} (PID: {pid})', fontsize=11, fontweight='bold')
            ax.set_yscale('log')
            ax.grid(True, alpha=0.3)
        
        # Plot 5: I/O size bucket distribution
        ax5 = fig.add_subplot(gs[1, 2])
        
        # Use more granular buckets for dashboard
        bucket_order = ["1 B", "2-4 B", "5-8 B", "9-16 B", "17-32 B", "33-64 B",
                       "65-128 B", "129-256 B", "257-512 B", "513-1023 B",
                       "1-2 KB", "2-4 KB", "4-8 KB", "8-16 KB", "16-32 KB",
                       "32-64 KB", "64-128 KB", "128-256 KB"]
        bucket_counts = defaultdict(int)
        
        for event in self.events:
            bucket = self.get_io_size_bucket(event['size'])
            if bucket != "0 B":  # Exclude zero-size operations
                bucket_counts[bucket] += 1
        
        # Filter to top 12 buckets for readability
        sorted_buckets = sorted(bucket_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        buckets = [b[0] for b in sorted_buckets]
        counts = [b[1] for b in sorted_buckets]
        
        if buckets:
            colors_bucket = plt.cm.RdYlGn_r(np.linspace(0.2, 0.9, len(buckets)))
            bars = ax5.bar(range(len(buckets)), counts, color=colors_bucket, edgecolor='black')
            ax5.set_xticks(range(len(buckets)))
            ax5.set_xticklabels(buckets, rotation=45, ha='right', fontsize=7)
            ax5.set_ylabel('Count', fontsize=10)
            ax5.set_title('Top I/O Size Buckets', fontsize=11, fontweight='bold')
            ax5.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars for top 5
            for i, (bar, count) in enumerate(zip(bars[:5], counts[:5])):
                ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                        f'{count}', ha='center', va='bottom', fontsize=7)
        else:
            ax5.text(0.5, 0.5, 'No I/O data', ha='center', va='center',
                    transform=ax5.transAxes)
        
        # Plot 6-8: FD usage for top 3 processes
        for proc_idx in range(min(3, len(top_procs))):
            pid, proc_data = top_procs[proc_idx]
            ax = fig.add_subplot(gs[2, proc_idx])
            
            fd_stats = defaultdict(int)
            for event in proc_data['events']:
                fd = event.get('fd')
                if fd is not None and fd != 4294967295 and fd < 1000:
                    fd_stats[fd] += 1
            
            if fd_stats:
                sorted_fds = sorted(fd_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                fds, counts = zip(*sorted_fds)
                
                colors_fd = plt.cm.plasma(np.linspace(0, 1, len(fds)))
                ax.bar([str(fd) for fd in fds], counts, color=colors_fd, edgecolor='black')
                ax.set_xlabel('File Descriptor', fontsize=10)
                ax.set_ylabel('Operations', fontsize=10)
                ax.set_title(f'{proc_data["name"]} - FD Usage', fontsize=10, fontweight='bold')
                ax.grid(axis='y', alpha=0.3)
                ax.tick_params(axis='x', rotation=45, labelsize=8)
            else:
                ax.text(0.5, 0.5, 'No FD data', ha='center', va='center', 
                       transform=ax.transAxes)
                ax.set_title(f'{proc_data["name"]} - FD Usage', fontsize=10, fontweight='bold')
        
        # Add metadata text
        metadata_text = f"Total Events: {len(self.events)} | "
        metadata_text += f"Processes: {len(self.processes)} | "
        metadata_text += f"Duration: {self.data['metadata'].get('monitoring_duration', 'N/A')}s"
        fig.text(0.5, 0.01, metadata_text, ha='center', fontsize=10, 
                style='italic', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Saved comprehensive dashboard to {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def generate_all_plots(self, output_prefix=None):
        """Generate all visualization plots"""
        if output_prefix is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_prefix = f"syscall_viz_{timestamp}"
        
        print(f"\nGenerating visualizations with prefix: {output_prefix}")
        print("=" * 60)
        
        # Generate individual plots
        self.plot_comprehensive_dashboard(f"{output_prefix}_dashboard.png")
        self.plot_process_io_timeseries(f"{output_prefix}_timeseries.png")
        self.plot_io_size_buckets(f"{output_prefix}_size_buckets.png")
        self.plot_fd_analysis(f"{output_prefix}_fd_analysis.png")
        self.plot_offset_patterns(f"{output_prefix}_offset_patterns.png")
        self.plot_syscall_io_distribution(f"{output_prefix}_syscall_io_dist.png")
        self.plot_syscall_timeseries_per_process(f"{output_prefix}_syscall_timeline.png")
        self.plot_detailed_syscall_analysis(f"{output_prefix}_syscall_detailed.png")
        
        print("=" * 60)
        print(f"All visualizations saved with prefix: {output_prefix}")
        print("\nGenerated files:")
        print(f"  - {output_prefix}_dashboard.png (comprehensive overview)")
        print(f"  - {output_prefix}_timeseries.png (I/O time series)")
        print(f"  - {output_prefix}_size_buckets.png (size distribution)")
        print(f"  - {output_prefix}_fd_analysis.png (file descriptor usage)")
        print(f"  - {output_prefix}_offset_patterns.png (access patterns)")
        print(f"  - {output_prefix}_syscall_io_dist.png (syscall I/O size distribution)")
        print(f"  - {output_prefix}_syscall_timeline.png (syscall activity timeline)")
        print(f"  - {output_prefix}_syscall_detailed.png (detailed syscall analysis)")



def main():
    parser = argparse.ArgumentParser(
        description='Visualize syscall monitor JSON output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s syscall_analysis_20250101_120000.json
  %(prog)s data.json --output-prefix my_analysis
  %(prog)s data.json --plot dashboard
  %(prog)s data.json --plot timeseries --output-prefix results
        """
    )
    
    parser.add_argument('json_file', help='JSON file from syscall monitor')
    parser.add_argument('--output-prefix', '-o', help='Output file prefix for saved plots')
    parser.add_argument('--plot', '-p', 
                       choices=['all', 'dashboard', 'timeseries', 'buckets', 'fd', 'offset'],
                       default='all',
                       help='Which plot to generate (default: all)')
    parser.add_argument('--show', '-s', action='store_true',
                       help='Display plots interactively instead of saving')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not Path(args.json_file).exists():
        print(f"Error: File '{args.json_file}' not found")
        sys.exit(1)
    
    # Initialize visualizer
    print(f"Loading data from {args.json_file}...")
    viz = SyscallVisualizer(args.json_file)
    
    # Determine output file prefix
    output_prefix = args.output_prefix
    if not args.show and output_prefix is None:
        # Auto-generate prefix from input filename
        base_name = Path(args.json_file).stem
        output_prefix = f"{base_name}_viz"
    
    # Generate requested plots
    if args.plot == 'all':
        if args.show:
            viz.plot_comprehensive_dashboard()
            viz.plot_process_io_timeseries()
            viz.plot_io_size_buckets()
            viz.plot_fd_analysis()
            viz.plot_offset_patterns()
        else:
            viz.generate_all_plots(output_prefix)
    else:
        output_file = None if args.show else f"{output_prefix}_{args.plot}.png"
        
        if args.plot == 'dashboard':
            viz.plot_comprehensive_dashboard(output_file)
        elif args.plot == 'offset':
            viz.plot_offset_patterns(output_file)
    
    print("\nVisualization complete!")


if __name__ == "__main__":
    main()