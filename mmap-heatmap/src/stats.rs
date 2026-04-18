// SPDX-License-Identifier: copyleft-next-0.3.1
//
// stats.rs — Running percentile statistics
//
// Keeps a Vec<u64> of historical values. Sorts on demand for percentile
// computation. The sort happens once per frame on a typically small vector
// (hundreds to thousands of entries for reasonable sampling intervals).
// Capped at 100,000 entries to prevent unbounded memory growth — when full,
// the oldest half is drained.

/// Maximum number of entries before compaction.
const MAX_ENTRIES: usize = 100_000;

/// Running statistics accumulator.
pub struct RunningStats {
    values: Vec<u64>,
    /// Cached running sum for O(1) average computation.
    cached_sum: u64,
    dirty: bool,
}

impl RunningStats {
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            cached_sum: 0,
            dirty: false,
        }
    }

    pub fn push(&mut self, value: u64) {
        if self.values.len() >= MAX_ENTRIES {
            // Drop the oldest half to bound memory.
            // Recompute the sum from the retained half to stay accurate.
            let half = MAX_ENTRIES / 2;
            let drained_sum: u64 = self.values[..half].iter().sum();
            self.cached_sum -= drained_sum;
            self.values.drain(..half);
        }
        self.cached_sum += value;
        self.values.push(value);
        self.dirty = true;
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Compute a summary snapshot. Only re-sorts when new values have been added.
    pub fn summary(&mut self) -> StatsSummary {
        let n = self.values.len();
        if n == 0 {
            return StatsSummary {
                min: 0,
                p50: 0,
                p95: 0,
                p99: 0,
                max: 0,
                avg: 0,
            };
        }

        if self.dirty {
            self.values.sort_unstable();
            self.dirty = false;
        }

        StatsSummary {
            min: self.values[0],
            p50: self.values[percentile_idx(n, 50)],
            p95: self.values[percentile_idx(n, 95)],
            p99: self.values[percentile_idx(n, 99)],
            max: self.values[n - 1],
            avg: self.cached_sum / n as u64,
        }
    }
}

/// Pre-computed statistics snapshot.
#[derive(Clone, Copy)]
pub struct StatsSummary {
    pub min: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
    pub avg: u64,
}

fn percentile_idx(n: usize, p: usize) -> usize {
    let idx = (p as f64 / 100.0 * n as f64) as usize;
    idx.min(n - 1)
}
