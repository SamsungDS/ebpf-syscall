// SPDX-License-Identifier: copyleft-next-0.3.1
//
// heat.rs — Heat map and frequency map storage with lazy decay
//
// Lazy heat decay: instead of iterating ALL blocks per frame to decay
// their heat, we store the sample number when each block was last touched.
// At render time, we compute:
//
//   effective = stored_heat - decay * (current_sample - last_touched)
//
// This converts O(total_blocks) decay per frame into O(visible_blocks)
// at render time. For a 1 GiB region with 8-byte granularity, that is
// 134 million blocks we never touch unless they are visible.
//
// FreqMap uses a DAMON-style moving-sum algorithm: per-block frequency is
// tracked in basis points (0-10000) with exponential decay applied lazily
// at touch and render time. Like HeatMap, only accessed blocks are updated.

const MAX_HEAT: i32 = 9;

/// Common interface for visualization data sources.
///
/// Both HeatMap and FreqMap implement this trait so render_frame can
/// accept either without knowing the concrete type.
pub trait HeatSource {
    /// Get the effective display value (0-9) for block `idx`.
    fn get(&self, idx: usize, current_sample: u64) -> i32;
    /// Get the maximum display value across a range of blocks.
    fn max_range(&self, start: usize, end: usize, current_sample: u64) -> i32;
    /// Count blocks with non-zero display value.
    fn count_hot(&self, current_sample: u64) -> usize;
    /// Record a write to block `idx` at the given sample number.
    fn touch(&mut self, idx: usize, sample: u64);
}

/// Per-block heat state: stored heat level and the sample when last written.
struct Block {
    heat: i32,
    last_touched: u64,
}

/// Heat map with lazy decay.
///
/// `heat_inc` is the number of writes needed to advance one digit level.
/// Internal heat is stored as raw points (0 to 9*heat_inc). Each write
/// adds 1 point, each idle sample subtracts `decay_rate` points. The
/// display digit is `raw / heat_inc`, clamped to 9.
pub struct HeatMap {
    blocks: Vec<Block>,
    decay_rate: i32,
    heat_inc: i32,
    max_raw: i32,
}

/// Saturate a u64 elapsed value to i32 range to prevent overflow.
fn saturate_elapsed(elapsed: u64) -> i32 {
    elapsed.min(i32::MAX as u64) as i32
}

impl HeatMap {
    /// Create a heat map with `num_blocks` entries.
    ///
    /// `decay_rate` below 0 would cause heat to grow during idle samples
    /// (subtracting a negative value adds), so it is clamped at 0.
    /// `heat_inc` must be at least 1 to avoid a division-by-zero in `get`.
    pub fn new(num_blocks: usize, decay_rate: i32, heat_inc: i32) -> Self {
        let decay_rate = decay_rate.max(0);
        let heat_inc = heat_inc.max(1);
        let blocks = (0..num_blocks)
            .map(|_| Block {
                heat: 0,
                last_touched: 0,
            })
            .collect();
        Self {
            blocks,
            decay_rate,
            heat_inc,
            max_raw: MAX_HEAT.saturating_mul(heat_inc),
        }
    }

    /// Return total number of blocks.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
}

impl HeatSource for HeatMap {
    /// Record a write to block `idx` at the given sample number.
    /// Adds 1 raw point. Needs `heat_inc` points per digit level.
    fn touch(&mut self, idx: usize, sample: u64) {
        if let Some(b) = self.blocks.get_mut(idx) {
            let elapsed = saturate_elapsed(sample.saturating_sub(b.last_touched));
            let effective = (b.heat - self.decay_rate.saturating_mul(elapsed)).max(0);
            b.heat = (effective + 1).min(self.max_raw);
            b.last_touched = sample;
        }
    }

    /// Get the effective heat at render time for block `idx`.
    ///
    /// Lazy decay: no iteration over untouched blocks.
    fn get(&self, idx: usize, current_sample: u64) -> i32 {
        match self.blocks.get(idx) {
            Some(b) => {
                let elapsed = saturate_elapsed(current_sample.saturating_sub(b.last_touched));
                let raw = (b.heat - self.decay_rate.saturating_mul(elapsed)).max(0);
                (raw / self.heat_inc).min(MAX_HEAT)
            }
            None => 0,
        }
    }

    /// Get the maximum effective heat across a range of fine-granularity blocks
    /// that map to a coarser block.
    ///
    /// Used when aggregating fine (8-byte) heat into zoom granularity.
    fn max_range(&self, start: usize, end: usize, current_sample: u64) -> i32 {
        let end = end.min(self.blocks.len());
        let mut max_h = 0i32;
        for idx in start..end {
            let h = self.get(idx, current_sample);
            if h > max_h {
                max_h = h;
                if max_h == MAX_HEAT {
                    break; // Cannot go higher.
                }
            }
        }
        max_h
    }

    /// Return the number of blocks with non-zero effective heat.
    fn count_hot(&self, current_sample: u64) -> usize {
        self.blocks
            .iter()
            .filter(|b| {
                let elapsed = saturate_elapsed(current_sample.saturating_sub(b.last_touched));
                (b.heat - self.decay_rate.saturating_mul(elapsed)) > 0
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// FreqMap — DAMON-style moving-sum frequency tracker
// ---------------------------------------------------------------------------

/// Per-block frequency state tracked in basis points (0-10000).
struct FreqBlock {
    freq_bp: u32,
    last_sample: u64,
}

/// Frequency map using DAMON moving-sum algorithm with lazy decay.
///
/// Each touch adds `10000 / window_size` basis points. Between touches,
/// each idle sample decays freq_bp by `freq_bp / window_size`. Both
/// operations are applied lazily — decay is computed from elapsed samples
/// only when a block is touched or rendered, not per-sample globally.
pub struct FreqMap {
    blocks: Vec<FreqBlock>,
    window: u32,
    decay_rate: u32,
}

impl FreqMap {
    /// Create a frequency map with `num_blocks` entries.
    ///
    /// `decay_rate` is a multiplier on the per-sample decay. With
    /// `decay_rate=1` (the default), each idle sample decays by
    /// `freq_bp / window` — identical to the plain DAMON moving-sum.
    /// With `decay_rate=2`, blocks fade twice as fast. With
    /// `decay_rate=0`, blocks never decay (accumulate forever).
    pub fn new(num_blocks: usize, window: u32, decay_rate: u32) -> Self {
        let blocks = (0..num_blocks)
            .map(|_| FreqBlock {
                freq_bp: 0,
                last_sample: 0,
            })
            .collect();
        Self { blocks, window, decay_rate }
    }

    /// Apply decay for `elapsed` idle samples.
    ///
    /// Each idle sample decays by `decay_rate * freq_bp / window`. For
    /// large elapsed values, the value fully decays to 0. With
    /// `decay_rate=0`, no decay is applied (blocks accumulate forever).
    fn decay(freq_bp: u32, elapsed: u64, window: u32, decay_rate: u32) -> u32 {
        if elapsed == 0 || decay_rate == 0 {
            return freq_bp;
        }
        // With decay_rate multiplier, effective full-decay happens in
        // approximately window/decay_rate samples.
        let effective_elapsed = elapsed.saturating_mul(u64::from(decay_rate));
        if effective_elapsed >= u64::from(window) {
            return 0;
        }
        let mut val = freq_bp;
        // Apply multiplicative decay: each idle sample subtracts
        // decay_rate * val / window from val. For small elapsed counts,
        // iterate. For larger counts, the geometric series converges
        // quickly to 0.
        let w = window;
        for _ in 0..elapsed {
            let step = val / w * decay_rate + val % w * decay_rate / w;
            if step >= val {
                return 0;
            }
            val -= step;
            if val == 0 {
                break;
            }
        }
        val
    }
}

impl HeatSource for FreqMap {
    fn touch(&mut self, idx: usize, sample: u64) {
        if let Some(b) = self.blocks.get_mut(idx) {
            let elapsed = sample.saturating_sub(b.last_sample);
            b.freq_bp = Self::decay(b.freq_bp, elapsed, self.window, self.decay_rate);
            b.freq_bp = b.freq_bp.saturating_add(10000 / self.window);
            if b.freq_bp > 10000 {
                b.freq_bp = 10000;
            }
            b.last_sample = sample;
        }
    }

    fn get(&self, idx: usize, current_sample: u64) -> i32 {
        match self.blocks.get(idx) {
            Some(b) => {
                let elapsed = current_sample.saturating_sub(b.last_sample);
                let decayed = Self::decay(b.freq_bp, elapsed, self.window, self.decay_rate);
                if decayed == 0 {
                    return 0;
                }
                // Map 1-10000 basis points to 1-9 display range.
                // Any non-zero frequency shows as at least digit 1.
                let level = (u64::from(decayed) * 8 / 10000 + 1) as i32;
                level.min(MAX_HEAT)
            }
            None => 0,
        }
    }

    fn max_range(&self, start: usize, end: usize, current_sample: u64) -> i32 {
        let end = end.min(self.blocks.len());
        let mut max_h = 0i32;
        for idx in start..end {
            let h = self.get(idx, current_sample);
            if h > max_h {
                max_h = h;
                if max_h == MAX_HEAT {
                    break;
                }
            }
        }
        max_h
    }

    fn count_hot(&self, current_sample: u64) -> usize {
        self.blocks
            .iter()
            .filter(|b| {
                let elapsed = current_sample.saturating_sub(b.last_sample);
                Self::decay(b.freq_bp, elapsed, self.window, self.decay_rate) > 0
            })
            .count()
    }
}
