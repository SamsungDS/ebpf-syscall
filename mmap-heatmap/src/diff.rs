// SPDX-License-Identifier: copyleft-next-0.3.1
//
// diff.rs — Shadow buffer + 8-byte u64 diff engine
//
// The diff compares 8-byte blocks as u64 values. A single u64 comparison
// is one CPU instruction per block. The compiler auto-vectorizes the inner
// loop — no explicit SIMD needed.
//
// The fine_changed bitmap has one entry per 8-byte word in the entire region.
// Only dirty pages (identified via soft-dirty pagemap bits) are processed,
// keeping the hot path proportional to the number of dirty pages, not the
// total region size.

use crate::consts::{PAGE_SIZE_USIZE, WORD_SIZE};

/// Diff engine that maintains a shadow buffer and per-word change bitmap.
pub struct DiffEngine {
    /// Shadow copy of the entire monitored region.
    pub shadow: Vec<u8>,
    /// One u8 per 8-byte word. 1 = changed this sample, 0 = unchanged.
    /// Using u8 instead of bool allows fill(0) to lower to memset.
    /// Zeroed at the start of each sample, only dirty pages are scanned.
    pub fine_changed: Vec<u8>,
    /// Region start virtual address.
    region_start: u64,
    /// Total region size in bytes.
    region_size: u64,
}

impl DiffEngine {
    /// Create a new diff engine from an initial shadow snapshot.
    pub fn new(shadow: Vec<u8>, region_start: u64) -> Self {
        let region_size = shadow.len() as u64;
        let num_words = shadow.len() / WORD_SIZE;
        Self {
            shadow,
            fine_changed: vec![0u8; num_words],
            region_start,
            region_size,
        }
    }

    /// Reset the fine_changed bitmap for a new sample.
    pub fn reset_changed(&mut self) {
        self.fine_changed.fill(0);
    }

    /// Diff a contiguous run of pages against the shadow buffer.
    ///
    /// `page_data` contains `num_pages` worth of data read from /proc/PID/mem.
    /// `page_addr` is the virtual address of the first page.
    ///
    /// Compares 8-byte blocks as u64 values. Each comparison is a single CPU
    /// instruction — the compiler auto-vectorizes the loop when the data is
    /// aligned. Updates shadow in-place and marks changed words in fine_changed.
    ///
    /// Returns the number of 8-byte words that changed.
    pub fn diff_pages(&mut self, page_addr: u64, page_data: &[u8], num_pages: usize) -> u64 {
        let page_offset = (page_addr - self.region_start) as usize;
        let total_bytes = num_pages * PAGE_SIZE_USIZE;
        let mut words_changed: u64 = 0;

        // Safety bounds check.
        if page_offset + total_bytes > self.region_size as usize {
            return 0;
        }
        if page_data.len() < total_bytes {
            return 0;
        }

        let first_word = page_offset / WORD_SIZE;

        // Compare as u64 words using chunks_exact for better vectorization.
        let shadow_slice = &self.shadow[page_offset..page_offset + total_bytes];
        let data_slice = &page_data[..total_bytes];
        let changed_slice = &mut self.fine_changed[first_word..first_word + total_bytes / WORD_SIZE];

        for ((s_chunk, d_chunk), changed) in shadow_slice
            .chunks_exact(WORD_SIZE)
            .zip(data_slice.chunks_exact(WORD_SIZE))
            .zip(changed_slice.iter_mut())
        {
            let old = u64::from_ne_bytes(s_chunk.try_into().unwrap());
            let new_val = u64::from_ne_bytes(d_chunk.try_into().unwrap());
            if old != new_val {
                *changed = 1;
                words_changed += 1;
            }
        }

        // Bulk update shadow buffer with new data.
        self.shadow[page_offset..page_offset + total_bytes]
            .copy_from_slice(&page_data[..total_bytes]);

        words_changed
    }
}
