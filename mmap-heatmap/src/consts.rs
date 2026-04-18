// SPDX-License-Identifier: copyleft-next-0.3.1
//
// consts.rs — Shared constants

#[cfg(not(target_pointer_width = "64"))]
compile_error!("mmap-heatmap requires a 64-bit target");

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;
pub const WORD_SIZE: usize = 8;
pub const FINEST: u64 = 8;
pub const PAGEMAP_ENTRY_SIZE: u64 = 8;
pub const DEFAULT_WINDOW: u32 = 20;
