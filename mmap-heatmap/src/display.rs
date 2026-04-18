// SPDX-License-Identifier: copyleft-next-0.3.1
//
// display.rs — ANSI frame rendering (overview + zoom panes)
//
// No ratatui/crossterm: the UI is a grid of colored digits (0-9).
// Raw ANSI escape codes are simpler, faster, and avoid 15+ transitive
// dependencies for something that is fundamentally just printf with colors.

use std::fmt::Write as _;

use crate::consts::{FINEST, PAGE_SIZE};
use crate::heat::HeatSource;
use crate::stats::StatsSummary;

// ANSI escape sequences.
const CLEAR_BELOW: &str = "\x1b[J";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const REVERSE: &str = "\x1b[7m";
const RESET: &str = "\x1b[0m";

/// 256-color ANSI codes for heat levels 0-9.
/// dark blue(0) -> blue -> cyan -> green -> yellow -> orange -> red -> bold red(9)
const HEAT_COLORS: [&str; 10] = [
    "\x1b[38;5;17m",     // 0: dark blue
    "\x1b[38;5;27m",     // 1: blue
    "\x1b[38;5;39m",     // 2: light blue
    "\x1b[38;5;49m",     // 3: cyan-green
    "\x1b[38;5;46m",     // 4: green
    "\x1b[38;5;226m",    // 5: yellow
    "\x1b[38;5;214m",    // 6: orange
    "\x1b[38;5;202m",    // 7: dark orange
    "\x1b[38;5;196m",    // 8: red
    "\x1b[1;38;5;196m",  // 9: bold red
];

pub const ZOOM_LEVELS: [u64; 5] = [4096, 512, 128, 64, 8];

/// Append a colored heat digit to the buffer.
fn push_heat_char(buf: &mut String, heat: i32) {
    let h = heat.clamp(0, 9) as usize;
    buf.push_str(HEAT_COLORS[h]);
    buf.push((b'0' + h as u8) as char);
    buf.push_str(RESET);
}

/// Format a byte size for display.
pub fn format_size(size: u64) -> String {
    if size >= 1_048_576 {
        format!("{:.1} MiB", size as f64 / 1_048_576.0)
    } else if size >= 1024 {
        format!("{} KiB", size / 1024)
    } else {
        format!("{} B", size)
    }
}

/// Terminal dimensions.
pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
}

/// Get terminal size using ioctl TIOCGWINSZ.
/// Tries stdout, then stderr, then stdin — one of them should be a TTY.
/// Falls back to /dev/tty when all standard fds are redirected.
pub fn get_term_size() -> TermSize {
    for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO, libc::STDIN_FILENO] {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
        if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return TermSize { cols: ws.ws_col, rows: ws.ws_row };
        }
    }
    // Also try opening /dev/tty directly (works even when stdio is redirected).
    let tty = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDONLY) };
    if tty >= 0 {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::ioctl(tty, libc::TIOCGWINSZ, &mut ws) };
        unsafe { libc::close(tty); }
        if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return TermSize { cols: ws.ws_col, rows: ws.ws_row };
        }
    }
    TermSize { cols: 80, rows: 40 }
}

/// Zoom navigation state.
pub struct ZoomState {
    /// Index into ZOOM_LEVELS.
    pub gran_idx: usize,
    /// Byte offset of zoom window start within the region.
    pub offset: u64,
    /// Reusable buffer for zoom heat values, avoiding per-frame allocation.
    zoom_values: Vec<i32>,
    /// Whether cursor inspection mode is active.
    pub cursor_mode: bool,
    /// Cursor column within the zoom pane (0-based).
    pub cursor_col: usize,
    /// Cursor row within the zoom pane (0-based).
    pub cursor_row: usize,
    /// Actual zoom rows rendered in the last frame (set by render_frame).
    /// Used by main loop for accurate cursor bounds instead of estimation.
    pub last_zoom_rows: usize,
}

impl ZoomState {
    pub fn new() -> Self {
        Self {
            gran_idx: 1, // Start at 512B
            offset: 0,
            zoom_values: Vec::new(),
            cursor_mode: false,
            cursor_col: 0,
            cursor_row: 0,
            last_zoom_rows: 1,
        }
    }

    pub fn granularity(&self) -> u64 {
        ZOOM_LEVELS[self.gran_idx]
    }

    /// Clamp offset to valid range.
    pub fn clamp(&mut self, region_size: u64, window_bytes: u64) {
        let gran = self.granularity();
        if region_size <= window_bytes {
            self.offset = 0;
        } else {
            self.offset = self.offset.min(region_size - window_bytes);
        }
        // Align to granularity.
        self.offset = (self.offset / gran) * gran;
    }

    /// Compute the byte offset within the region that the cursor points at.
    pub fn cursor_byte_offset(&self, map_cols: usize) -> u64 {
        let gran = self.granularity();
        self.offset + (self.cursor_row * map_cols + self.cursor_col) as u64 * gran
    }

    /// Recompute cursor_col and cursor_row from a byte offset at the current
    /// granularity. The caller must ensure `byte_offset >= self.offset`.
    pub fn set_cursor_from_byte_offset(&mut self, byte_offset: u64, map_cols: usize) {
        let gran = self.granularity();
        let block_within_window = ((byte_offset.saturating_sub(self.offset)) / gran) as usize;
        self.cursor_row = block_within_window / map_cols;
        self.cursor_col = block_within_window % map_cols;
    }

    pub fn zoom_in(&mut self) {
        if self.gran_idx < ZOOM_LEVELS.len() - 1 {
            self.gran_idx += 1;
        }
    }

    pub fn zoom_out(&mut self) {
        if self.gran_idx > 0 {
            self.gran_idx -= 1;
        }
    }
}

/// Visualization mode selector.
#[derive(Clone, Copy, PartialEq)]
pub enum VizMode {
    Heat,
    Freq,
}

/// Static region info passed to render_frame, avoiding repetition.
pub struct RegionInfo<'a> {
    pub pid: u32,
    pub file_name: &'a str,
    pub perms: &'a str,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub num_pages: u64,
    pub interval: f64,
    pub decay: i32,
    pub heat_inc: i32,
    pub mode: VizMode,
    pub window: u32,
    pub paused: bool,
    /// True when the target process has exited. The display freezes (same
    /// as pause) and a persistent [EXITED] tag appears in the header so
    /// the user knows the picture no longer reflects live activity.
    pub exited: bool,
}

/// Build a complete display frame into `buf` using absolute cursor positioning.
///
/// Each line is rendered by first emitting `\x1b[row;1H\x1b[K` (move cursor to
/// an absolute row, clear the line) and then writing the line content. This
/// replaces an earlier approach that used `\x1b[H` (cursor home) followed by
/// newline characters to advance rows sequentially.
///
/// The newline-based approach had a rendering bug: the first line of the TUI
/// (the "mmap-heatmap PID..." header) was written to the terminal but invisible.
/// Only the second line appeared as the topmost visible line. The bug was
/// confirmed via asciinema recording — data was being written at position (1,1)
/// but was not visible. The following did NOT fix it:
///   - Using `\x1b[1;1H` instead of `\x1b[H` (explicit row;col vs. implicit)
///   - Removing the DECSTBM scroll region `\x1b[1;Nr`
///   - Removing all eprintln! output before alt screen entry
///
/// Root cause: some terminal emulators (specifically xterm-256color under certain
/// conditions with the alternate screen buffer `\x1b[?1049h`) have an off-by-one
/// behavior where cursor home plus newline-based row advancement places the first
/// line at a position above the visible viewport, or the alt screen initial cursor
/// sits at row 0 rather than row 1.
///
/// The fix is absolute cursor positioning per line (`\x1b[row;1H`), which is the
/// same approach ncurses uses internally. Absolute positioning is more reliable
/// than relative cursor movement across terminal emulator implementations.
#[allow(clippy::too_many_arguments, unused_assignments)]
pub fn render_frame(
    buf: &mut String,
    ri: &RegionInfo,
    sample: u64,
    dirty_count: u64,
    bytes_changed: u64,
    pages_stats: &StatsSummary,
    bytes_stats: &StatsSummary,
    source_4k: &dyn HeatSource,
    source_fine: &dyn HeatSource,
    zoom: &mut ZoomState,
    term: &TermSize,
) {
    let region_size = ri.size;
    let num_pages = ri.num_pages;
    let max_rows = term.rows as usize;

    buf.clear();

    let label_width: usize = 14; // "+  XXXX KiB  " plus 1 safety margin
    let map_cols = (term.cols as usize).saturating_sub(label_width).max(20);

    // Use absolute cursor positioning for each line: \x1b[row;1H
    // This avoids any cursor offset bugs from alt screen entry.
    let mut cur_row: usize = 0; // next row to write (0-based internally, 1-based in escapes)

    // Begin a new line: move cursor to the next absolute row and clear it.
    // Uses \x1b[row;1H (absolute positioning) instead of \n (relative movement)
    // because newline-based advancement is unreliable on certain terminal
    // emulators when writing to the alternate screen buffer — the first line
    // can end up at an invisible row above the viewport. Absolute positioning
    // guarantees each line appears at its intended row. See render_frame docs.
    macro_rules! begin_line {
        ($buf:expr) => {{
            cur_row += 1;
            // write!() into the existing String avoids the per-call
            // allocation that format!() would perform. This macro runs
            // 30-80 times per frame on a typical terminal.
            let _ = write!($buf, "\x1b[{};1H\x1b[K", cur_row);
        }};
    }
    // Begin a line and return false if we've exceeded terminal height.
    macro_rules! begin_line_check {
        ($buf:expr) => {{
            begin_line!($buf);
            cur_row < max_rows
        }};
    }

    // Column width for stats alignment.
    let cw = format!("{}", num_pages)
        .len()
        .max(format_size(region_size).len());

    // Header: position BEFORE content on each line.
    let mode_tag = match ri.mode {
        VizMode::Freq => "[freq]",
        VizMode::Heat => "[heat]",
    };
    begin_line!(buf);
    // [EXITED] takes precedence over [PAUSED] — if the process is gone, the
    // freeze is permanent and the pause flag is irrelevant to the user.
    let status_tag = if ri.exited {
        "  \x1b[1;31m[EXITED]\x1b[0m"
    } else if ri.paused {
        "  \x1b[1;31m[PAUSED]\x1b[0m"
    } else {
        ""
    };
    buf.push_str(&format!(
        "mmap-heatmap  PID {}  {}  {}  {} interval {}s{}",
        ri.pid, ri.file_name, format_size(region_size), mode_tag, ri.interval, status_tag
    ));

    begin_line!(buf);
    buf.push_str(&format!(
        "  addr: 0x{:x} - 0x{:x}  {}  {} pages  perms: {}",
        ri.start, ri.end, format_size(region_size), num_pages, ri.perms
    ));

    let ts = current_time_str();
    begin_line!(buf);
    buf.push_str(&format!(
        "[{}] sample {:>8}:  dirty pages {:>cw$}  changed {:>cw$}",
        ts,
        sample,
        dirty_count,
        format_size(bytes_changed),
        cw = cw,
    ));

    begin_line!(buf);
    buf.push_str(&format!(
        "  pages  min {:>cw$}  p50 {:>cw$}  p95 {:>cw$}  p99 {:>cw$}  max {:>cw$}  avg {:>cw$}",
        pages_stats.min,
        pages_stats.p50,
        pages_stats.p95,
        pages_stats.p99,
        pages_stats.max,
        pages_stats.avg,
        cw = cw,
    ));

    begin_line!(buf);
    buf.push_str(&format!(
        "  bytes  min {:>cw$}  p50 {:>cw$}  p95 {:>cw$}  p99 {:>cw$}  max {:>cw$}  avg {:>cw$}",
        format_size(bytes_stats.min),
        format_size(bytes_stats.p50),
        format_size(bytes_stats.p95),
        format_size(bytes_stats.p99),
        format_size(bytes_stats.max),
        format_size(bytes_stats.avg),
        cw = cw,
    ));

    begin_line!(buf);
    buf.push_str("  ");
    for h in 0..10 {
        push_heat_char(buf, h);
    }
    match ri.mode {
        VizMode::Heat => {
            if ri.decay > 0 {
                buf.push_str(&format!(
                    "  heat: {} writes/level, -{}/idle",
                    ri.heat_inc, ri.decay
                ));
            } else {
                buf.push_str(&format!(
                    "  heat: {} writes/level, no decay",
                    ri.heat_inc
                ));
            }
        }
        VizMode::Freq => {
            if ri.decay != 1 {
                buf.push_str(&format!(
                    "  freq: window {} samples, decay {}x, 0=idle 9=every",
                    ri.window, ri.decay
                ));
            } else {
                buf.push_str(&format!(
                    "  freq: last {} samples, 0=idle 9=every",
                    ri.window
                ));
            }
        }
    }

    begin_line!(buf); // blank line

    // === Overview pane: full region at 4 KiB ===
    let overview_hot = source_4k.count_hot(sample);
    let pages_w = format!("{}", num_pages).len();
    begin_line!(buf);
    buf.push_str(&format!(
        "{}=== Overview: 4 KiB  ({:>w$}/{} hot) ==={}",
        BOLD, overview_hot, num_pages, RESET, w = pages_w
    ));

    // Compute the zoom pane geometry up front so the overview highlight and
    // the actual zoom rendering agree on the same byte range. Previously the
    // highlight used a heuristic (rows-20)/2 that drifted from the real zoom
    // area, so the underlined pages in the overview did not match what the
    // zoom pane actually displayed.
    let zoom_gran = zoom.granularity();
    let help_reserve = if zoom.cursor_mode { 4 } else { 3 };
    // Reserve: header(1) + at least 3 overview rows + blank(1) + zoom header(1)
    //          + help_reserve lines below the zoom pane.
    let min_zoom_lines = 2 + help_reserve;
    let max_overview_rows = max_rows.saturating_sub(cur_row + min_zoom_lines);

    // Provisional zoom_rows estimate: the true value depends on how many
    // overview rows render, which depends on num_pages, which is capped by
    // max_overview_rows above. Compute a conservative lower bound so the
    // highlight undershoots rather than overshoots on very small terminals.
    let overview_row_guess = max_overview_rows
        .min(num_pages.div_ceil(map_cols as u64) as usize);
    let zoom_rows_guess = max_rows
        .saturating_sub(cur_row + overview_row_guess + 2 + help_reserve)
        .max(1);
    let zoom_window_blocks = (zoom_rows_guess as u64) * (map_cols as u64);
    let zoom_window_bytes = zoom_window_blocks * zoom_gran;
    let zoom_start_page = zoom.offset / PAGE_SIZE;
    let zoom_end_byte = (zoom.offset + zoom_window_bytes).min(region_size);
    let zoom_end_page = zoom_end_byte.div_ceil(PAGE_SIZE).min(num_pages);

    // In cursor mode, compute which page the cursor points at for
    // highlighting in the overview. This shows the user which page
    // they are inspecting as they navigate sub-page blocks.
    let cursor_page = if zoom.cursor_mode {
        Some(zoom.cursor_byte_offset(map_cols) / PAGE_SIZE)
    } else {
        None
    };

    let mut overview_lines = 0;
    let mut p = 0u64;
    while p < num_pages && overview_lines < max_overview_rows {
        let row_end = (p + map_cols as u64).min(num_pages);
        let offset_bytes = p * PAGE_SIZE;

        if !begin_line_check!(buf) { break; }
        let _ = write!(buf, "+{:>6} KiB  ", offset_bytes / 1024);

        for i in p..row_end {
            let is_cursor_page = cursor_page == Some(i);
            let in_zoom_window = i >= zoom_start_page && i < zoom_end_page;

            if is_cursor_page {
                // Bright white background, black text — cursor page.
                let val = source_4k.get(i as usize, sample).clamp(0, 9);
                buf.push_str("\x1b[1;30;47m");
                buf.push((b'0' + val as u8) as char);
                buf.push_str(RESET);
            } else if in_zoom_window {
                // Underline — zoom window range. Applied per-character
                // because push_heat_char emits RESET after each digit.
                let val = source_4k.get(i as usize, sample).clamp(0, 9);
                let color = HEAT_COLORS[val as usize];
                buf.push_str("\x1b[4m"); // underline
                buf.push_str(color);
                buf.push((b'0' + val as u8) as char);
                buf.push_str(RESET);
            } else {
                push_heat_char(buf, source_4k.get(i as usize, sample));
            }
        }
        overview_lines += 1;
        p = row_end;
    }
    begin_line!(buf); // blank line

    // === Zoom pane ===
    let blocks_per_fine = (zoom_gran / FINEST) as usize;
    let total_zoom_blocks = region_size / zoom_gran;
    let zoom_start_block = zoom.offset / zoom_gran;

    // Fill remaining terminal rows with zoom. help_reserve was computed
    // earlier alongside the overview highlight calculation.
    let zoom_rows = max_rows.saturating_sub(cur_row + help_reserve).max(1);
    zoom.last_zoom_rows = zoom_rows;
    let zoom_visible_blocks = (zoom_rows * map_cols) as u64;
    let zoom_end_block = (zoom_start_block + zoom_visible_blocks).min(total_zoom_blocks);

    // Aggregate fine heat into zoom granularity, reusing the buffer.
    let zoom_values_count = (zoom_end_block - zoom_start_block) as usize;
    zoom.zoom_values.clear();
    zoom.zoom_values.reserve(zoom_values_count);
    for b in zoom_start_block..zoom_end_block {
        let fine_start = (b as usize) * blocks_per_fine;
        let fine_end = fine_start + blocks_per_fine;
        zoom.zoom_values
            .push(source_fine.max_range(fine_start, fine_end, sample));
    }

    let zoom_hot = zoom.zoom_values.iter().filter(|&&h| h > 0).count();
    let zoom_range_start = zoom.offset;
    let zoom_range_end = (zoom.offset + zoom_visible_blocks * zoom_gran).min(region_size);

    let max_zoom_blocks = region_size / zoom_gran;
    let max_blk_w = format!("{}", max_zoom_blocks).len();
    let max_off_w = format_with_commas(region_size).len();

    begin_line!(buf);
    buf.push_str(&format!(
        "{}=== Zoom: {}  ({:>w_blk$} hot)  +{:>w_off$} B - +{:>w_off$} B  ({} window) ==={}",
        BOLD,
        format_size(zoom_gran),
        zoom_hot,
        format_with_commas(zoom_range_start),
        format_with_commas(zoom_range_end),
        format_size(zoom_range_end - zoom_range_start),
        RESET,
        w_blk = max_blk_w,
        w_off = max_off_w,
    ));

    // In cursor mode, precompute the page range for the cursor block so
    // we can highlight all sibling blocks within the same 4K page.
    // Three visual levels:
    //   1. Cursor block:  bright white bg, black text (most prominent)
    //   2. Page siblings: dark gray bg with heat color (subtle)
    //   3. Normal:        just the heat color
    let cursor_page_start_byte: u64;
    let cursor_page_end_byte: u64;
    if zoom.cursor_mode {
        let co = zoom.cursor_byte_offset(map_cols);
        cursor_page_start_byte = (co / PAGE_SIZE) * PAGE_SIZE;
        cursor_page_end_byte = cursor_page_start_byte + PAGE_SIZE;
    } else {
        cursor_page_start_byte = u64::MAX;
        cursor_page_end_byte = u64::MAX;
    }

    let mut zoom_lines_rendered = 0;
    for row in 0..zoom_rows {
        let blk_start = row * map_cols;
        let blk_end_row = (blk_start + map_cols).min(zoom.zoom_values.len());
        if blk_start >= zoom.zoom_values.len() {
            break;
        }

        let offset_bytes = zoom.offset + (blk_start as u64) * zoom_gran;

        begin_line!(buf);
        if zoom_gran >= 1024 {
            let _ = write!(buf, "+{:>6} KiB  ", offset_bytes / 1024);
        } else {
            let _ = write!(buf, "+{:>8} B  ", offset_bytes);
        }

        for i in blk_start..blk_end_row {
            let col = i - blk_start;
            let is_cursor = zoom.cursor_mode && row == zoom.cursor_row && col == zoom.cursor_col;
            let block_byte = zoom.offset + (i as u64) * zoom_gran;
            let is_same_page = zoom.cursor_mode
                && block_byte >= cursor_page_start_byte
                && block_byte < cursor_page_end_byte;

            let val = zoom.zoom_values[i].clamp(0, 9);
            if is_cursor {
                // Level 1: bright white bg, black text.
                buf.push_str("\x1b[1;30;47m");
                buf.push((b'0' + val as u8) as char);
                buf.push_str(RESET);
            } else if is_same_page {
                // Level 2: dark gray bg with heat color.
                let color = HEAT_COLORS[val as usize];
                buf.push_str("\x1b[48;5;236m"); // dark gray background
                buf.push_str(color);
                buf.push((b'0' + val as u8) as char);
                buf.push_str(RESET);
            } else {
                push_heat_char(buf, zoom.zoom_values[i]);
            }
        }
        zoom_lines_rendered += 1;
    }

    // Fill remaining zoom rows with blank lines to prevent jitter.
    for _ in zoom_lines_rendered..zoom_rows {
        begin_line!(buf);
    }

    // Cursor status line (only in cursor mode).
    if zoom.cursor_mode {
        let cursor_offset = zoom.cursor_byte_offset(map_cols);
        let page_idx = cursor_offset / PAGE_SIZE;
        let offset_in_page = cursor_offset % PAGE_SIZE;

        // Block indices: global (within-page / total-in-page)
        let blk_512 = cursor_offset / 512;
        let blk_512_in_page = offset_in_page / 512;
        let blk_64 = cursor_offset / 64;
        let blk_64_in_page = offset_in_page / 64;
        let blk_8 = cursor_offset / 8;
        let blk_8_in_page = offset_in_page / 8;

        // Look up the heat value for the block under the cursor.
        let cursor_block = (cursor_offset / zoom_gran) as usize;
        let cursor_local = cursor_block.saturating_sub(zoom_start_block as usize);
        let cursor_val = zoom.zoom_values.get(cursor_local).copied().unwrap_or(0);
        // Fixed-width fields based on region size to prevent jitter.
        let max_offset_w = format_with_commas(region_size).len();
        let max_page_w = format!("{}", num_pages.saturating_sub(1)).len();
        let max_512_w = format!("{}", (region_size / 512).saturating_sub(1)).len();
        let max_64_w = format!("{}", (region_size / 64).saturating_sub(1)).len();
        let max_8_w = format!("{}", (region_size / 8).saturating_sub(1)).len();

        begin_line!(buf);
        buf.push_str(&format!(
            "  +{:>w_off$} B  page {:>w_pg$}  512B:{:>w_512$} ({}/8)  64B:{:>w_64$} ({:>2}/64)  8B:{:>w_8$} ({:>3}/512)  val:{}",
            format_with_commas(cursor_offset),
            page_idx,
            blk_512, blk_512_in_page,
            blk_64, blk_64_in_page,
            blk_8, blk_8_in_page,
            cursor_val,
            w_off = max_offset_w,
            w_pg = max_page_w,
            w_512 = max_512_w,
            w_64 = max_64_w,
            w_8 = max_8_w,
        ));
    }

    begin_line!(buf); // blank line before help
    begin_line!(buf);
    if zoom.cursor_mode {
        buf.push_str(&format!(
            "{}  {}[CURSOR]{}  h/l/j/k: move  n/N: next/prev page  +/-: gran ({})  g/G: start/end  c: exit  q: quit{}",
            DIM,
            REVERSE,
            RESET,  // close reverse
            format_size(zoom_gran),
            RESET,
        ));
    } else {
        buf.push_str(&format!(
            "{}  h/l: scroll  j/k: page  g/G: start/end  +/-: granularity ({})  f: mode  c: cursor  space: pause  q: quit{}",
            DIM,
            format_size(zoom_gran),
            RESET,
        ));
    }

    // Final clear: wipe anything below our fixed frame.
    buf.push_str(CLEAR_BELOW);
}

/// Format a u64 with comma separators (e.g., 1,234,567).
fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(c);
    }
    result
}

/// Get current time as HH:MM:SS.
fn current_time_str() -> String {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    unsafe {
        libc::gettimeofday(&mut tv, std::ptr::null_mut());
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&tv.tv_sec, &mut tm);
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}
