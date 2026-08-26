// SPDX-License-Identifier: copyleft-next-0.3.1
//
// mmap-heatmap — Sub-page change detection for file-backed mmap regions
//
// Monitors file-backed mmap regions at sub-page (down to 8-byte) granularity
// using Linux soft-dirty page tracking + shadow buffer diffing. Reads
// /proc/PID/pagemap, /proc/PID/mem, and /proc/PID/clear_refs.
//
// Usage:
//   sudo ./mmap-heatmap -p PID
//   sudo ./mmap-heatmap -p PID -i 0.005 --decay 0

mod consts;
mod diff;
mod display;
mod heat;
mod proc;
mod stats;

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::consts::{DEFAULT_WINDOW, FINEST, PAGE_SIZE};
use crate::display::VizMode;
use crate::heat::HeatSource;

const HIDE_CURSOR: &str = "\x1b[?25l";
const HOME: &str = "\x1b[1;1H";
const ALT_SCREEN_ON: &str = "\x1b[?1049h";  // Switch to alternate screen buffer
// Disable autowrap (DECAWM). When the help line at the bottom row is wider
// than the terminal, autowrap would push the wrapped tail to a new line,
// which at the last row causes the alt screen to scroll up by one — and
// drops the top header row out of view. Disabling DECAWM clips overflow
// at the right margin instead. ncurses does the same for full-screen apps.
// The matching restore sequence (\x1b[?7h) is inlined in the two exit
// paths: restore_terminal (normal/panic drop) and sigint_handler (must
// use a static byte slice for async-signal safety).
const AUTOWRAP_OFF: &str = "\x1b[?7l";

// Global flags for signal handlers.
static SIGWINCH_FLAG: AtomicBool = AtomicBool::new(false);
static SIGINT_FLAG: AtomicBool = AtomicBool::new(false);

// Store original termios globally for signal handler cleanup.
// OnceLock is safe to access from signal handlers (read-only after set).
static ORIG_TERMIOS: OnceLock<libc::termios> = OnceLock::new();

/// CLI arguments parsed from std::env::args.
struct Args {
    pid: u32,
    start: Option<u64>,
    end: Option<u64>,
    interval: f64,
    count: u64,
    decay: i32,
    heat_inc: i32,
    window: u32,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut pid: Option<u32> = None;
    let mut start: Option<u64> = None;
    let mut end: Option<u64> = None;
    let mut interval: f64 = 1.0;
    let mut count: u64 = 0;
    let mut decay: i32 = 1;
    let mut heat_inc: i32 = 2;
    let mut window: u32 = DEFAULT_WINDOW;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--pid" => {
                i += 1;
                pid = Some(
                    args.get(i)
                        .ok_or("missing value for --pid")?
                        .parse()
                        .map_err(|_| "invalid PID")?,
                );
            }
            "-m" | "--start" => {
                i += 1;
                let s = args.get(i).ok_or("missing value for --start")?;
                start = Some(parse_addr(s)?);
            }
            "-M" | "--end" => {
                i += 1;
                let s = args.get(i).ok_or("missing value for --end")?;
                end = Some(parse_addr(s)?);
            }
            "-i" | "--interval" => {
                i += 1;
                interval = args
                    .get(i)
                    .ok_or("missing value for --interval")?
                    .parse()
                    .map_err(|_| "invalid interval")?;
            }
            "-n" | "--count" => {
                i += 1;
                count = args
                    .get(i)
                    .ok_or("missing value for --count")?
                    .parse()
                    .map_err(|_| "invalid count")?;
            }
            "--decay" => {
                i += 1;
                decay = args
                    .get(i)
                    .ok_or("missing value for --decay")?
                    .parse()
                    .map_err(|_| "invalid decay")?;
            }
            "--heat-inc" => {
                i += 1;
                heat_inc = args
                    .get(i)
                    .ok_or("missing value for --heat-inc")?
                    .parse()
                    .map_err(|_| "invalid heat-inc")?;
            }
            "--window" => {
                i += 1;
                window = args
                    .get(i)
                    .ok_or("missing value for --window")?
                    .parse()
                    .map_err(|_| "invalid window")?;
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: mmap-heatmap -p PID [-m START] [-M END] [-i INTERVAL] [-n COUNT] [--decay N] [--heat-inc N] [--window N]"
                );
                eprintln!();
                eprintln!("  -p, --pid PID        Target process ID (required)");
                eprintln!("  -m, --start ADDR     Region start address (hex or decimal)");
                eprintln!("  -M, --end ADDR       Region end address (hex or decimal)");
                eprintln!("  -i, --interval SECS  Sampling interval (default: 1.0)");
                eprintln!("  -n, --count N        Number of samples, 0=unlimited (default: 0)");
                eprintln!("  --decay N            Decay rate: heat=points/idle, freq=multiplier (default: 1)");
                eprintln!("  --heat-inc N         Heat mode: increment per write (default: 2)");
                eprintln!("  --window N           Freq mode: samples in sliding window (default: 20)");
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
        i += 1;
    }

    if window == 0 {
        return Err("--window must be >= 1 (0 would divide by zero in freq decay)".into());
    }
    if heat_inc < 1 {
        return Err("--heat-inc must be >= 1".into());
    }
    if !interval.is_finite() || interval <= 0.0 {
        return Err("--interval must be a finite positive number of seconds".into());
    }

    Ok(Args {
        pid: pid.ok_or("--pid is required")?,
        start,
        end,
        interval,
        count,
        decay,
        heat_inc,
        window,
    })
}

fn parse_addr(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid hex address: {}", s))
    } else {
        s.parse().map_err(|_| format!("invalid address: {}", s))
    }
}

/// Check if stdin is a terminal.
fn is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Has the target process disappeared from /proc?
///
/// When the target exits, /proc/PID/... operations surface two distinct
/// errors depending on the syscall and timing: pread() against an open
/// pagemap/mem fd returns ESRCH (the fd stays valid but the task is gone);
/// fs::write("/proc/PID/clear_refs") returns ENOENT (the path vanished
/// once /proc/PID/ was torn down). read_pages() additionally re-maps ESRCH
/// to io::ErrorKind::NotFound, so we accept that too.
fn is_process_gone(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT))
        || err.kind() == io::ErrorKind::NotFound
}

/// Set terminal to cbreak mode for non-blocking keypress reading.
/// Returns the original termios for restoration, or None if stdin
/// is not a terminal (e.g., piped or run from a non-interactive shell).
fn enter_raw_mode() -> io::Result<Option<libc::termios>> {
    if !is_tty() {
        return Ok(None);
    }

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut orig) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut raw = orig;
    // cbreak mode: disable canonical mode and echo, keep signals.
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 0; // Non-blocking.
    raw.c_cc[libc::VTIME] = 0;

    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Some(orig))
}

/// Restore terminal to original mode.
fn restore_terminal(orig: &Option<libc::termios>) {
    if let Some(ref t) = orig {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, t);
        }
    }
    // Re-enable autowrap, show cursor, and leave alt screen (restores previous
    // content). Autowrap must be restored so the shell behaves normally after
    // exit.
    let _ = io::stdout().write_all(b"\x1b[?7h\x1b[?25h\x1b[?1049l");
    let _ = io::stdout().flush();
}

/// RAII guard that restores terminal state on drop, including panics.
struct TermGuard {
    orig: Option<libc::termios>,
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        restore_terminal(&self.orig);
    }
}

/// Install signal handlers using sigaction.
fn install_signal_handlers() {
    unsafe {
        // SIGWINCH: use SA_RESTART so interrupted syscalls restart.
        let mut sa_winch: libc::sigaction = std::mem::zeroed();
        sa_winch.sa_sigaction = sigwinch_handler as libc::sighandler_t;
        libc::sigemptyset(&mut sa_winch.sa_mask);
        sa_winch.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGWINCH, &sa_winch, std::ptr::null_mut());

        // SIGINT and SIGTERM: no SA_RESTART so nanosleep is interrupted.
        let mut sa_int: libc::sigaction = std::mem::zeroed();
        sa_int.sa_sigaction = sigint_handler as libc::sighandler_t;
        libc::sigemptyset(&mut sa_int.sa_mask);
        sa_int.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa_int, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa_int, std::ptr::null_mut());
    }
}

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_FLAG.store(true, Ordering::Relaxed);
}

/// Signal-safe handler: only uses async-signal-safe functions.
/// No allocations, no format!(), no std::process::exit.
extern "C" fn sigint_handler(_sig: libc::c_int) {
    SIGINT_FLAG.store(true, Ordering::Relaxed);
    // Restore terminal in signal handler to avoid leaving terminal broken.
    if let Some(orig) = ORIG_TERMIOS.get() {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
        }
    }
    // Re-enable autowrap, show cursor, leave alt screen, print message using
    // only write(2).
    static MSG: &[u8] = b"\x1b[?7h\x1b[?25h\x1b[?1049lStopped.\n";
    unsafe {
        libc::write(libc::STDOUT_FILENO, MSG.as_ptr() as *const _, MSG.len());
        libc::_exit(0);
    }
}

/// Wait up to `timeout_ms` milliseconds for stdin input.
///
/// Returns true if stdin has data ready, false on timeout or signal.
/// Decouples the UI tick from the sampling interval so large `-i`
/// values don't starve input.
fn wait_for_input(timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    r > 0 && (pfd.revents & libc::POLLIN) != 0
}

/// Monotonic time in nanoseconds (CLOCK_MONOTONIC).
///
/// Used to schedule the next sample independently of UI ticks.  Must
/// be monotonic so wall-clock jumps (NTP, suspend) don't shift the
/// sampling cadence.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Read a keypress non-blocking. Returns None if no input available.
fn read_key() -> Option<Key> {
    let mut buf = [0u8; 3];
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // Non-blocking: VMIN=0, VTIME=0 means read returns immediately.
    let n = match handle.read(&mut buf[..1]) {
        Ok(n) => n,
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return None,
        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => return None,
        Err(_) => return None,
    };
    if n == 0 {
        return None;
    }

    match buf[0] {
        b'q' => Some(Key::Quit),
        b'h' => Some(Key::Left),
        b'l' => Some(Key::Right),
        b'j' => Some(Key::Down),
        b'k' => Some(Key::Up),
        b'g' => Some(Key::Home),
        b'G' => Some(Key::End),
        b'f' => Some(Key::ToggleMode),
        b'c' => Some(Key::ToggleCursor),
        b'n' => Some(Key::NextPage),
        b'N' => Some(Key::PrevPage),
        b' ' | b'p' => Some(Key::Pause),
        b'+' | b'=' => Some(Key::ZoomIn),
        b'-' => Some(Key::ZoomOut),
        0x1b => {
            // Escape sequence.
            let n2 = match handle.read(&mut buf[..2]) {
                Ok(n) => n,
                Err(_) => return Some(Key::Quit),
            };
            if n2 == 2 && buf[0] == b'[' {
                match buf[1] {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    _ => None,
                }
            } else {
                Some(Key::Quit) // bare Escape
            }
        }
        _ => None,
    }
}

enum Key {
    Quit,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    ZoomIn,
    ZoomOut,
    ToggleMode,
    ToggleCursor,
    Pause,
    NextPage,
    PrevPage,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().map_err(|e| {
        eprintln!("error: {}", e);
        eprintln!("usage: mmap-heatmap -p PID [-i INTERVAL] [--decay N] [--heat-inc N] [--window N]");
        e
    })?;

    // Must run as root for /proc/PID/pagemap and /proc/PID/mem access.
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root (need access to /proc/PID/pagemap and /proc/PID/mem)".into());
    }

    // Resolve region.
    let (region_start, region_end, region_perms, region_file) =
        if let (Some(s), Some(e)) = (args.start, args.end) {
            (s, e, String::from("?"), String::from("(user-specified)"))
        } else {
            match proc::find_mmap_region(args.pid)? {
                Some(r) => (r.start, r.end, r.perms, r.path),
                None => {
                    return Err(format!(
                        "no file-backed shared mmap found for PID {}",
                        args.pid
                    )
                    .into());
                }
            }
        };

    // Validate region bounds. region_end must be strictly greater than
    // region_start and both must be page-aligned for the pagemap math
    // (offset = page_index * PAGEMAP_ENTRY_SIZE) and for pread offsets
    // to match kernel expectations.
    if region_end <= region_start {
        return Err(format!(
            "invalid region: end (0x{:x}) must be greater than start (0x{:x})",
            region_end, region_start
        )
        .into());
    }
    if region_start % PAGE_SIZE != 0 || region_end % PAGE_SIZE != 0 {
        return Err(format!(
            "invalid region: start (0x{:x}) and end (0x{:x}) must be page-aligned ({}B)",
            region_start, region_end, PAGE_SIZE
        )
        .into());
    }

    let region_size = region_end - region_start;
    let num_pages = region_size / PAGE_SIZE;

    // Open /proc files. OwnedFd handles close on drop.
    let mem_fd = proc::open_mem(args.pid)?;
    let pagemap_fd = proc::open_pagemap(args.pid)?;

    // Initial snapshot.
    let file_basename = region_file
        .rsplit('/')
        .next()
        .unwrap_or(&region_file);
    // Do not write to stderr (eprintln!) between here and alt screen entry.
    // Some terminal emulators carry the cursor position from the main screen
    // into the alternate screen buffer. If stderr output has advanced the
    // cursor past row 1, the alt screen may start with the cursor at a
    // non-zero row, causing the first line of the TUI to be invisible even
    // with absolute cursor positioning. All diagnostic output must happen
    // before this point (during argument parsing) or after alt screen exit.
    let shadow = proc::read_full_region(&mem_fd, region_start, region_size)?;
    proc::clear_soft_dirty(args.pid)?;

    // Diff engine.
    let mut engine = diff::DiffEngine::new(shadow, region_start);

    // Heat maps: overview at 4K, fine at 8-byte granularity.
    let mut heat_4k = heat::HeatMap::new(num_pages as usize, args.decay, args.heat_inc);
    let mut heat_fine = heat::HeatMap::new((region_size / FINEST) as usize, args.decay, args.heat_inc);

    // Frequency maps: DAMON-style moving-sum at both granularities.
    // decay_rate for freq mode: clamp to 0 if negative (negative decay
    // is meaningless; decay=0 means no decay / accumulate forever).
    let freq_decay = args.decay.max(0) as u32;
    let mut freq_4k = heat::FreqMap::new(num_pages as usize, args.window, freq_decay);
    let mut freq_fine = heat::FreqMap::new((region_size / FINEST) as usize, args.window, freq_decay);

    // Visualization mode: freq is the default.
    let mut viz_mode = VizMode::Freq;

    // Zoom state.
    let mut zoom = display::ZoomState::new();

    // Stats accumulators.
    let mut stats_pages = stats::RunningStats::new();
    let mut stats_bytes = stats::RunningStats::new();

    // Terminal setup. Returns None if stdin is not a TTY.
    let orig_termios = enter_raw_mode()?;
    if let Some(t) = orig_termios {
        let _ = ORIG_TERMIOS.set(t);
    }
    install_signal_handlers();

    // TermGuard restores terminal on drop, including panics.
    let _term_guard = TermGuard {
        orig: orig_termios,
    };

    // Switch to alternate screen buffer (like vim/htop) and hide cursor.
    // This prevents scroll history pollution and ensures \x1b[H always
    // homes to the actual top-left of the visible screen.
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Enter alt screen, disable autowrap, clear, home, hide cursor.
    // Do NOT set a scroll region (\x1b[1;Nr) — even when it matches the full
    // terminal size, some emulators (xterm-256color) treat the first margin row
    // differently during overwrite, making line 1 invisible. We manage cursor
    // position manually with HOME on every frame and never rely on scrolling.
    // Autowrap is disabled so overflowing content (such as a help line wider
    // than the terminal) is clipped at the right margin rather than wrapping
    // into a scroll that would push the header off the top.
    out.write_all(
        format!(
            "{}{}{}\x1b[2J{}",
            ALT_SCREEN_ON, AUTOWRAP_OFF, HIDE_CURSOR, HOME
        )
        .as_bytes(),
    )?;
    out.flush()?;


    // Reusable buffers to avoid per-frame allocation.
    let mut pagemap_buf: Vec<u8> = Vec::new();
    let mut dirty_pages: Vec<u64> = Vec::new();
    let mut dirty_runs: Vec<(u64, usize)> = Vec::new();
    let mut page_read_buf: Vec<u8> = vec![0u8; 256 * PAGE_SIZE as usize]; // Up to 256 contiguous pages.
    let mut frame_buf = String::with_capacity(64 * 1024);

    let mut sample: u64 = 0;
    let mut paused = false;
    // When the target process exits we want to keep the captured state on
    // screen (and let the user still navigate/cursor/zoom) instead of
    // bailing out. process_alive flips to false on the first /proc error
    // that indicates the target is gone, and the main loop then behaves
    // like a permanent pause: no sample increment, no data collection.
    let mut process_alive = true;
    let interval_ns = (args.interval * 1_000_000_000.0) as u64;

    // UI tick budget: drives the input/render cadence independently of
    // the sampling interval.  ~30 FPS feels instant for scroll/zoom/pan
    // without burning CPU on idle repaints.  When the sampling interval
    // is smaller than the UI tick (fast sampling like -i 0.01), the
    // poll timeout shrinks accordingly so we never oversleep a sample.
    const UI_TICK_MS: u64 = 33;

    let mut next_sample_ns = monotonic_ns().saturating_add(interval_ns);

    'main: loop {
        if SIGINT_FLAG.load(Ordering::Relaxed) {
            break;
        }

        // Sleep until either (a) stdin has input or (b) the next sample
        // is due or (c) UI_TICK_MS has elapsed.  This decouples keyboard
        // latency from the sampling interval: even at -i 60, keys land
        // within one UI tick instead of blocking for a minute.
        let now_ns = monotonic_ns();
        let until_sample_ms = if next_sample_ns > now_ns {
            ((next_sample_ns - now_ns) / 1_000_000).min(UI_TICK_MS) as i32
        } else {
            0
        };
        let _ = wait_for_input(until_sample_ms);

        let now_ns = monotonic_ns();
        let do_sample = now_ns >= next_sample_ns;
        if do_sample {
            // Advance the next deadline without drifting.  If we fell
            // far behind (paused, suspended, slow /proc read), snap the
            // deadline to now + interval so we don't burst-sample to
            // catch up.
            next_sample_ns = next_sample_ns.saturating_add(interval_ns);
            if next_sample_ns < now_ns {
                next_sample_ns = now_ns.saturating_add(interval_ns);
            }
            if !paused && process_alive {
                sample += 1;
            }
        }
        if args.count > 0 && sample > args.count {
            break;
        }

        // Get terminal size (check SIGWINCH flag too).
        SIGWINCH_FLAG.store(false, Ordering::Relaxed);
        let term = display::get_term_size();

        let label_width: usize = 14; // Must match display::render_frame label_width
        let map_cols = (term.cols as usize).saturating_sub(label_width).max(20);

        // Clamp cursor to visible area after terminal resize.  last_zoom_rows
        // reflects the actual zoom rows from the previous frame; if the terminal
        // shrank, the cursor might be past the visible area.
        if zoom.cursor_mode {
            let max_row = zoom.last_zoom_rows.max(1).saturating_sub(1);
            if zoom.cursor_row > max_row {
                zoom.cursor_row = max_row;
            }
            if zoom.cursor_col >= map_cols {
                zoom.cursor_col = map_cols.saturating_sub(1);
            }
        }

        // Handle keyboard input.  Drain every pending key per UI tick so
        // fast keystrokes (or pasted input) are not deferred across ticks.
        while let Some(key) = read_key() {
            let zoom_gran = zoom.granularity();
            let step_bytes = map_cols as u64 * zoom_gran; // one row

            // Use the actual zoom rows from the last rendered frame for accurate
            // cursor bounds and window size.  On the first frame before any
            // render, last_zoom_rows is initialized to 1, which is safe (cursor
            // stays at row 0 and window is one row).
            let est_zoom_rows = zoom.last_zoom_rows.max(1);
            let wbytes = est_zoom_rows as u64 * map_cols as u64 * zoom_gran;

            if zoom.cursor_mode {
                match key {
                    Key::Quit => break 'main,
                    Key::Left => {
                        if zoom.cursor_col > 0 {
                            zoom.cursor_col -= 1;
                        } else if zoom.cursor_row > 0 {
                            // Wrap to end of previous row.
                            zoom.cursor_row -= 1;
                            zoom.cursor_col = map_cols.saturating_sub(1);
                        } else if zoom.offset > 0 {
                            // Auto-scroll backward one row.
                            zoom.offset = zoom.offset.saturating_sub(step_bytes);
                            zoom.cursor_col = map_cols.saturating_sub(1);
                        }
                    }
                    Key::Right => {
                        // Check if we would exceed region bounds.
                        let next_offset = zoom.cursor_byte_offset(map_cols) + zoom_gran;
                        if next_offset < region_size {
                            if zoom.cursor_col + 1 < map_cols {
                                zoom.cursor_col += 1;
                            } else if zoom.cursor_row + 1 < est_zoom_rows {
                                zoom.cursor_row += 1;
                                zoom.cursor_col = 0;
                            } else {
                                // Auto-scroll forward one row.
                                zoom.offset = zoom.offset.saturating_add(step_bytes)
                                    .min(region_size.saturating_sub(wbytes));
                                zoom.cursor_col = 0;
                            }
                        }
                    }
                    Key::Up => {
                        if zoom.cursor_row > 0 {
                            zoom.cursor_row -= 1;
                        } else if zoom.offset > 0 {
                            // Auto-scroll backward one row.
                            zoom.offset = zoom.offset.saturating_sub(step_bytes);
                        }
                    }
                    Key::Down => {
                        let next_row_offset = zoom.offset
                            + ((zoom.cursor_row + 1) * map_cols + zoom.cursor_col) as u64 * zoom_gran;
                        if next_row_offset < region_size {
                            if zoom.cursor_row + 1 < est_zoom_rows {
                                zoom.cursor_row += 1;
                            } else {
                                // Auto-scroll forward one row.
                                zoom.offset = zoom.offset.saturating_add(step_bytes)
                                    .min(region_size.saturating_sub(wbytes));
                            }
                        }
                    }
                    Key::Home => {
                        zoom.offset = 0;
                        zoom.cursor_col = 0;
                        zoom.cursor_row = 0;
                    }
                    Key::End => {
                        let total_blocks = region_size / zoom_gran;
                        let last_block = total_blocks.saturating_sub(1) as usize;
                        let last_row = last_block / map_cols;
                        let last_col = last_block % map_cols;
                        // Position the viewport so the last block is visible.
                        let visible_blocks = est_zoom_rows * map_cols;
                        if total_blocks as usize > visible_blocks {
                            // Place cursor at the last row of the viewport.
                            let start_block = total_blocks as usize - visible_blocks;
                            zoom.offset = (start_block as u64) * zoom_gran;
                            zoom.cursor_row = est_zoom_rows.saturating_sub(1);
                            zoom.cursor_col = last_col;
                        } else {
                            zoom.offset = 0;
                            zoom.cursor_row = last_row;
                            zoom.cursor_col = last_col;
                        }
                    }
                    Key::ZoomIn | Key::ZoomOut => {
                        // Track byte offset across granularity change.
                        let byte_off = zoom.cursor_byte_offset(map_cols);
                        if matches!(key, Key::ZoomIn) {
                            zoom.zoom_in();
                        } else {
                            zoom.zoom_out();
                        }
                        let new_gran = zoom.granularity();
                        // Align byte offset to new granularity.
                        let aligned = (byte_off / new_gran) * new_gran;
                        // Recompute window bytes at new granularity using the
                        // actual zoom rows from the last rendered frame.
                        let new_wbytes = est_zoom_rows as u64 * map_cols as u64 * new_gran;
                        // Try to center the cursor in the viewport.
                        let half_window = new_wbytes / 2;
                        if aligned >= half_window {
                            zoom.offset = ((aligned - half_window) / new_gran) * new_gran;
                        } else {
                            zoom.offset = 0;
                        }
                        zoom.clamp(region_size, new_wbytes);
                        zoom.set_cursor_from_byte_offset(aligned, map_cols);
                        // Clamp cursor_row: set_cursor_from_byte_offset may
                        // produce a row beyond the visible zoom area if the
                        // centering couldn't place the target in the viewport.
                        if zoom.cursor_row >= est_zoom_rows {
                            zoom.cursor_row = est_zoom_rows.saturating_sub(1);
                        }
                    }
                    Key::NextPage => {
                        // Jump cursor to first block of next page.
                        let cur_off = zoom.cursor_byte_offset(map_cols);
                        let cur_page = cur_off / PAGE_SIZE;
                        let next_page_off = (cur_page + 1) * PAGE_SIZE;
                        if next_page_off < region_size {
                            // Scroll viewport if needed so the target is visible.
                            let end_visible = zoom.offset + (est_zoom_rows * map_cols) as u64 * zoom_gran;
                            if next_page_off >= end_visible {
                                zoom.offset = (next_page_off / zoom_gran) * zoom_gran;
                                let wbytes_new = est_zoom_rows as u64 * map_cols as u64 * zoom_gran;
                                zoom.clamp(region_size, wbytes_new);
                            }
                            zoom.set_cursor_from_byte_offset(next_page_off, map_cols);
                            if zoom.cursor_row >= est_zoom_rows {
                                zoom.cursor_row = est_zoom_rows.saturating_sub(1);
                            }
                        }
                    }
                    Key::PrevPage => {
                        // Jump cursor to first block of current or previous page.
                        let cur_off = zoom.cursor_byte_offset(map_cols);
                        let cur_page = cur_off / PAGE_SIZE;
                        let page_start = cur_page * PAGE_SIZE;
                        // If already at page start, go to previous page.
                        let target = if cur_off == page_start && cur_page > 0 {
                            (cur_page - 1) * PAGE_SIZE
                        } else {
                            page_start
                        };
                        if target < zoom.offset {
                            zoom.offset = (target / zoom_gran) * zoom_gran;
                        }
                        zoom.set_cursor_from_byte_offset(target, map_cols);
                    }
                    Key::ToggleCursor => {
                        zoom.cursor_mode = false;
                    }
                    Key::ToggleMode => {
                        viz_mode = if viz_mode == VizMode::Freq {
                            VizMode::Heat
                        } else {
                            VizMode::Freq
                        };
                    }
                    Key::Pause => {
                        paused = !paused;
                    }
                }
            } else {
                match key {
                    Key::Quit => break 'main,
                    Key::Right => {
                        zoom.offset = zoom
                            .offset
                            .saturating_add(step_bytes)
                            .min(region_size.saturating_sub(wbytes));
                    }
                    Key::Left => {
                        zoom.offset = zoom.offset.saturating_sub(step_bytes);
                    }
                    Key::Down => {
                        zoom.offset = zoom
                            .offset
                            .saturating_add(wbytes)
                            .min(region_size.saturating_sub(wbytes));
                    }
                    Key::Up => {
                        zoom.offset = zoom.offset.saturating_sub(wbytes);
                    }
                    Key::Home => {
                        zoom.offset = 0;
                    }
                    Key::End => {
                        zoom.offset = region_size.saturating_sub(wbytes);
                    }
                    Key::ZoomIn => zoom.zoom_in(),
                    Key::ZoomOut => zoom.zoom_out(),
                    Key::ToggleMode => {
                        viz_mode = if viz_mode == VizMode::Freq {
                            VizMode::Heat
                        } else {
                            VizMode::Freq
                        };
                    }
                    Key::ToggleCursor => {
                        zoom.cursor_mode = true;
                        zoom.cursor_col = 0;
                        zoom.cursor_row = 0;
                    }
                    Key::Pause => {
                        paused = !paused;
                    }
                    Key::NextPage | Key::PrevPage => {}
                }
            }
            let zoom_gran = zoom.granularity();
            let wbytes = zoom.last_zoom_rows.max(1) as u64 * map_cols as u64 * zoom_gran;
            zoom.clamp(region_size, wbytes);
        }

        // === Data collection (skipped when paused or target has exited) ===
        // Only runs when this UI tick coincides with a sample deadline.
        // On off-sample ticks we fall through to rendering so keyboard
        // navigation stays responsive at any -i.
        let mut bytes_changed: u64 = 0;

        if do_sample && !paused && process_alive {
            engine.reset_changed();

            // Any "process gone" error from /proc I/O freezes the display
            // instead of exiting.  We inspect raw_os_error so an ESRCH
            // surfacing from pread(mem)/pread(pagemap) is handled uniformly
            // with ENOENT from fs::write(/proc/PID/clear_refs).
            match proc::get_dirty_pages(&pagemap_fd, region_start, region_end, &mut pagemap_buf, &mut dirty_pages) {
                Ok(()) => {}
                Err(e) if is_process_gone(&e) => { process_alive = false; }
                Err(e) => return Err(e.into()),
            }

            if process_alive {
                // Batch contiguous dirty pages into single pread() calls.
                proc::batch_dirty_runs(&dirty_pages, &mut dirty_runs);
                for (run_addr, run_pages) in &dirty_runs {
                    let read_size = *run_pages * PAGE_SIZE as usize;
                    if page_read_buf.len() < read_size {
                        page_read_buf.resize(read_size, 0);
                    }

                    match proc::read_pages(&mem_fd, *run_addr, *run_pages, &mut page_read_buf) {
                        Ok(n) if n == read_size => {
                            let words = engine.diff_pages(*run_addr, &page_read_buf[..read_size], *run_pages);
                            bytes_changed += words * FINEST;
                        }
                        Ok(_) => {
                            let words = engine.diff_pages(*run_addr, &page_read_buf[..read_size], *run_pages);
                            bytes_changed += words * FINEST;
                        }
                        Err(ref e) if is_process_gone(e) => {
                            process_alive = false;
                            break;
                        }
                        Err(_) => {}
                    }
                }
            }

            if process_alive {
                match proc::clear_soft_dirty(args.pid) {
                    Ok(()) => {}
                    Err(e) if is_process_gone(&e) => { process_alive = false; }
                    Err(e) => return Err(e.into()),
                }
            }

            if process_alive {
                // Update heat and frequency maps.
                let words_per_page = (PAGE_SIZE / FINEST) as usize;
                for p in 0..num_pages as usize {
                    let fine_start = p * words_per_page;
                    let fine_end = fine_start + words_per_page;
                    let page_hot = engine.fine_changed[fine_start..fine_end]
                        .iter()
                        .any(|&c| c != 0);
                    if page_hot {
                        heat_4k.touch(p, sample);
                        freq_4k.touch(p, sample);
                    }
                }

                for (idx, &changed) in engine.fine_changed.iter().enumerate() {
                    if changed != 0 {
                        heat_fine.touch(idx, sample);
                        freq_fine.touch(idx, sample);
                    }
                }

                stats_pages.push(dirty_pages.len() as u64);
                stats_bytes.push(bytes_changed);
            }
        }

        let pages_summary = stats_pages.summary();
        let bytes_summary = stats_bytes.summary();

        // === Render frame ===
        let ri = display::RegionInfo {
            pid: args.pid,
            file_name: file_basename,
            perms: &region_perms,
            start: region_start,
            end: region_end,
            size: region_size,
            num_pages,
            interval: args.interval,
            decay: args.decay,
            heat_inc: args.heat_inc,
            mode: viz_mode,
            window: args.window,
            paused,
            exited: !process_alive,
        };

        let (s4k, sfine): (&dyn HeatSource, &dyn HeatSource) = match viz_mode {
            VizMode::Heat => (&heat_4k, &heat_fine),
            VizMode::Freq => (&freq_4k, &freq_fine),
        };

        display::render_frame(
            &mut frame_buf,
            &ri,
            sample,
            dirty_pages.len() as u64,
            bytes_changed,
            &pages_summary,
            &bytes_summary,
            s4k,
            sfine,
            &mut zoom,
            &term,
        );

        out.write_all(frame_buf.as_bytes())?;
        out.flush()?;
    }

    // TermGuard will restore terminal on drop.
    // OwnedFd will close file descriptors on drop.
    // Print final message before guard drops (which clears screen).
    drop(out);
    println!("Stopped.");

    Ok(())
}
