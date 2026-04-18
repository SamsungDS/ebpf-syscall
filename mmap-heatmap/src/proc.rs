// SPDX-License-Identifier: copyleft-next-0.3.1
//
// proc.rs — /proc/PID/{pagemap,clear_refs,mem,maps} interface
//
// All reads use pread(2) which combines seek+read in a single syscall,
// halving kernel transitions compared to lseek()+read().

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::consts::{PAGE_SIZE, PAGE_SIZE_USIZE, PAGEMAP_ENTRY_SIZE};

const SOFT_DIRTY_BIT: u32 = 55;

/// A parsed /proc/PID/maps region.
#[derive(Debug, Clone)]
pub struct MapRegion {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

/// Find the best file-backed shared mmap region for a process.
///
/// Two-pass strategy matching the Python prototype:
///   Pass 0: prefer named files (skip [heap], /dev/*, (deleted), SYSV*, empty)
///   Pass 1: accept anything except [bracket] paths
///
/// Returns the largest matching region.
pub fn find_mmap_region(pid: u32) -> io::Result<Option<MapRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path)?;

    for pass_num in 0..2 {
        let mut best: Option<MapRegion> = None;
        let mut best_size: u64 = 0;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let perms = parts[1];
            let path = if parts.len() > 5 { parts[5] } else { "" };

            // Must be a shared mapping ('s' in permissions).
            if !perms.contains('s') {
                continue;
            }

            if pass_num == 0 {
                if path.starts_with('[')
                    || path.contains("/dev/")
                    || path.contains("(deleted)")
                    || path.contains("SYSV")
                    || path.is_empty()
                {
                    continue;
                }
            } else if path.starts_with('[') {
                continue;
            }

            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }
            let start = match u64::from_str_radix(addr_range[0], 16) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let end = match u64::from_str_radix(addr_range[1], 16) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let size = end.saturating_sub(start);

            if size > best_size {
                best_size = size;
                best = Some(MapRegion {
                    start,
                    end,
                    perms: perms.to_string(),
                    path: path.to_string(),
                });
            }
        }

        if best.is_some() {
            return Ok(best);
        }
    }

    Ok(None)
}

/// Open /proc/PID/mem for reading. Returns an owned file descriptor.
pub fn open_mem(pid: u32) -> io::Result<OwnedFd> {
    open_proc_fd(pid, "mem")
}

/// Open /proc/PID/pagemap for reading. Returns an owned file descriptor.
pub fn open_pagemap(pid: u32) -> io::Result<OwnedFd> {
    open_proc_fd(pid, "pagemap")
}

fn open_proc_fd(pid: u32, name: &str) -> io::Result<OwnedFd> {
    let path = format!("/proc/{}/{}", pid, name);
    let c_path = std::ffi::CString::new(path.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a valid, newly opened file descriptor that we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read pagemap entries and append dirty page addresses to `dirty`.
///
/// Reads the entire pagemap range for [start, end) in a single pread() call
/// into a reusable buffer. Each 8-byte entry is checked for the soft-dirty
/// bit (bit 55).
///
/// `dirty` is cleared before use so callers can reuse the allocation.
pub fn get_dirty_pages(
    pagemap_fd: &OwnedFd,
    start: u64,
    end: u64,
    buf: &mut Vec<u8>,
    dirty: &mut Vec<u64>,
) -> io::Result<()> {
    dirty.clear();

    let num_pages = (end - start) / PAGE_SIZE;
    let read_size = (num_pages * PAGEMAP_ENTRY_SIZE) as usize;
    let offset = (start / PAGE_SIZE) * PAGEMAP_ENTRY_SIZE;

    buf.resize(read_size, 0);

    // pread: one syscall to read the entire pagemap range.
    let n = unsafe {
        libc::pread(
            pagemap_fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            read_size,
            offset as libc::off_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes_read = n as usize;

    // Use chunks_exact for cleaner pagemap entry parsing.
    for (i, chunk) in buf[..bytes_read]
        .chunks_exact(PAGEMAP_ENTRY_SIZE as usize)
        .enumerate()
    {
        let entry = u64::from_ne_bytes(chunk.try_into().unwrap());
        if entry & (1u64 << SOFT_DIRTY_BIT) != 0 {
            dirty.push(start + (i as u64) * PAGE_SIZE);
        }
    }

    Ok(())
}

/// Detect contiguous runs of dirty pages and append (start_addr, page_count) pairs to `runs`.
///
/// When a workload writes sequentially, many consecutive pages are dirty.
/// Batching them into single pread() calls dramatically reduces syscalls.
///
/// `runs` is cleared before use so callers can reuse the allocation.
pub fn batch_dirty_runs(dirty_pages: &[u64], runs: &mut Vec<(u64, usize)>) {
    runs.clear();

    if dirty_pages.is_empty() {
        return;
    }

    let mut run_start = dirty_pages[0];
    let mut run_count: usize = 1;

    for i in 1..dirty_pages.len() {
        if dirty_pages[i] == dirty_pages[i - 1] + PAGE_SIZE {
            run_count += 1;
        } else {
            runs.push((run_start, run_count));
            run_start = dirty_pages[i];
            run_count = 1;
        }
    }
    runs.push((run_start, run_count));
}

/// Read a contiguous range of pages from /proc/PID/mem using pread().
///
/// pread(2) combines seek+read in one syscall, halving kernel transitions
/// per dirty page read compared to lseek()+read().
pub fn read_pages(
    mem_fd: &OwnedFd,
    addr: u64,
    num_pages: usize,
    buf: &mut [u8],
) -> io::Result<usize> {
    let size = num_pages * PAGE_SIZE_USIZE;
    debug_assert!(buf.len() >= size);
    let n = unsafe {
        libc::pread(
            mem_fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            size,
            addr as libc::off_t,
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        // ESRCH means the process exited — propagate as a distinct error.
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "target process exited",
            ));
        }
        return Err(err);
    }
    let bytes_read = n as usize;

    // Zero-fill any unread tail so the shadow buffer is deterministic.
    if bytes_read < size {
        buf[bytes_read..size].fill(0);
    }

    Ok(bytes_read)
}

/// Write "4" to /proc/PID/clear_refs to clear soft-dirty bits.
pub fn clear_soft_dirty(pid: u32) -> io::Result<()> {
    let path = format!("/proc/{}/clear_refs", pid);
    fs::write(&path, "4")?;
    Ok(())
}

/// Read the entire region from /proc/PID/mem into a shadow buffer.
///
/// Used for the initial snapshot before monitoring begins.
pub fn read_full_region(mem_fd: &OwnedFd, start: u64, size: u64) -> io::Result<Vec<u8>> {
    let mut shadow = vec![0u8; size as usize];
    let num_pages = size / PAGE_SIZE;

    // Read in chunks to avoid massive single pread calls.
    // 256 pages = 1 MiB per syscall.
    let chunk_pages: u64 = 256;
    let mut offset: u64 = 0;

    while offset < num_pages {
        let pages_left = num_pages - offset;
        let pages_this = pages_left.min(chunk_pages) as usize;
        let byte_offset = offset * PAGE_SIZE;
        let byte_size = pages_this * PAGE_SIZE_USIZE;
        let addr = start + byte_offset;

        let n = unsafe {
            libc::pread(
                mem_fd.as_raw_fd(),
                shadow[byte_offset as usize..].as_mut_ptr() as *mut libc::c_void,
                byte_size,
                addr as libc::off_t,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            // EIO on unmapped pages is expected; fill with zeros and continue.
            if err.raw_os_error() == Some(libc::EIO) {
                shadow[byte_offset as usize..byte_offset as usize + byte_size].fill(0);
            } else {
                return Err(err);
            }
        } else {
            // Zero-fill any short read tail within this chunk.
            let bytes_read = n as usize;
            if bytes_read < byte_size {
                shadow[byte_offset as usize + bytes_read..byte_offset as usize + byte_size]
                    .fill(0);
            }
        }

        offset += chunk_pages;
    }

    Ok(shadow)
}

// OwnedFd needs FromRawFd.
use std::os::fd::FromRawFd;
