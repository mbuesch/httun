// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};

use std::os::unix::net::UnixListener;
use std::{
    mem::size_of_val,
    os::fd::{FromRawFd as _, RawFd},
};

/// Check if the passed raw `fd` is a socket.
fn is_socket(fd: RawFd) -> bool {
    // SAFETY: Initializing `libc::stat64` structure with zero is an allowed pattern.
    let mut stat: libc::stat64 = unsafe { std::mem::zeroed() };

    // SAFETY: The `fd` is valid and `stat` is initialized and valid.
    let ret = unsafe { libc::fstat64(fd, &raw mut stat) };

    if ret == 0 {
        const S_IFMT: libc::mode_t = libc::S_IFMT as libc::mode_t;
        const S_IFSOCK: libc::mode_t = libc::S_IFSOCK as libc::mode_t;
        (stat.st_mode as libc::mode_t & S_IFMT) == S_IFSOCK
    } else {
        false
    }
}

/// Get the socket type of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
unsafe fn get_socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut sotype: libc::c_int = 0;
    let sizeof_sotype: u32 = size_of_val(&sotype).try_into().expect("libc::c_int size");
    let mut len: libc::socklen_t = sizeof_sotype as _;

    // SAFETY: The `fd` is valid, `sotype` and `len` are initialized and valid.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut sotype).cast(),
            &raw mut len,
        )
    };

    if ret == 0 && len == sizeof_sotype as libc::socklen_t {
        Some(sotype)
    } else {
        None
    }
}

/// Get the socket family of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
unsafe fn get_socket_family(fd: RawFd) -> Option<libc::c_int> {
    // SAFETY: Initializing `libc::sockaddr` structure with zero is an allowed pattern.
    let mut saddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    let sizeof_saddr: u32 = size_of_val(&saddr).try_into().expect("libc::sockaddr size");
    let mut len: libc::socklen_t = sizeof_saddr as _;

    // SAFETY: The `fd` is valid, `saddr` and `len` are initialized and valid.
    let ret = unsafe { libc::getsockname(fd, &raw mut saddr, &raw mut len) };

    if ret == 0 && len >= sizeof_saddr as _ {
        Some(saddr.sa_family.into())
    } else {
        None
    }
}

fn is_unix_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && get_socket_family(fd) == Some(libc::AF_UNIX)
    }
}

/// A socket that systemd handed us over.
#[derive(Debug)]
#[non_exhaustive]
pub enum SystemdSocket {
    /// Unix socket.
    Unix(UnixListener),
}

impl SystemdSocket {
    /// Get all sockets from systemd.
    ///
    /// All environment variables related to this operation will be cleared.
    #[allow(unused_mut)]
    pub fn get_all() -> ah::Result<Vec<SystemdSocket>> {
        let mut sockets = vec![];
        if sd_notify::booted().unwrap_or(false) {
            for fd in sd_notify::listen_fds().context("Systemd listen_fds")? {
                if is_unix_socket(fd) {
                    // SAFETY:
                    // The fd from systemd is good and lives for the lifetime of the program.
                    let sock = unsafe { UnixListener::from_raw_fd(fd) };
                    sockets.push(SystemdSocket::Unix(sock));
                    continue;
                }

                let _ = fd;
                return Err(err!("Received unknown socket from systemd"));
            }
        }
        Ok(sockets)
    }
}

/// Notify ready-status to systemd.
pub fn systemd_notify_ready() -> ah::Result<()> {
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;
    Ok(())
}

// vim: ts=4 sw=4 expandtab
