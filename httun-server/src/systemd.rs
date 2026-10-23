// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};

use std::os::unix::net::UnixListener;
use std::{
    mem::{offset_of, size_of_val},
    os::fd::{FromRawFd as _, RawFd},
    sync::atomic::{AtomicBool, Ordering::SeqCst},
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

    if ret == 0 && len >= sizeof_sotype as libc::socklen_t {
        Some(sotype)
    } else {
        None
    }
}

/// Get the socket family of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
unsafe fn get_socket_family(fd: RawFd) -> Option<libc::c_int> {
    // SAFETY: Initializing `libc::sockaddr_un` structure with zero is an allowed pattern.
    // Use `libc::sockaddr_un` because its size is sufficient to hold all socket types.
    let mut saddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let sizeof_saddr: u32 = size_of_val(&saddr).try_into().expect("libc::sockaddr_un");
    let mut len: libc::socklen_t = sizeof_saddr as _;

    // SAFETY: The `fd` is valid, `saddr` and `len` are initialized and valid.
    let ret =
        unsafe { libc::getsockname(fd, (&raw mut saddr).cast::<libc::sockaddr>(), &raw mut len) };

    let min_len = offset_of!(libc::sockaddr_un, sun_family) + size_of::<libc::sa_family_t>();
    if ret == 0 && len as usize >= min_len {
        Some(saddr.sun_family.into())
    } else {
        None
    }
}

/// Check if the stream socket `fd` is in the listening state.
fn is_listening(fd: RawFd) -> bool {
    let mut val: libc::c_int = 0;
    let sizeof_val: u32 = size_of_val(&val).try_into().expect("libc::c_int size");
    let mut len: libc::socklen_t = sizeof_val as _;

    // SAFETY: The `fd` is valid, `val` and `len` are initialized and valid.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&raw mut val).cast(),
            &raw mut len,
        )
    };

    (ret == 0) && (len >= sizeof_val as libc::socklen_t) && (val != 0)
}

fn is_unix_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && is_listening(fd)
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
    #[allow(unused_mut)]
    pub fn get_all() -> ah::Result<Vec<SystemdSocket>> {
        // This function can only be called once.
        static ONCE: AtomicBool = AtomicBool::new(false);
        if ONCE.fetch_or(true, SeqCst) {
            return Err(err!("SystemdSocket::get_all() called twice"));
        }

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
    // This function can only be called once.
    static ONCE: AtomicBool = AtomicBool::new(false);
    if ONCE.fetch_or(true, SeqCst) {
        return Err(err!("systemd_notify_ready() called twice"));
    }

    sd_notify::notify(&[sd_notify::NotifyState::Ready])?;

    Ok(())
}

// vim: ts=4 sw=4 expandtab
