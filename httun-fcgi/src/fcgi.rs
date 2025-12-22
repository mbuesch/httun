// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::async_main::MAX_NUM_CONNECTIONS;
use anyhow::{self as ah, Context as _, format_err as err};
use std::{
    os::fd::{FromRawFd as _, RawFd},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};
use tokio_fastcgi::{Request, RequestResult, Requests, Role};

/// Maximum number of requests per connection.
const FCGI_MAX_REQS: u8 = 16;

const INET46: [Option<libc::c_int>; 2] = [Some(libc::AF_INET), Some(libc::AF_INET6)];

/// Check if the passed raw `fd` is a socket.
fn is_socket(fd: RawFd) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use libc::{stat64, fstat64};
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    use libc::{stat as stat64, fstat as fstat64};

    // SAFETY: Initializing `libc::stat64` structure with zero is an allowed pattern.
    let mut stat: stat64 = unsafe { std::mem::zeroed() };
    // SAFETY: The `fd` is valid and `stat` is initialized and valid.
    let ret = unsafe { fstat64(fd, &mut stat) };
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
    let mut len: libc::socklen_t = size_of_val(&sotype) as _;
    // SAFETY: The `fd` is valid, `sotype` and `len` are initialized and valid.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sotype as *mut _ as _,
            &mut len,
        )
    };
    if ret == 0 && len >= size_of_val(&sotype) as _ {
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
    let mut len: libc::socklen_t = size_of_val(&saddr) as _;
    // SAFETY: The `fd` is valid, `saddr` and `len` are initialized and valid.
    let ret = unsafe { libc::getsockname(fd, &mut saddr, &mut len) };
    if ret == 0 && len >= size_of_val(&saddr) as _ {
        Some(saddr.sa_family.into())
    } else {
        None
    }
}

fn is_tcp_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && INET46.contains(&get_socket_family(fd))
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

pub struct FcgiConn {
    stream: FcgiStream,
}

pub type FcgiRequest<'a> = Arc<Request<Box<dyn AsyncWrite + Send + Sync + Unpin + 'a>>>;
pub type FcgiRequestResult = RequestResult;
pub type FcgiRole = Role;

impl FcgiConn {
    fn new(stream: FcgiStream) -> Self {
        Self { stream }
    }

    pub async fn handle<
        'a,
        F: Future<Output = FcgiRequestResult>,
        C: FnMut(FcgiRequest<'a>) -> F,
    >(
        &'a mut self,
        mut handler: C,
    ) -> ah::Result<()> {
        let sock = self.stream.split();
        let mut reqs = Requests::from_split_socket(sock, MAX_NUM_CONNECTIONS, FCGI_MAX_REQS);

        while let Ok(Some(request)) = reqs.next().await {
            request
                .process(|request| async { handler(request).await })
                .await?;
        }
        Ok(())
    }
}

enum FcgiStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl FcgiStream {
    pub fn split<'a>(
        &'a mut self,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send + Sync + 'a>,
        Box<dyn AsyncWrite + Unpin + Send + Sync + 'a>,
    ) {
        match self {
            Self::Unix(stream) => {
                let (a, b) = stream.split();
                (Box::new(a), Box::new(b))
            }
            Self::Tcp(stream) => {
                let (a, b) = stream.split();
                (Box::new(a), Box::new(b))
            }
        }
    }
}

enum FcgiListener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

pub struct Fcgi {
    listener: FcgiListener,
}

impl Fcgi {
    pub fn new(fd: RawFd) -> ah::Result<Self> {
        let listener = if is_unix_socket(fd) {
            // SAFETY: We have checked that this is a Unix socket.
            let sock = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            sock.set_nonblocking(true)
                .context("Set socket non-blocking")?;
            let listener = UnixListener::from_std(sock)?;
            FcgiListener::Unix(listener)
        } else if is_tcp_socket(fd) {
            // SAFETY: We have checked that this is a TCP socket.
            let sock = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            sock.set_nonblocking(true)
                .context("Set socket non-blocking")?;
            let listener = TcpListener::from_std(sock)?;
            FcgiListener::Tcp(listener)
        } else {
            return Err(err!("FCGI: Socket is neither Unix nor TCP socket."));
        };
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> ah::Result<FcgiConn> {
        let stream = match &self.listener {
            FcgiListener::Unix(listener) => {
                let (stream, _addr) = listener.accept().await?;
                FcgiStream::Unix(stream)
            }
            FcgiListener::Tcp(listener) => {
                let (stream, _addr) = listener.accept().await?;
                FcgiStream::Tcp(stream)
            }
        };
        Ok(FcgiConn::new(stream))
    }
}

// vim: ts=4 sw=4 expandtab
