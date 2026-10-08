// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{WEBSERVER_CRED_CHECK_DISABLED, WEBSERVER_GID, WEBSERVER_UID};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_util::header::HttpHeader;
use std::{
    path::Path,
    sync::{Arc, atomic},
};
use tokio::{
    io::{ReadHalf, WriteHalf, split},
    net::{UnixListener, UnixStream},
};

#[cfg(target_os = "linux")]
use crate::systemd::SystemdSocket;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener as StdUnixListener;

/// IPC connection carried by a Unix domain socket.
pub type IpcServerConn =
    httun_unix_protocol::IpcServerConn<ReadHalf<UnixStream>, WriteHalf<UnixStream>>;

/// The Unix socket server.
///
/// This listens for connections from the httun `FastCGI` daemon.
#[derive(Debug)]
pub struct UnixSock {
    /// The Unix listener.
    listener: UnixListener,
    /// The server configuration.
    conf: Arc<Config>,
    /// Extra HTTP headers to add to each request.
    extra_headers: Arc<[HttpHeader]>,
}

impl UnixSock {
    /// Create a new Unix socket server from the systemd socket.
    #[allow(unreachable_code)]
    pub async fn new(
        conf: Arc<Config>,
        socket_path: Option<&Path>,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Self> {
        if let Some(socket_path) = socket_path {
            let listener = UnixListener::bind(socket_path).context("Open Unix socket")?;
            return Self::new_listener(conf, listener, extra_headers).await;
        }

        #[cfg(target_os = "linux")]
        {
            let sockets = SystemdSocket::get_all()?;
            if let Some(SystemdSocket::Unix(socket)) = sockets.into_iter().next() {
                log::info!("Using Unix socket from systemd.");

                return Self::new_std_listener(conf, socket, extra_headers).await;
            }
            return Err(err!("Received an unusable socket from systemd."));
        }

        Err(err!(
            "No unix socket path specified. See --unix-socket command line option."
        ))
    }

    async fn new_listener(
        conf: Arc<Config>,
        listener: UnixListener,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Self> {
        Ok(Self {
            listener,
            conf,
            extra_headers,
        })
    }

    #[cfg(target_os = "linux")]
    async fn new_std_listener(
        conf: Arc<Config>,
        listener: StdUnixListener,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Self> {
        listener
            .set_nonblocking(true)
            .context("Set socket non-blocking")?;
        let listener = UnixListener::from_std(listener)
            .context("Convert std UnixListener to tokio UnixListener")?;
        Self::new_listener(conf, listener, extra_headers).await
    }

    /// Accept a connection on the Unix socket.
    pub async fn accept(&self) -> ah::Result<IpcServerConn> {
        let (stream, _addr) = self.listener.accept().await?;

        // Get the credentials of the connected process.
        let cred = stream
            .peer_cred()
            .context("Get Unix socket peer credentials")?;

        let web_uid = WEBSERVER_UID.load(atomic::Ordering::Relaxed);
        let web_gid = WEBSERVER_GID.load(atomic::Ordering::Relaxed);
        let web_cred_check_disabled = WEBSERVER_CRED_CHECK_DISABLED.load(atomic::Ordering::Relaxed);

        let peer_uid = cred.uid();
        let peer_gid = cred.gid();

        if !web_cred_check_disabled && peer_uid != web_uid {
            return Err(err!(
                "Unix socket: \
                The connected uid {peer_uid} is not the web server's uid ({web_uid}). \
                Rejecting connection. \
                Please see the --webserver-user command line option.",
            ));
        }

        if !web_cred_check_disabled && peer_gid != web_gid {
            return Err(err!(
                "Unix socket: \
                The connected gid {peer_gid} is not the web server's gid ({web_gid}). \
                Rejecting connection. \
                Please see the --webserver-group command line option.",
            ));
        }

        let (reader, writer) = split(stream);
        IpcServerConn::new(reader, writer, &self.conf, &self.extra_headers).await
    }
}

// vim: ts=4 sw=4 expandtab
