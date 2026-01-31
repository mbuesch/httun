// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{WEBSERVER_GID, WEBSERVER_UID};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::{Config, ConfigChannel};
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use httun_util::{
    ChannelId, errors::DisconnectedError, header::HttpHeader, strings::Direction,
    timeouts::UNIX_HANDSHAKE_TIMEOUT,
};
use std::{
    path::Path,
    sync::{Arc, atomic},
};
use tokio::{
    net::{UnixListener, UnixStream},
    time::timeout,
};

#[cfg(target_os = "linux")]
use crate::systemd::SystemdSocket;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener as StdUnixListener;

/// A connection on the Unix socket.
///
/// This is where the `FastCGI` requests are received from the httun `FastCGI` daemon.
#[derive(Debug)]
pub struct UnixConn {
    /// The channel ID.
    id: ChannelId,
    /// Direction.
    dir: Option<Direction>,
    /// The underlying Unix stream.
    stream: UnixStream,
}

impl UnixConn {
    /// Create a new `UnixConn` from an accepted `UnixStream`.
    ///
    /// This performs the initialization handshake.
    async fn new(
        stream: UnixStream,
        conf: &Config,
        extra_headers: &[HttpHeader],
    ) -> ah::Result<Self> {
        let mut this = Self {
            id: ConfigChannel::ID_INVALID,
            dir: None,
            stream,
        };

        // Receive the initialization handshake.
        let msg = timeout(UNIX_HANDSHAKE_TIMEOUT, this.recv())
            .await
            .context("Handshake receive timeout")?
            .context("Handshake receive")?;
        if msg.op() == UnOperation::InitDirToSrv {
            this.dir = Some(Direction::W);
        } else if msg.op() == UnOperation::InitDirFromSrv {
            this.dir = Some(Direction::R);
        } else {
            return Err(err!(
                "UnixConn: Got unexpected init message {:?}.",
                msg.op(),
            ));
        }
        if msg.chan_id() > ConfigChannel::ID_MAX {
            return Err(err!("UnixConn: Got invalid channel ID."));
        }
        this.id = msg.chan_id();

        // Send the initialization handshake reply.
        let mut extra_headers = extra_headers.to_vec();
        if let Some(chan_conf) = conf.channel_by_id(this.chan_id()) {
            extra_headers.extend_from_slice(chan_conf.http().extra_headers());
        }
        this.send(&UnMessage::new_init_reply(this.chan_id(), extra_headers))
            .await
            .context("Handshake reply")?;

        log::debug!("Connected: id={}", this.chan_id());

        Ok(this)
    }

    /// Get the channel ID.
    pub fn chan_id(&self) -> ChannelId {
        self.id
    }

    /// Get the communication direction.
    pub fn dir(&self) -> Direction {
        self.dir.expect("No Direction")
    }

    /// Receive raw data from the Unix socket.
    async fn do_recv(&self, size: usize) -> ah::Result<Vec<u8>> {
        let mut count = 0;
        let mut data = vec![0_u8; size];
        loop {
            self.stream.readable().await?;

            match self.stream.try_read(&mut data[count..]) {
                Ok(n) => {
                    if n == 0 {
                        return Err(DisconnectedError.into());
                    }
                    count += n;
                    assert!(count <= size);
                    if count == size {
                        return Ok(data);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Receive a message from the Unix socket.
    #[allow(clippy::match_same_arms)]
    pub async fn recv(&self) -> ah::Result<UnMessage> {
        let hdr = self.do_recv(UnMessageHeader::header_size()).await?;
        let hdr = UnMessageHeader::deserialize(&hdr)?;
        let msg = self.do_recv(hdr.body_size()).await?;
        let msg = UnMessage::deserialize(&msg)?;

        let allowed = match self.dir {
            None => match msg.op() {
                UnOperation::InitDirToSrv => true,
                UnOperation::InitDirFromSrv => true,
                UnOperation::InitReply => true,
                UnOperation::Keepalive => false,
                UnOperation::ToSrv => false,
                UnOperation::ReqFromSrv => false,
                UnOperation::FromSrv => false,
                UnOperation::Close => false,
            },
            Some(Direction::W) => match msg.op() {
                UnOperation::InitDirToSrv => false,
                UnOperation::InitDirFromSrv => false,
                UnOperation::InitReply => false,
                UnOperation::Keepalive => true,
                UnOperation::ToSrv => true,
                UnOperation::ReqFromSrv => false,
                UnOperation::FromSrv => false,
                UnOperation::Close => false,
            },
            Some(Direction::R) => match msg.op() {
                UnOperation::InitDirToSrv => false,
                UnOperation::InitDirFromSrv => false,
                UnOperation::InitReply => false,
                UnOperation::Keepalive => true,
                UnOperation::ToSrv => false,
                UnOperation::ReqFromSrv => true,
                UnOperation::FromSrv => false,
                UnOperation::Close => false,
            },
        };
        if !allowed {
            return Err(err!(
                "Unix recv: Received invalid message {:?} for {:?}.",
                msg.op(),
                self.dir()
            ));
        }

        if self.chan_id() <= ConfigChannel::ID_MAX && msg.chan_id() != self.chan_id() {
            return Err(err!("Unix recv: Received message for wrong channel."));
        }

        Ok(msg)
    }

    /// Send raw data on the Unix socket.
    async fn do_send(&self, data: &[u8]) -> ah::Result<()> {
        let mut count = 0;
        loop {
            self.stream.writable().await?;

            match self.stream.try_write(&data[count..]) {
                Ok(n) => {
                    count += n;
                    assert!(count <= data.len());
                    if count == data.len() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Send a message on the Unix socket.
    #[allow(clippy::match_same_arms)]
    pub async fn send(&self, msg: &UnMessage) -> ah::Result<()> {
        let allowed = match self.dir {
            None => false,
            Some(Direction::W) => match msg.op() {
                UnOperation::InitDirToSrv => false,
                UnOperation::InitDirFromSrv => false,
                UnOperation::InitReply => true,
                UnOperation::Keepalive => false,
                UnOperation::ToSrv => false,
                UnOperation::ReqFromSrv => false,
                UnOperation::FromSrv => false,
                UnOperation::Close => true,
            },
            Some(Direction::R) => match msg.op() {
                UnOperation::InitDirToSrv => false,
                UnOperation::InitDirFromSrv => false,
                UnOperation::InitReply => true,
                UnOperation::Keepalive => false,
                UnOperation::ToSrv => false,
                UnOperation::ReqFromSrv => false,
                UnOperation::FromSrv => true,
                UnOperation::Close => true,
            },
        };
        if !allowed {
            return Err(err!(
                "Unix send: Trying to send invalid message {:?} for {:?}.",
                msg.op(),
                self.dir()
            ));
        }

        let mut msg = msg.serialize()?;
        let mut buf = UnMessageHeader::new(msg.len())?.serialize()?;
        buf.append(&mut msg);
        self.do_send(&buf).await
    }
}

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
    pub async fn accept(&self) -> ah::Result<UnixConn> {
        let (stream, _addr) = self.listener.accept().await?;

        // Get the credentials of the connected process.
        let cred = stream
            .peer_cred()
            .context("Get Unix socket peer credentials")?;

        let web_uid = WEBSERVER_UID.load(atomic::Ordering::Relaxed);
        let web_gid = WEBSERVER_GID.load(atomic::Ordering::Relaxed);

        let peer_uid = cred.uid();
        let peer_gid = cred.gid();

        if peer_uid != web_uid {
            return Err(err!(
                "Unix socket: \
                The connected uid {peer_uid} is not the web server's uid ({web_uid}). \
                Rejecting connection. \
                Please see the --webserver-user command line option.",
            ));
        }

        if peer_gid != web_gid {
            return Err(err!(
                "Unix socket: \
                The connected gid {peer_gid} is not the web server's gid ({web_gid}). \
                Rejecting connection. \
                Please see the --webserver-group command line option.",
            ));
        }

        UnixConn::new(stream, &self.conf, &self.extra_headers).await
    }
}

// vim: ts=4 sw=4 expandtab
