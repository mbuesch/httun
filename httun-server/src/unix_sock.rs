// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{WEBSERVER_GID, WEBSERVER_UID, systemd::SystemdSocket};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use httun_util::{errors::DisconnectedError, header::HttpHeader, timeouts::UNIX_HANDSHAKE_TIMEOUT};
use std::sync::{Arc, atomic};
use tokio::{
    net::{UnixListener, UnixStream},
    time::timeout,
};

/// A connection on the Unix socket.
///
/// This is where the FastCGI requests are received from the httun FastCGI daemon.
#[derive(Debug)]
pub struct UnixConn {
    /// The channel name.
    name: String,
    /// The underlying Unix stream.
    stream: UnixStream,
}

impl UnixConn {
    /// Create a new UnixConn from an accepted UnixStream.
    ///
    /// This performs the initialization handshake.
    async fn new(
        stream: UnixStream,
        conf: &Config,
        extra_headers: &[HttpHeader],
    ) -> ah::Result<Self> {
        let mut this = Self {
            name: "".to_string(),
            stream,
        };

        // Receive the initialization handshake.
        let msg = timeout(UNIX_HANDSHAKE_TIMEOUT, this.recv())
            .await
            .context("Handshake receive timeout")?
            .context("Handshake receive")?;
        if msg.op() != UnOperation::ToSrvInit {
            return Err(err!(
                "UnixConn: Got {:?} but expected {:?}",
                msg.op(),
                UnOperation::ToSrvInit
            ));
        }
        if msg.chan_name().is_empty() {
            return Err(err!("UnixConn: Got invalid channel name."));
        }
        this.name = msg.chan_name().to_string();

        // Send the initialization handshake reply.
        let mut extra_headers = extra_headers.to_vec();
        if let Some(chan_conf) = conf.channel(this.chan_name()) {
            extra_headers.extend_from_slice(chan_conf.http().extra_headers());
        }
        this.send(&UnMessage::new_from_srv_init(
            this.chan_name().to_string(),
            extra_headers,
        ))
        .await
        .context("Handshake reply")?;

        log::debug!("Connected: {}", this.name);

        Ok(this)
    }

    /// Get the channel name.
    pub fn chan_name(&self) -> &str {
        &self.name
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
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Receive a message from the Unix socket.
    pub async fn recv(&self) -> ah::Result<UnMessage> {
        let hdr = self.do_recv(UnMessageHeader::header_size()).await?;
        let hdr = UnMessageHeader::deserialize(&hdr)?;
        let msg = self.do_recv(hdr.body_size()).await?;
        let msg = UnMessage::deserialize(&msg)?;
        if !self.name.is_empty() && msg.chan_name() != self.name {
            return Err(err!("Unix socket: Received message for wrong channel."));
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
    pub async fn send(&self, msg: &UnMessage) -> ah::Result<()> {
        let msg = msg.serialize()?;
        let hdr = UnMessageHeader::new(msg.len())?.serialize()?;
        self.do_send(&hdr).await?;
        self.do_send(&msg).await
    }
}

/// The Unix socket server.
///
/// This listens for connections from the httun FastCGI daemon.
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
    pub async fn new(conf: Arc<Config>, extra_headers: Arc<[HttpHeader]>) -> ah::Result<Self> {
        let sockets = SystemdSocket::get_all()?;
        if let Some(SystemdSocket::Unix(socket)) = sockets.into_iter().next() {
            log::info!("Using Unix socket from systemd.");

            socket
                .set_nonblocking(true)
                .context("Set socket non-blocking")?;
            let listener = UnixListener::from_std(socket)
                .context("Convert std UnixListener to tokio UnixListener")?;

            Ok(Self {
                listener,
                conf,
                extra_headers,
            })
        } else {
            Err(err!("Received an unusable socket from systemd."))
        }
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
