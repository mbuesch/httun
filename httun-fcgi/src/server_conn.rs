// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use httun_util::{header::HttpHeader, timeouts::UNIX_HANDSHAKE_TIMEOUT};
use std::{io::ErrorKind, path::Path};
use tokio::{net::UnixStream, time::timeout};

/// Unix socket connection between this FCGI process and the httun-server.
#[derive(Debug)]
pub struct ServerUnixConn {
    stream: UnixStream,
    chan_id: u16,
    extra_headers: Vec<HttpHeader>,
}

impl ServerUnixConn {
    pub async fn new(socket_path: &Path, chan_id: u16) -> ah::Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("Connect to Unix socket")?;
        let mut this = Self {
            stream,
            chan_id,
            extra_headers: vec![],
        };

        // Send initialization handshake.
        this.send_msg(UnMessage::new_to_srv_init(chan_id))
            .await
            .context("Initialize unix connection to httun-server")?;

        // Receive the initialization handshake reply.
        let msg = timeout(UNIX_HANDSHAKE_TIMEOUT, this.recv_msg())
            .await
            .context("Handshake receive timeout")?
            .context("Handshake receive")?;
        if msg.op() != UnOperation::FromSrvInit {
            return Err(err!(
                "UnixConn: Got {:?} but expected {:?}",
                msg.op(),
                UnOperation::FromSrvInit
            ));
        }
        if msg.chan_id() != chan_id {
            return Err(err!("UnixConn: Got invalid channel ID."));
        }
        this.extra_headers = msg.into_extra_headers();

        Ok(this)
    }

    pub fn extra_headers(&self) -> &[HttpHeader] {
        &self.extra_headers
    }

    async fn do_send(&self, data: &[u8]) -> ah::Result<()> {
        let mut count = 0;
        loop {
            self.stream
                .writable()
                .await
                .context("Socket polling (send)")?;

            match self.stream.try_write(&data[count..]) {
                Ok(n) => {
                    count += n;
                    assert!(count <= data.len());
                    if count == data.len() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket write: {e}"));
                }
            }
        }
    }

    async fn do_recv(&self, size: usize) -> ah::Result<Vec<u8>> {
        let mut count = 0;
        let mut data = vec![0_u8; size];
        loop {
            self.stream
                .readable()
                .await
                .context("Socket polling (recv)")?;

            match self.stream.try_read(&mut data[count..]) {
                Ok(n) => {
                    if n == 0 {
                        return Err(err!("Socket read: Peer disconnected"));
                    }
                    count += n;
                    assert!(count <= size);
                    if count == size {
                        return Ok(data);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket read: {e}"));
                }
            }
        }
    }

    async fn send_msg(&self, msg: UnMessage) -> ah::Result<()> {
        let msg = msg.serialize()?;
        let hdr = UnMessageHeader::new(msg.len())?.serialize()?;
        self.do_send(&hdr).await?;
        self.do_send(&msg).await
    }

    async fn recv_msg(&self) -> ah::Result<UnMessage> {
        let hdr = self.do_recv(UnMessageHeader::header_size()).await?;
        let hdr = UnMessageHeader::deserialize(&hdr)?;
        let msg = self.do_recv(hdr.body_size()).await?;
        UnMessage::deserialize(&msg)
    }

    pub async fn send(&self, payload: Vec<u8>) -> ah::Result<()> {
        self.send_msg(UnMessage::new_to_srv(self.chan_id, payload))
            .await
    }

    pub async fn send_keepalive(&self) -> ah::Result<()> {
        self.send_msg(UnMessage::new_keepalive(self.chan_id)).await
    }

    pub async fn recv(&self, payload: Vec<u8>) -> ah::Result<Vec<u8>> {
        self.send_msg(UnMessage::new_req_from_srv(self.chan_id, payload))
            .await?;
        let msg = self.recv_msg().await?;
        match msg.op() {
            UnOperation::Close => {
                return Err(err!("ServerUnixConn: Closed by server"));
            }
            UnOperation::FromSrv => (),
            op => {
                return Err(err!("ServerUnixConn: Got unexpected op: {op:?}"));
            }
        }
        if msg.chan_id() != self.chan_id {
            return Err(err!(
                "ServerUnixConn: Reply chan was '{}' instead of '{}'",
                msg.chan_id(),
                self.chan_id
            ));
        }
        Ok(msg.into_payload())
    }
}

// vim: ts=4 sw=4 expandtab
