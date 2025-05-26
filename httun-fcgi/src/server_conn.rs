// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use std::{io::ErrorKind, path::Path};
use tokio::net::UnixStream;

#[derive(Debug)]
pub struct ServerUnixConn {
    stream: UnixStream,
    chan_name: String,
}

impl ServerUnixConn {
    pub async fn new(socket_path: &Path, chan_name: &str) -> ah::Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("Connect to Unix socket")?;
        let this = Self {
            stream,
            chan_name: chan_name.to_string(),
        };
        this.send_msg(UnMessage::new_init(chan_name.to_string()))
            .await
            .context("Initialize unix connection to httun-server")?;
        Ok(this)
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
        let msg = msg.serialize();
        let hdr = UnMessageHeader::new(msg.len()).serialize();
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
        self.send_msg(UnMessage::new_to_srv(self.chan_name.to_string(), payload))
            .await
    }

    pub async fn recv(&self, payload: Vec<u8>) -> ah::Result<Vec<u8>> {
        self.send_msg(UnMessage::new_req_from_srv(
            self.chan_name.to_string(),
            payload,
        ))
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
        if msg.chan_name() != self.chan_name {
            return Err(err!(
                "ServerUnixConn: Reply chan was '{}' instead of '{}'",
                msg.chan_name(),
                self.chan_name
            ));
        }
        Ok(msg.into_payload())
    }
}

// vim: ts=4 sw=4 expandtab
