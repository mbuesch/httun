// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::systemd::{SystemdSocket, systemd_notify_ready};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use std::time::Duration;
use tokio::{
    net::{UnixListener, UnixStream},
    time::timeout,
};

const DEBUG: bool = false;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct UnixConn {
    name: String,
    stream: UnixStream,
}

impl UnixConn {
    async fn new(stream: UnixStream) -> ah::Result<Self> {
        let mut this = Self {
            name: "".to_string(),
            stream,
        };

        let Some(msg) = timeout(HANDSHAKE_TIMEOUT, this.recv())
            .await
            .context("Handshake receive timeout")?
            .context("Handshake receive")?
        else {
            return Err(err!("Disconnected."));
        };
        if msg.op() != UnOperation::Init {
            return Err(err!(
                "UnixConn: Got {:?} but expected {:?}",
                msg.op(),
                UnOperation::Init
            ));
        }
        if msg.chan_name().is_empty() {
            return Err(err!("UnixConn: Got invalid channel name."));
        }
        this.name = msg.chan_name().to_string();

        println!("Connected: {}", this.name);

        Ok(this)
    }

    pub fn chan_name(&self) -> &str {
        &self.name
    }

    async fn do_recv(&mut self, size: usize) -> ah::Result<Option<Vec<u8>>> {
        let mut count = 0;
        let mut data = vec![0_u8; size];
        loop {
            self.stream.readable().await?;

            match self.stream.try_read(&mut data[count..size - count]) {
                Ok(n) => {
                    if n == 0 {
                        return Ok(None);
                    }
                    count += n;
                    assert!(count <= size);
                    if count == size {
                        return Ok(Some(data));
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

    pub async fn recv(&mut self) -> ah::Result<Option<UnMessage>> {
        let Some(hdr) = self.do_recv(UnMessageHeader::header_size()).await? else {
            return Ok(None);
        };
        let hdr = UnMessageHeader::deserialize(&hdr)?;
        let Some(msg) = self.do_recv(hdr.body_size()).await? else {
            return Ok(None);
        };
        let msg = UnMessage::deserialize(&msg)?;
        if DEBUG {
            println!("RX Unix msg: {msg:?}");
        }
        Ok(Some(msg))
    }

    async fn do_send(&mut self, data: &[u8]) -> ah::Result<()> {
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

    pub async fn send(&mut self, msg: &UnMessage) -> ah::Result<()> {
        if DEBUG {
            println!("TX Unix msg: {msg:?}");
        }
        let msg = msg.serialize();
        let hdr = UnMessageHeader::new(msg.len()).serialize();
        self.do_send(&hdr).await?;
        self.do_send(&msg).await
    }
}

#[derive(Debug)]
pub struct UnixSock {
    listener: UnixListener,
}

impl UnixSock {
    pub async fn new() -> ah::Result<Self> {
        let sockets = SystemdSocket::get_all()?;
        if let Some(SystemdSocket::Unix(socket)) = sockets.into_iter().next() {
            println!("Using Unix socket from systemd.");

            socket
                .set_nonblocking(true)
                .context("Set socket non-blocking")?;
            let listener = UnixListener::from_std(socket)
                .context("Convert std UnixListener to tokio UnixListener")?;

            systemd_notify_ready()?;

            Ok(Self { listener })
        } else {
            Err(err!("Received an unusable socket from systemd."))
        }
    }

    /// Accept a connection on the Unix socket.
    pub async fn accept(&self) -> ah::Result<UnixConn> {
        let (stream, _addr) = self.listener.accept().await?;
        UnixConn::new(stream).await
    }
}

// vim: ts=4 sw=4 expandtab
