// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use arc_swap::ArcSwap;
use httun_unix_protocol::{UnMessage, UnMessageHeader, UnOperation};
use httun_util::errors::{ConnectionResetError, DisconnectedError};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::UnixStream;

const TRIES: usize = 3;

async fn unix_connect(path: &Path) -> ah::Result<UnixStream> {
    UnixStream::connect(path)
        .await
        .context("Connect to Unix socket")
}

#[derive(Debug)]
pub struct ServerUnixConn {
    socket_path: PathBuf,
    stream: ArcSwap<UnixStream>,
    chan_name: String,
}

impl ServerUnixConn {
    pub async fn new(socket_path: &Path, chan_name: &str) -> ah::Result<Self> {
        let this = Self {
            socket_path: socket_path.to_path_buf(),
            stream: ArcSwap::new(Arc::new(unix_connect(socket_path).await?)),
            chan_name: chan_name.to_string(),
        };
        this.init_conn().await?;
        Ok(this)
    }

    async fn init_conn(&self) -> ah::Result<()> {
        self.send_msg(UnMessage::new_init(self.chan_name.to_string()))
            .await
            .context("Initialize unix connection to httun-server")
    }

    async fn reconnect(&self) -> ah::Result<()> {
        self.stream
            .store(Arc::new(unix_connect(&self.socket_path).await?));
        self.init_conn().await
    }

    async fn do_send(&self, data: &[u8]) -> ah::Result<()> {
        let mut count = 0;
        loop {
            self.stream
                .load()
                .writable()
                .await
                .context("Socket polling (send)")?;

            match self.stream.load().try_write(&data[count..]) {
                Ok(n) => {
                    count += n;
                    assert!(count <= data.len());
                    if count == data.len() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e)
                    if [ErrorKind::ConnectionReset, ErrorKind::BrokenPipe].contains(&e.kind()) =>
                {
                    return Err(ConnectionResetError.into());
                }
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
                .load()
                .readable()
                .await
                .context("Socket polling (recv)")?;

            match self.stream.load().try_read(&mut data[count..]) {
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
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e)
                    if [ErrorKind::ConnectionReset, ErrorKind::BrokenPipe].contains(&e.kind()) =>
                {
                    return Err(ConnectionResetError.into());
                }
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
        for _ in 0..TRIES {
            match self
                .send_msg(UnMessage::new_to_srv(
                    self.chan_name.to_string(),
                    payload.clone(),
                ))
                .await
            {
                Err(e)
                    if e.downcast_ref::<ConnectionResetError>().is_some()
                        || e.downcast_ref::<DisconnectedError>().is_some() =>
                {
                    self.reconnect().await?;
                    continue;
                }
                res => return res,
            }
        }
        Err(err!("Unix socket connection reset by peer."))
    }

    pub async fn recv(&self, payload: Vec<u8>) -> ah::Result<Vec<u8>> {
        for _ in 0..TRIES {
            match self
                .send_msg(UnMessage::new_req_from_srv(
                    self.chan_name.to_string(),
                    payload.clone(),
                ))
                .await
            {
                Err(e)
                    if e.downcast_ref::<ConnectionResetError>().is_some()
                        || e.downcast_ref::<DisconnectedError>().is_some() =>
                {
                    self.reconnect().await?;
                    continue;
                }
                Err(e) => return Err(e),
                Ok(()) => (),
            }
            let msg = match self.recv_msg().await {
                Err(e)
                    if e.downcast_ref::<ConnectionResetError>().is_some()
                        || e.downcast_ref::<DisconnectedError>().is_some() =>
                {
                    self.reconnect().await?;
                    continue;
                }
                Err(e) => return Err(e),
                Ok(m) => m,
            };
            match msg.op() {
                UnOperation::Close => {
                    self.reconnect().await?;
                    continue;
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
            return Ok(msg.into_payload());
        }
        Err(err!("Unix socket connection reset by peer."))
    }
}

// vim: ts=4 sw=4 expandtab
