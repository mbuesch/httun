// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{IpcMessage, IpcMessageHeader, IpcOperation};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::{Config, ConfigChannel};
use httun_util::{ChannelId, errors::DisconnectedError, header::HttpHeader, strings::Direction};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::Mutex,
    time::timeout,
};

/// Timeout for the initial IPC handshake.
pub const IPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A message received from an IPC connection.
#[derive(Debug)]
pub enum IpcRxMessage {
    /// Data to the server.
    ToSrv(Vec<u8>),
    /// Request for data from the server.
    ReqFromSrv(Vec<u8>),
    /// Keepalive message.
    Keepalive,
}

/// A client connection to the local IPC protocol.
#[derive(Debug)]
pub struct IpcClientConn<R, W> {
    chan_id: ChannelId,
    extra_headers: Vec<HttpHeader>,
    reader: Mutex<R>,
    writer: Mutex<W>,
}

impl<R, W> IpcClientConn<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Initialize a client connection and perform the IPC handshake.
    pub async fn new(reader: R, writer: W, chan_id: ChannelId, dir: Direction) -> ah::Result<Self> {
        let mut this = Self {
            chan_id,
            extra_headers: vec![],
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        };

        let msg = match dir {
            Direction::W => IpcMessage::new_init_dir_to_srv(chan_id),
            Direction::R => IpcMessage::new_init_dir_from_srv(chan_id),
        };
        this.send_message(&msg)
            .await
            .context("Initialize IPC connection")?;

        let msg = timeout(IPC_HANDSHAKE_TIMEOUT, this.recv_message())
            .await
            .context("IPC handshake receive timeout")?
            .context("IPC handshake receive")?;
        if msg.op() != IpcOperation::InitReply {
            return Err(err!(
                "IPC client: Got {:?} but expected {:?}",
                msg.op(),
                IpcOperation::InitReply,
            ));
        }
        if msg.chan_id() != chan_id {
            return Err(err!("IPC client: Got invalid channel ID."));
        }
        this.extra_headers = msg.into_extra_headers();
        Ok(this)
    }

    /// Get the response headers returned during the handshake.
    pub fn extra_headers(&self) -> &[HttpHeader] {
        &self.extra_headers
    }

    /// Send a payload to the server.
    pub async fn send(&self, payload: Vec<u8>) -> ah::Result<()> {
        self.send_message(&IpcMessage::new_to_srv(self.chan_id, payload))
            .await
    }

    /// Send a keepalive message to the server.
    pub async fn send_keepalive(&self) -> ah::Result<()> {
        self.send_message(&IpcMessage::new_keepalive(self.chan_id))
            .await
    }

    /// Request a response from the server.
    pub async fn recv(&self, payload: Vec<u8>) -> ah::Result<Vec<u8>> {
        self.send_message(&IpcMessage::new_req_from_srv(self.chan_id, payload))
            .await?;
        let msg = self.recv_message().await?;
        match msg.op() {
            IpcOperation::Close => return Err(err!("IPC client: Closed by server")),
            IpcOperation::FromSrv => (),
            op => return Err(err!("IPC client: Got unexpected operation: {op:?}")),
        }
        if msg.chan_id() != self.chan_id {
            return Err(err!(
                "IPC client: Reply channel was '{}' instead of '{}'",
                msg.chan_id(),
                self.chan_id
            ));
        }
        Ok(msg.into_payload())
    }

    async fn send_message(&self, msg: &IpcMessage) -> ah::Result<()> {
        let mut writer = self.writer.lock().await;
        write_message(&mut *writer, msg).await
    }

    async fn recv_message(&self) -> ah::Result<IpcMessage> {
        let mut reader = self.reader.lock().await;
        read_message(&mut *reader).await
    }
}

/// A server-side local IPC protocol connection.
#[derive(Debug)]
pub struct IpcServerConn<R, W> {
    id: ChannelId,
    dir: Option<Direction>,
    reader: Mutex<R>,
    writer: Mutex<W>,
}

impl<R, W> IpcServerConn<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Initialize a connection by performing the IPC handshake.
    pub async fn new(
        reader: R,
        writer: W,
        conf: &Config,
        extra_headers: &[HttpHeader],
    ) -> ah::Result<Self> {
        let mut this = Self {
            id: ConfigChannel::ID_INVALID,
            dir: None,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        };

        let msg = timeout(IPC_HANDSHAKE_TIMEOUT, this.recv_message())
            .await
            .context("IPC handshake receive timeout")?
            .context("IPC handshake receive")?;
        this.dir = match msg.op() {
            IpcOperation::InitDirToSrv => Some(Direction::W),
            IpcOperation::InitDirFromSrv => Some(Direction::R),
            op => return Err(err!("IPC: Got unexpected init message {op:?}.")),
        };
        if msg.chan_id() > ConfigChannel::ID_MAX {
            return Err(err!("IPC: Got invalid channel ID."));
        }
        this.id = msg.chan_id();

        let mut headers = extra_headers.to_vec();
        if let Some(chan_conf) = conf.channel_by_id(this.chan_id()) {
            headers.extend_from_slice(chan_conf.http().extra_headers());
        }
        this.send(&IpcMessage::new_init_reply(this.chan_id(), headers))
            .await
            .context("IPC handshake reply")?;

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

    /// Receive and interpret one message.
    pub async fn recv(&self) -> ah::Result<IpcRxMessage> {
        let msg = self.recv_message().await?;
        match msg.op() {
            IpcOperation::ToSrv => Ok(IpcRxMessage::ToSrv(msg.into_payload())),
            IpcOperation::ReqFromSrv => Ok(IpcRxMessage::ReqFromSrv(msg.into_payload())),
            IpcOperation::Keepalive => Ok(IpcRxMessage::Keepalive),
            IpcOperation::InitDirToSrv
            | IpcOperation::InitDirFromSrv
            | IpcOperation::InitReply
            | IpcOperation::FromSrv
            | IpcOperation::Close => Err(err!("Received invalid IPC operation: {:?}", msg.op())),
        }
    }

    /// Send a reply to the client.
    pub async fn send_reply(&self, payload: Vec<u8>) -> ah::Result<()> {
        self.send(&IpcMessage::new_from_srv(self.chan_id(), payload))
            .await
    }

    /// Close the IPC connection.
    pub async fn close(&self) -> ah::Result<()> {
        self.send(&IpcMessage::new_close(self.chan_id())).await
    }

    /// Receive and validate one message.
    pub async fn recv_message(&self) -> ah::Result<IpcMessage> {
        let msg = {
            let mut reader = self.reader.lock().await;
            read_message(&mut *reader).await?
        };

        let allowed = match self.dir {
            None => matches!(
                msg.op(),
                IpcOperation::InitDirToSrv | IpcOperation::InitDirFromSrv | IpcOperation::InitReply
            ),
            Some(Direction::W) => {
                matches!(msg.op(), IpcOperation::Keepalive | IpcOperation::ToSrv)
            }
            Some(Direction::R) => {
                matches!(msg.op(), IpcOperation::Keepalive | IpcOperation::ReqFromSrv)
            }
        };
        if !allowed {
            return Err(err!(
                "IPC receive: Invalid message {:?} for {:?}.",
                msg.op(),
                self.dir
            ));
        }
        if self.chan_id() <= ConfigChannel::ID_MAX && msg.chan_id() != self.chan_id() {
            return Err(err!("IPC receive: Message for wrong channel."));
        }
        Ok(msg)
    }

    /// Send a validated message.
    pub async fn send(&self, msg: &IpcMessage) -> ah::Result<()> {
        let allowed = match self.dir {
            None => false,
            Some(Direction::W) => {
                matches!(msg.op(), IpcOperation::InitReply | IpcOperation::Close)
            }
            Some(Direction::R) => matches!(
                msg.op(),
                IpcOperation::InitReply | IpcOperation::FromSrv | IpcOperation::Close
            ),
        };
        if !allowed {
            return Err(err!(
                "IPC send: Invalid message {:?} for {:?}.",
                msg.op(),
                self.dir()
            ));
        }

        let mut writer = self.writer.lock().await;
        write_message(&mut *writer, msg).await
    }
}

async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> ah::Result<IpcMessage> {
    let mut header = vec![0; IpcMessageHeader::header_size()];
    match reader.read_exact(&mut header).await {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(DisconnectedError.into());
        }
        Err(e) => return Err(e.into()),
    }
    let header = IpcMessageHeader::deserialize(&header)?;
    let mut body = vec![0; header.body_size()];
    match reader.read_exact(&mut body).await {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(DisconnectedError.into());
        }
        Err(e) => return Err(e.into()),
    }
    IpcMessage::deserialize(&body)
}

async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, msg: &IpcMessage) -> ah::Result<()> {
    let mut body = msg.serialize()?;
    let mut data = IpcMessageHeader::new(body.len())?.serialize()?;
    data.append(&mut body);
    writer.write_all(&data).await?;
    Ok(())
}
