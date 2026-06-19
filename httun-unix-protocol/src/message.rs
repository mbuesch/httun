// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use httun_util::{ChannelId, header::HttpHeader};

/// Header for a local IPC protocol message.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct IpcMessageHeader {
    /// Size of the message body in bytes.
    body_size: u32,
}

impl IpcMessageHeader {
    const SIZE: usize = 4;

    /// Returns the size of the serialized header.
    pub fn header_size() -> usize {
        debug_assert_eq!(
            IpcMessageHeader::new(0).unwrap().serialize().unwrap().len(),
            Self::SIZE
        );
        Self::SIZE
    }

    /// Creates a new IPC message header with the given body size.
    pub fn new(body_size: usize) -> ah::Result<Self> {
        Ok(Self {
            body_size: body_size
                .try_into()
                .map_err(|_| err!("IpcMessageHeader: Body size is too big"))?,
        })
    }

    /// Returns the size of the message body in bytes.
    pub fn body_size(&self) -> usize {
        self.body_size
            .try_into()
            .expect("IpcMessageHeader: Internal size error")
    }

    /// Serializes the header to a byte vector.
    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(self)?.into_vec())
    }

    /// Deserializes the header from a byte slice.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        Ok(rkyv::from_bytes::<IpcMessageHeader, rkyv::rancor::Error>(
            buf,
        )?)
    }
}

/// Operation code for the local IPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub enum IpcOperation {
    /// Initialize a new `ToSrv` IPC connection.
    InitDirToSrv,

    /// Initialize a new `FromSrv` IPC connection.
    InitDirFromSrv,

    /// Reply to `InitDirToSrv` or `InitDirFromSrv`.
    InitReply,

    /// Keep-alive message to server.
    Keepalive,

    /// To httun-server.
    ToSrv,

    /// Request `FromSrv`.
    ReqFromSrv,

    /// From httun-server.
    FromSrv,

    /// Close the connection.
    Close,
}

/// Message for the local IPC protocol.
///
/// This protocol is used for local IPC with `httun-server`.
#[derive(Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct IpcMessage {
    /// Operation code.
    op: IpcOperation,
    /// Channel ID.
    chan_id: ChannelId,
    /// Extra HTTP headers returned in the handshake reply.
    extra_headers: Vec<HttpHeader>,
    /// Payload data.
    payload: Vec<u8>,
}

impl std::fmt::Debug for IpcMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "IpcMessage {{ op: {:?}, chan_id: {}, extra_headers: {:?} }}",
            self.op, self.chan_id, self.extra_headers,
        )
    }
}

impl IpcMessage {
    /// Create a new IPC protocol message.
    fn new(
        op: IpcOperation,
        chan_id: ChannelId,
        extra_headers: Vec<HttpHeader>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            op,
            chan_id,
            extra_headers,
            payload,
        }
    }

    /// Creates a new `InitDirToSrv` message.
    pub fn new_init_dir_to_srv(chan_id: ChannelId) -> Self {
        Self::new(IpcOperation::InitDirToSrv, chan_id, vec![], vec![])
    }

    /// Creates a new `InitDirFromSrv` message.
    pub fn new_init_dir_from_srv(chan_id: ChannelId) -> Self {
        Self::new(IpcOperation::InitDirFromSrv, chan_id, vec![], vec![])
    }

    /// Creates a new `InitReply` message.
    pub fn new_init_reply(chan_id: ChannelId, extra_headers: Vec<HttpHeader>) -> Self {
        Self::new(IpcOperation::InitReply, chan_id, extra_headers, vec![])
    }

    /// Creates a new `Keepalive` message.
    pub fn new_keepalive(chan_id: ChannelId) -> Self {
        Self::new(IpcOperation::Keepalive, chan_id, vec![], vec![])
    }

    /// Creates a new `ToSrv` message.
    pub fn new_to_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(IpcOperation::ToSrv, chan_id, vec![], payload)
    }

    /// Creates a new `ReqFromSrv` message.
    pub fn new_req_from_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(IpcOperation::ReqFromSrv, chan_id, vec![], payload)
    }

    /// Creates a new `FromSrv` message.
    pub fn new_from_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(IpcOperation::FromSrv, chan_id, vec![], payload)
    }

    /// Creates a new `Close` message.
    pub fn new_close(chan_id: ChannelId) -> Self {
        Self::new(IpcOperation::Close, chan_id, vec![], vec![])
    }

    /// Returns the operation code.
    pub fn op(&self) -> IpcOperation {
        self.op
    }

    /// Returns the channel ID.
    pub fn chan_id(&self) -> ChannelId {
        self.chan_id
    }

    /// Convert this message into the extra http headers.
    pub fn into_extra_headers(self) -> Vec<HttpHeader> {
        self.extra_headers
    }

    /// Returns the payload data.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Convert this message into the payload data.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Serializes the message to a byte vector.
    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(self)?.into_vec())
    }

    /// Deserializes the message from a byte slice.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        Ok(rkyv::from_bytes::<IpcMessage, rkyv::rancor::Error>(buf)?)
    }
}

// vim: ts=4 sw=4 expandtab
