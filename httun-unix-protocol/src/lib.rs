// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err};
use httun_util::{ChannelId, header::HttpHeader};

/// Path to the Unix domain socket used by httun-server.
pub const UNIX_SOCK: &str = "/run/httun-server/httun-server.sock";

/// Header for a Unix domain socket protocol message.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct UnMessageHeader {
    /// Size of the message body in bytes.
    body_size: u32,
}

impl UnMessageHeader {
    const SIZE: usize = 4;

    /// Returns the size of the serialized header.
    pub fn header_size() -> usize {
        debug_assert_eq!(
            UnMessageHeader::new(0).unwrap().serialize().unwrap().len(),
            Self::SIZE
        );
        Self::SIZE
    }

    /// Creates a new `UnMessageHeader` with the given body size.
    pub fn new(body_size: usize) -> ah::Result<Self> {
        Ok(Self {
            body_size: body_size
                .try_into()
                .map_err(|_| err!("UnMessageHeader: Body size is too big"))?,
        })
    }

    /// Returns the size of the message body in bytes.
    pub fn body_size(&self) -> usize {
        self.body_size
            .try_into()
            .expect("UnMessageHeader: Internal size error")
    }

    /// Serializes the header to a byte vector.
    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(self)?.into_vec())
    }

    /// Deserializes the header from a byte slice.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        Ok(rkyv::from_bytes::<UnMessageHeader, rkyv::rancor::Error>(
            buf,
        )?)
    }
}

/// Operation code for the Unix domain socket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub enum UnOperation {
    /// Initialize a new `ToSrv` socket.
    InitDirToSrv,

    /// Initialize a new `FromSrv` socket.
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

/// Message for the Unix domain socket protocol.
///
/// The Unix socket is used for communication between
/// the `FastCGI` daemon (`httun-fcgi`) and the `httun-server`.
#[derive(Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct UnMessage {
    /// Operation code.
    op: UnOperation,
    /// Channel ID.
    chan_id: ChannelId,
    /// Extra HTTP headers (only for `FromSrvInit`).
    extra_headers: Vec<HttpHeader>,
    /// Payload data.
    payload: Vec<u8>,
}

impl std::fmt::Debug for UnMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "UnMessage {{ op: {:?}, chan_id: {}, extra_headers: {:?} }}",
            self.op, self.chan_id, self.extra_headers,
        )
    }
}

impl UnMessage {
    /// Create a new Unix domain socket protocol message.
    fn new(
        op: UnOperation,
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
        Self::new(UnOperation::InitDirToSrv, chan_id, vec![], vec![])
    }

    /// Creates a new `InitDirFromSrv` message.
    pub fn new_init_dir_from_srv(chan_id: ChannelId) -> Self {
        Self::new(UnOperation::InitDirFromSrv, chan_id, vec![], vec![])
    }

    /// Creates a new `InitReply` message.
    pub fn new_init_reply(chan_id: ChannelId, extra_headers: Vec<HttpHeader>) -> Self {
        Self::new(UnOperation::InitReply, chan_id, extra_headers, vec![])
    }

    /// Creates a new `Keepalive` message.
    pub fn new_keepalive(chan_id: ChannelId) -> Self {
        Self::new(UnOperation::Keepalive, chan_id, vec![], vec![])
    }

    /// Creates a new `ToSrv` message.
    pub fn new_to_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ToSrv, chan_id, vec![], payload)
    }

    /// Creates a new `ReqFromSrv` message.
    pub fn new_req_from_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ReqFromSrv, chan_id, vec![], payload)
    }

    /// Creates a new `FromSrv` message.
    pub fn new_from_srv(chan_id: ChannelId, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::FromSrv, chan_id, vec![], payload)
    }

    /// Creates a new `Close` message.
    pub fn new_close(chan_id: ChannelId) -> Self {
        Self::new(UnOperation::Close, chan_id, vec![], vec![])
    }

    /// Returns the operation code.
    pub fn op(&self) -> UnOperation {
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
        Ok(rkyv::from_bytes::<UnMessage, rkyv::rancor::Error>(buf)?)
    }
}

// vim: ts=4 sw=4 expandtab
