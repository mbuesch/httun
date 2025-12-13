// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err};
use bincode::serde::{decode_from_slice, encode_to_vec};
use httun_util::header::HttpHeader;
use serde::{Deserialize, Serialize};

/// Maximum length of the serialized message.
const MAX_LEN: usize = u16::MAX as usize * 2;
/// Path to the Unix domain socket used by httun-server.
pub const UNIX_SOCK: &str = "/run/httun-server/httun-server.sock";

/// Configuration for bincode serialization/deserialization.
#[inline]
fn cfg() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_limit::<MAX_LEN>()
        .with_little_endian()
        .with_fixed_int_encoding()
}

/// Header for a Unix domain socket protocol message.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
        Ok(encode_to_vec(self, cfg())?)
    }

    /// Deserializes the header from a byte slice.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

/// Operation code for the Unix domain socket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum UnOperation {
    /// First message to server.
    ToSrvInit,

    /// First message from server.
    FromSrvInit,

    /// Keep-alive message to server.
    Keepalive,

    /// To httun-server.
    ToSrv,

    /// Request FromSrv.
    ReqFromSrv,

    /// From httun-server.
    FromSrv,

    /// Close the connection.
    Close,
}

/// Message for the Unix domain socket protocol.
///
/// The Unix socket is used for communication between
/// the FastCGI daemon (`httun-fcgi`) and the `httun-server``.
#[derive(Clone, Deserialize, Serialize)]
pub struct UnMessage {
    /// Operation code.
    op: UnOperation,
    /// Channel name.
    chan_name: String,
    /// Extra HTTP headers (only for FromSrvInit).
    extra_headers: Vec<HttpHeader>,
    /// Payload data.
    payload: Vec<u8>,
}

impl std::fmt::Debug for UnMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "UnMessage {{ op: {:?}, chan_name: {}, extra_headers: {:?} }}",
            self.op, self.chan_name, self.extra_headers,
        )
    }
}

impl UnMessage {
    /// Create a new Unix domain socket protocol message.
    fn new(
        op: UnOperation,
        chan_name: String,
        extra_headers: Vec<HttpHeader>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            op,
            chan_name,
            extra_headers,
            payload,
        }
    }

    /// Creates a new `ToSrvInit` message.
    pub fn new_to_srv_init(chan_name: String) -> Self {
        Self::new(UnOperation::ToSrvInit, chan_name, vec![], vec![])
    }

    /// Creates a new `FromSrvInit` message.
    pub fn new_from_srv_init(chan_name: String, extra_headers: Vec<HttpHeader>) -> Self {
        Self::new(UnOperation::FromSrvInit, chan_name, extra_headers, vec![])
    }

    /// Creates a new `Keepalive` message.
    pub fn new_keepalive(chan_name: String) -> Self {
        Self::new(UnOperation::Keepalive, chan_name, vec![], vec![])
    }

    /// Creates a new `ToSrv` message.
    pub fn new_to_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ToSrv, chan_name, vec![], payload)
    }

    /// Creates a new `ReqFromSrv` message.
    pub fn new_req_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ReqFromSrv, chan_name, vec![], payload)
    }

    /// Creates a new `FromSrv` message.
    pub fn new_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::FromSrv, chan_name, vec![], payload)
    }

    /// Creates a new `Close` message.
    pub fn new_close(chan_name: String) -> Self {
        Self::new(UnOperation::Close, chan_name, vec![], vec![])
    }

    /// Returns the operation code.
    pub fn op(&self) -> UnOperation {
        self.op
    }

    /// Returns the channel name.
    pub fn chan_name(&self) -> &str {
        &self.chan_name
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
        Ok(encode_to_vec(self, cfg())?)
    }

    /// Deserializes the message from a byte slice.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

// vim: ts=4 sw=4 expandtab
