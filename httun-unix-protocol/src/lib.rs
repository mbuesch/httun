// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err};
use bincode::serde::{decode_from_slice, encode_to_vec};
use httun_util::header::HttpHeader;
use serde::{Deserialize, Serialize};

const MAX_LEN: usize = u16::MAX as usize * 2;
pub const UNIX_SOCK: &str = "/run/httun-server/httun-server.sock";

#[inline]
fn cfg() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_limit::<MAX_LEN>()
        .with_little_endian()
        .with_fixed_int_encoding()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnMessageHeader {
    body_size: u32,
}

impl UnMessageHeader {
    const SIZE: usize = 4;

    pub fn header_size() -> usize {
        debug_assert_eq!(
            UnMessageHeader::new(0).unwrap().serialize().unwrap().len(),
            Self::SIZE
        );
        Self::SIZE
    }

    pub fn new(body_size: usize) -> ah::Result<Self> {
        Ok(Self {
            body_size: body_size
                .try_into()
                .map_err(|_| err!("UnMessageHeader: Body size is too big"))?,
        })
    }

    pub fn body_size(&self) -> usize {
        self.body_size
            .try_into()
            .expect("UnMessageHeader: Internal size error")
    }

    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(encode_to_vec(self, cfg())?)
    }

    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

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

#[derive(Clone, Deserialize, Serialize)]
pub struct UnMessage {
    op: UnOperation,
    chan_name: String,
    extra_headers: Vec<HttpHeader>,
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

    pub fn new_to_srv_init(chan_name: String) -> Self {
        Self::new(UnOperation::ToSrvInit, chan_name, vec![], vec![])
    }

    pub fn new_from_srv_init(chan_name: String, extra_headers: Vec<HttpHeader>) -> Self {
        Self::new(UnOperation::FromSrvInit, chan_name, extra_headers, vec![])
    }

    pub fn new_keepalive(chan_name: String) -> Self {
        Self::new(UnOperation::Keepalive, chan_name, vec![], vec![])
    }

    pub fn new_to_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ToSrv, chan_name, vec![], payload)
    }

    pub fn new_req_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ReqFromSrv, chan_name, vec![], payload)
    }

    pub fn new_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::FromSrv, chan_name, vec![], payload)
    }

    pub fn new_close(chan_name: String) -> Self {
        Self::new(UnOperation::Close, chan_name, vec![], vec![])
    }

    pub fn op(&self) -> UnOperation {
        self.op
    }

    pub fn chan_name(&self) -> &str {
        &self.chan_name
    }

    pub fn into_extra_headers(self) -> Vec<HttpHeader> {
        self.extra_headers
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(encode_to_vec(self, cfg())?)
    }

    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

// vim: ts=4 sw=4 expandtab
