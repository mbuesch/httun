// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use anyhow as ah;
use bincode::serde::{decode_from_slice, encode_to_vec};
use serde::{Deserialize, Serialize};

const MAX_LEN: usize = u16::MAX as usize * 2;

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
    pub fn header_size() -> usize {
        UnMessageHeader::new(0).serialize().len()
    }

    pub fn new(body_size: usize) -> Self {
        Self {
            body_size: body_size
                .try_into()
                .expect("UnMessageHeader: Body size is too big"),
        }
    }

    pub fn body_size(&self) -> usize {
        self.body_size
            .try_into()
            .expect("UnMessageHeader: Internal size error")
    }

    pub fn serialize(&self) -> Vec<u8> {
        encode_to_vec(self, cfg()).expect("UnMessageHeader serialize failed")
    }

    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum UnOperation {
    /// First message to server.
    Init,

    /// To httun-server.
    ToSrv,

    /// Request FromSrv.
    ReqFromSrv,

    /// From httun-server.
    FromSrv,

    /// Close the connection.
    Close,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnMessage {
    op: UnOperation,
    chan_name: String,
    payload: Vec<u8>,
}

impl UnMessage {
    pub fn new(op: UnOperation, chan_name: String, payload: Vec<u8>) -> Self {
        Self {
            op,
            chan_name,
            payload,
        }
    }

    pub fn new_init(chan_name: String) -> Self {
        Self::new(UnOperation::Init, chan_name, vec![])
    }

    pub fn new_to_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ToSrv, chan_name, payload)
    }

    pub fn new_req_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::ReqFromSrv, chan_name, payload)
    }

    pub fn new_from_srv(chan_name: String, payload: Vec<u8>) -> Self {
        Self::new(UnOperation::FromSrv, chan_name, payload)
    }

    pub fn new_close(chan_name: String) -> Self {
        Self::new(UnOperation::Close, chan_name, vec![])
    }

    pub fn op(&self) -> UnOperation {
        self.op
    }

    pub fn chan_name(&self) -> &str {
        &self.chan_name
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self) -> Vec<u8> {
        encode_to_vec(self, cfg()).expect("UnMessage serialize failed")
    }

    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let (this, _) = decode_from_slice(buf, cfg())?;
        Ok(this)
    }
}

// vim: ts=4 sw=4 expandtab
