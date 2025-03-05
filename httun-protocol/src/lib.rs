// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use anyhow as ah;
use bincode::serde::{decode_from_slice as decode, encode_into_std_write as encode};
use std::fmt::{Display, Formatter};

pub type Key = [u8; 32];
//TODO
//type Nonce = [u8; 12];

const MAX_LEN: usize = 1024 * (64 + 1);

#[inline]
fn cfg() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_limit::<MAX_LEN>()
        .with_little_endian()
        .with_variable_int_encoding()
}

#[derive(Debug, Clone)]
pub struct Message {
    payload: Vec<u8>,
}

impl Message {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self, _key: &Key) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(MAX_LEN);

        encode(&self.payload, &mut buf, cfg()).expect("payload serialize failed");

        //TODO AEAD

        buf
    }

    pub fn deserialize(buf: &[u8], _key: &Key) -> ah::Result<Self> {
        //TODO AEAD

        let (payload, _) = decode(buf, cfg())?;

        Ok(Self { payload })
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let payload = &self.payload[..self.payload.len().min(16)];
        write!(f, "Message {{ payload: {:?} }}", payload)
    }
}

// vim: ts=4 sw=4 expandtab
