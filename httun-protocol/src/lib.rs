// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

//! # httun on-wire protocol
//!
//! ## Physical message layout (unencrypted)
//!
//! | Byte offset | Name               | Byte size |
//! | ----------- | ------------------ | --------- |
//! | 0           | Operation          | 1         |
//! | 1           | Flags              | 1         |
//! | 2           | Session            | 2 (be)    |
//! | 4           | Sequence counter   | 8 (be)    |
//! | 12          | Payload length     | 2 (be)    |
//! | 14          | Payload            | var       |
//!
//! ## Physical message layout (encrypted)
//!
//! | Byte offset | Name               | Byte size |
//! | ----------- | ------------------ | --------- |
//! | 0           | Encrypted message  | var       |
//! | var         | nonce              | 12        |

#![forbid(unsafe_code)]

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore as _, AeadInPlace as _, AeadMut as _, KeyInit as _, OsRng},
};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;
use std::fmt::{Display, Formatter};

pub type Key = [u8; 32];
type Nonce = [u8; 12];
const NONCE_LEN: usize = std::mem::size_of::<Nonce>();
pub type SessionNonce = [u8; 16];

const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const OFFS_OPER: usize = 0;
const OFFS_FLAGS: usize = 1;
const OFFS_SESSION: usize = 2;
const OFFS_SEQ: usize = 4;
const OFFS_LEN: usize = 12;
const OFFS_PAYLOAD: usize = 14;

const AUTHTAG_LEN: usize = 16;
pub const OVERHEAD_LEN: usize = 1 + 1 + 2 + 8 + 2 + NONCE_LEN + AUTHTAG_LEN;

/// Generate a cryptographically secure random token.
pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    // For lengths bigger than 8 bytes the likelyhood of the sanity checks below
    // triggering on good generator is low enough.
    assert!(SZ >= 8);

    // Get secure random bytes from the operating system.
    let mut buf: [u8; SZ] = [0; SZ];
    if getrandom::fill(&mut buf).is_err() {
        panic!("Failed to read secure random bytes from the operating system. (getrandom failed)");
    }

    // Sanity check if getrandom implementation
    // is a no-op or otherwise trivially broken.
    assert_ne!(buf, [0; SZ]);
    assert_ne!(buf, [0xFF; SZ]);
    let first = buf[0];
    assert!(!buf.iter().all(|x| *x == first));
    buf
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Init,
    ToSrv,
    FromSrv,
}

impl TryFrom<u8> for Operation {
    type Error = ah::Error;

    fn try_from(op: u8) -> ah::Result<Self> {
        const INIT: u8 = Operation::Init as _;
        const TOSRV: u8 = Operation::ToSrv as _;
        const FROMSRV: u8 = Operation::FromSrv as _;
        match op {
            INIT => Ok(Operation::Init),
            TOSRV => Ok(Operation::ToSrv),
            FROMSRV => Ok(Operation::FromSrv),
            _ => Err(err!("Invalid Message Operation: {op}")),
        }
    }
}

impl From<Operation> for u8 {
    fn from(op: Operation) -> Self {
        op as Self
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    oper: Operation,
    flags: u8,
    session: u16,
    sequence: u64,
    payload: Vec<u8>,
}

impl Message {
    pub fn new(oper: Operation, payload: Vec<u8>) -> ah::Result<Self> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(err!("Payload size is too big"));
        }
        Ok(Self {
            oper,
            flags: 0,
            session: 0,
            sequence: 0,
            payload,
        })
    }

    pub fn oper(&self) -> Operation {
        self.oper
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn session(&self) -> u16 {
        self.session
    }

    pub fn set_session(&mut self, session: u16) {
        self.session = session;
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn set_sequence(&mut self, sequence: u64) {
        self.sequence = sequence;
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self, key: &Key) -> Vec<u8> {
        let oper: u8 = self.oper.into();
        let flags: u8 = self.flags;
        let session: u16 = self.session;
        let sequence: u64 = self.sequence;
        let len: u16 = self.payload.len().try_into().expect("Payload too big");

        let mut buf = Vec::with_capacity(MAX_PAYLOAD_LEN + OVERHEAD_LEN);
        buf.extend(&oper.to_be_bytes());
        buf.extend(&flags.to_be_bytes());
        buf.extend(&session.to_be_bytes());
        buf.extend(&sequence.to_be_bytes());
        buf.extend(&len.to_be_bytes());
        buf.extend(&self.payload);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .encrypt_in_place(&nonce, &[], &mut buf)
            .expect("AEAD encryption failed");

        buf.extend(&nonce);

        assert_eq!(buf.len(), self.payload.len() + OVERHEAD_LEN);
        buf
    }

    pub fn serialize_b64u(&self, key: &Key) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.serialize(key))
    }

    pub fn deserialize(buf: &[u8], key: &Key) -> ah::Result<Self> {
        if buf.len() < OVERHEAD_LEN {
            return Err(err!("Message size is too small."));
        }
        if buf.len() > OVERHEAD_LEN + MAX_PAYLOAD_LEN {
            return Err(err!("Message size is too big."));
        }

        let ciphertext = &buf[0..buf.len() - NONCE_LEN];
        let nonce = &buf[buf.len() - NONCE_LEN..buf.len()];

        let mut cipher = Aes256Gcm::new(key.into());
        let Ok(plain) = cipher.decrypt(nonce.into(), ciphertext) else {
            return Err(err!("AEAD decrypt failed."));
        };
        if plain.len() + AUTHTAG_LEN + NONCE_LEN != buf.len() {
            return Err(err!("AEAD decrypt failed (invalid plaintext length)."));
        }

        let oper = u8::from_be_bytes(plain[OFFS_OPER..OFFS_OPER + 1].try_into()?);
        let flags = u8::from_be_bytes(plain[OFFS_FLAGS..OFFS_FLAGS + 1].try_into()?);
        let session = u16::from_be_bytes(plain[OFFS_SESSION..OFFS_SESSION + 2].try_into()?);
        let sequence = u64::from_be_bytes(plain[OFFS_SEQ..OFFS_SEQ + 8].try_into()?);
        let len = u16::from_be_bytes(plain[OFFS_LEN..OFFS_LEN + 2].try_into()?);

        let oper = oper.try_into()?;

        let len: usize = len.into();
        if len != buf.len() - OVERHEAD_LEN {
            return Err(err!("Invalid payload length."));
        }
        let payload = plain[OFFS_PAYLOAD..OFFS_PAYLOAD + len].to_vec();

        Ok(Message {
            oper,
            flags,
            session,
            sequence,
            payload,
        })
    }

    pub fn deserialize_b64u(buf: &str, key: &Key) -> ah::Result<Self> {
        Self::deserialize(
            &BASE64_URL_SAFE_NO_PAD
                .decode(buf.as_bytes())
                .context("Base64url decode")?,
            key,
        )
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let payload = &self.payload[..self.payload.len().min(16)];
        write!(f, "Message {{ payload: {:?} }}", payload)
    }
}

// vim: ts=4 sw=4 expandtab
