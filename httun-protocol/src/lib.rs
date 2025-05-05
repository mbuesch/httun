// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

//! # httun on-wire protocol
//!
//! ## Physical message layout
//!
//! | Byte offset | Name                 | Byte size | Area  |
//! | ----------- | -------------------- | --------- | ----- |
//! | 0           | Type                 | 1         | assoc |
//! | 1           | Nonce                | 12        | nonce |
//! | 13          | Operation            | 1         | crypt |
//! | 14          | Session              | 2 (be)    | crypt |
//! | 16          | Sequence counter     | 8 (be)    | crypt |
//! | 24          | Payload length       | 2 (be)    | crypt |
//! | 26          | Payload              | var       | crypt |
//! | var         | Authentication tag   | 16        | tag   |

#![forbid(unsafe_code)]

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore as _, AeadInPlace as _, KeyInit as _, OsRng},
};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;
use std::{
    collections::HashSet,
    fmt::{Display, Formatter},
    num::NonZeroUsize,
};

pub type Key = [u8; 32];
type Nonce = [u8; 12];
const NONCE_LEN: usize = std::mem::size_of::<Nonce>();
const AUTHTAG_LEN: usize = 16;
pub type SessionSecret = [u8; 16];
const SESSION_SECRET_LEN: usize = std::mem::size_of::<SessionSecret>();

const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const OFFS_TYPE: usize = 0;
const OFFS_NONCE: usize = 1;
const OFFS_OPER: usize = 13;
const OFFS_SESSION: usize = 14;
const OFFS_SEQ: usize = 16;
const OFFS_LEN: usize = 24;
const OFFS_PAYLOAD: usize = 26;

const AREA_ASSOC_LEN: usize = 1;
const AREA_CRYPT_LEN: usize = 1 + 2 + 8 + 2;
pub const OVERHEAD_LEN: usize = AREA_ASSOC_LEN + NONCE_LEN + AREA_CRYPT_LEN + AUTHTAG_LEN;

/// Generate a cryptographically secure random token.
pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    // Get secure random bytes from the operating system.
    let mut buf: [u8; SZ] = [0; SZ];
    if getrandom::fill(&mut buf).is_err() {
        panic!("Failed to read secure random bytes from the operating system. (getrandom failed)");
    }

    // For lengths bigger than 11 bytes the likelyhood of the sanity checks below
    // triggering on good generator is low enough.
    if SZ >= 12 {
        // Sanity check if getrandom implementation
        // is a no-op or otherwise trivially broken.
        assert_ne!(buf, [0; SZ]);
        assert_ne!(buf, [0xFF; SZ]);
        let first = buf[0];
        assert!(!buf.iter().all(|x| *x == first));
    }

    buf
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Init,
    Data,
}

impl TryFrom<u8> for MsgType {
    type Error = ah::Error;

    fn try_from(ty: u8) -> ah::Result<Self> {
        const INIT: u8 = MsgType::Init as _;
        const DATA: u8 = MsgType::Data as _;
        match ty {
            INIT => Ok(MsgType::Init),
            DATA => Ok(MsgType::Data),
            _ => Err(err!("Invalid MsgType: {ty}")),
        }
    }
}

impl From<MsgType> for u8 {
    fn from(ty: MsgType) -> Self {
        ty as Self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    ToSrv,
    FromSrv,
}

impl TryFrom<u8> for Operation {
    type Error = ah::Error;

    fn try_from(op: u8) -> ah::Result<Self> {
        const TOSRV: u8 = Operation::ToSrv as _;
        const FROMSRV: u8 = Operation::FromSrv as _;
        match op {
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
    type_: MsgType,
    oper: Operation,
    session: u16,
    sequence: u64,
    payload: Vec<u8>,
}

impl Message {
    pub fn new(type_: MsgType, oper: Operation, payload: Vec<u8>) -> ah::Result<Self> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(err!("Payload size is too big"));
        }
        Ok(Self {
            type_,
            oper,
            session: 0,
            sequence: 0,
            payload,
        })
    }

    pub fn type_(&self) -> MsgType {
        self.type_
    }

    pub fn oper(&self) -> Operation {
        self.oper
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

    pub fn serialize(&self, key: &Key, session_secret: Option<SessionSecret>) -> Vec<u8> {
        let type_: u8 = self.type_.into();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let oper: u8 = self.oper.into();
        let session: u16 = self.session;
        let sequence: u64 = self.sequence;
        let len: u16 = self.payload.len().try_into().expect("Payload too big");

        let mut buf = Vec::with_capacity(MAX_PAYLOAD_LEN + OVERHEAD_LEN);
        buf.extend(&type_.to_be_bytes());
        buf.extend(&nonce);
        buf.extend(&oper.to_be_bytes());
        buf.extend(&session.to_be_bytes());
        buf.extend(&sequence.to_be_bytes());
        buf.extend(&len.to_be_bytes());
        buf.extend(&self.payload);

        let mut assoc_data = [0_u8; SESSION_SECRET_LEN + 1];
        assoc_data[0] = type_;
        assoc_data[1..].copy_from_slice(&session_secret.unwrap_or_default());

        let cipher = Aes256Gcm::new(key.into());
        let authtag = cipher
            .encrypt_in_place_detached(&nonce, &assoc_data, &mut buf[AREA_ASSOC_LEN + NONCE_LEN..])
            .expect("AEAD encryption failed");

        buf.extend(&authtag);

        assert_eq!(buf.len(), self.payload.len() + OVERHEAD_LEN);
        buf
    }

    pub fn serialize_b64u(&self, key: &Key, session_secret: Option<SessionSecret>) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.serialize(key, session_secret))
    }

    pub fn deserialize(
        buf: &[u8],
        key: &Key,
        session_secret: Option<SessionSecret>,
    ) -> ah::Result<Self> {
        Self::basic_length_check(buf)?;

        let mut buf = buf.to_vec();
        let buf_len = buf.len();

        let type_ = u8::from_be_bytes(buf[OFFS_TYPE..OFFS_TYPE + 1].try_into()?);
        let nonce: [u8; NONCE_LEN] = buf[OFFS_NONCE..OFFS_NONCE + NONCE_LEN].try_into()?;
        let authtag: [u8; AUTHTAG_LEN] = buf[buf_len - AUTHTAG_LEN..].try_into()?;

        let mut assoc_data = [0_u8; SESSION_SECRET_LEN + 1];
        assoc_data[0] = type_;
        assoc_data[1..].copy_from_slice(&session_secret.unwrap_or_default());

        let cipher = Aes256Gcm::new(key.into());
        if cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &assoc_data,
                &mut buf[AREA_ASSOC_LEN + NONCE_LEN..buf_len - AUTHTAG_LEN],
                &authtag.into(),
            )
            .is_err()
        {
            return Err(err!("AEAD decrypt failed."));
        }

        let oper = u8::from_be_bytes(buf[OFFS_OPER..OFFS_OPER + 1].try_into()?);
        let session = u16::from_be_bytes(buf[OFFS_SESSION..OFFS_SESSION + 2].try_into()?);
        let sequence = u64::from_be_bytes(buf[OFFS_SEQ..OFFS_SEQ + 8].try_into()?);
        let len = u16::from_be_bytes(buf[OFFS_LEN..OFFS_LEN + 2].try_into()?);

        let type_ = type_.try_into()?;
        let oper = oper.try_into()?;

        let len: usize = len.into();
        if len != buf.len() - OVERHEAD_LEN {
            return Err(err!("Invalid payload length."));
        }
        let payload = buf[OFFS_PAYLOAD..OFFS_PAYLOAD + len].to_vec();

        Ok(Message {
            type_,
            oper,
            session,
            sequence,
            payload,
        })
    }

    pub fn deserialize_b64u(
        buf: &str,
        key: &Key,
        session_secret: Option<SessionSecret>,
    ) -> ah::Result<Self> {
        Self::deserialize(
            &BASE64_URL_SAFE_NO_PAD
                .decode(buf.as_bytes())
                .context("Base64url decode")?,
            key,
            session_secret,
        )
    }

    pub fn peek_type(buf: &[u8]) -> ah::Result<MsgType> {
        Self::basic_length_check(buf)?;
        u8::from_be_bytes(buf[OFFS_TYPE..OFFS_TYPE + 1].try_into()?).try_into()
    }

    fn basic_length_check(buf: &[u8]) -> ah::Result<()> {
        if buf.len() < OVERHEAD_LEN {
            return Err(err!("Message size is too small."));
        }
        if buf.len() > OVERHEAD_LEN + MAX_PAYLOAD_LEN {
            return Err(err!("Message size is too big."));
        }
        Ok(())
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let payload = &self.payload[..self.payload.len().min(16)];
        write!(f, "Message {{ payload: {:?} }}", payload)
    }
}

//TODO use a sequence number offset of 1<<63 for one of the channel directions so that they are never equal.
pub struct SequenceValidator {
    win_len: NonZeroUsize,
    rx_seq: HashSet<u64>,
}

impl SequenceValidator {
    pub fn new(win_len: NonZeroUsize) -> Self {
        Self {
            win_len,
            rx_seq: HashSet::with_capacity(
                win_len.checked_add(1).expect("win_len overflow").into(),
            ),
        }
    }

    pub fn reset(&mut self) {
        self.rx_seq.clear();
    }

    pub fn check_recv_seq(&mut self, msg: &Message) -> ah::Result<()> {
        let sequence = msg.sequence();

        let oldest_seq = self.rx_seq.iter().min().copied();

        if let Some(oldest_seq) = oldest_seq {
            if sequence <= oldest_seq {
                return Err(err!("Message is too old: {sequence} <= {oldest_seq}."));
            }
        }
        if self.rx_seq.contains(&sequence) {
            return Err(err!("Message has already been received."));
        }

        self.rx_seq.insert(sequence);

        if let Some(oldest_seq) = oldest_seq {
            if self.rx_seq.len() > self.win_len.into() {
                self.rx_seq.remove(&oldest_seq);
            }
        }
        assert!(self.rx_seq.len() <= self.win_len.into());

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
