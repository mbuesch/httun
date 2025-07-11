// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use aes_gcm::aead::{AeadCore as _, AeadInPlace as _, KeyInit as _, OsRng};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;

//TODO: Currently we only have a symmetric common secret.
// Add a way to derive a symmetric key from some sort of asymmetric key handshake.
// We should be able to have both, a symmetric user key and an asymmetric user key
// and use them both at the same time.

type Aes256GcmN16 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aes::cipher::consts::U16>;
pub type Key = [u8; 32];
type Nonce = [u8; 16];
const NONCE_LEN: usize = std::mem::size_of::<Nonce>();
const AUTHTAG_LEN: usize = 16;
pub type SessionSecret = [u8; 16];
const SESSION_SECRET_LEN: usize = std::mem::size_of::<SessionSecret>();

pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const OFFS_TYPE: usize = 0;
const OFFS_NONCE: usize = 1;
const OFFS_OPER: usize = 17;
const OFFS_SEQ: usize = 18;
const OFFS_LEN: usize = 26;
const OFFS_PAYLOAD: usize = 28;

const AREA_ASSOC_LEN: usize = 1;
const AREA_CRYPT_LEN: usize = 1 + 8 + 2;
pub const OVERHEAD_LEN: usize = AREA_ASSOC_LEN + NONCE_LEN + AREA_CRYPT_LEN + AUTHTAG_LEN;

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
    Init,
    L4ToSrv,
    L4FromSrv,
    L7ToSrv,
    L7FromSrv,
    TestToSrv,
    TestFromSrv,
}

impl TryFrom<u8> for Operation {
    type Error = ah::Error;

    fn try_from(op: u8) -> ah::Result<Self> {
        const INIT: u8 = Operation::Init as _;
        const L4TOSRV: u8 = Operation::L4ToSrv as _;
        const L4FROMSRV: u8 = Operation::L4FromSrv as _;
        const L7TOSRV: u8 = Operation::L7ToSrv as _;
        const L7FROMSRV: u8 = Operation::L7FromSrv as _;
        const TESTTOSRV: u8 = Operation::TestToSrv as _;
        const TESTFROMSRV: u8 = Operation::TestFromSrv as _;
        match op {
            INIT => Ok(Operation::Init),
            L4TOSRV => Ok(Operation::L4ToSrv),
            L4FROMSRV => Ok(Operation::L4FromSrv),
            L7TOSRV => Ok(Operation::L7ToSrv),
            L7FROMSRV => Ok(Operation::L7FromSrv),
            TESTTOSRV => Ok(Operation::TestToSrv),
            TESTFROMSRV => Ok(Operation::TestFromSrv),
            _ => Err(err!("Invalid Message Operation: {op}")),
        }
    }
}

impl From<Operation> for u8 {
    fn from(op: Operation) -> Self {
        op as Self
    }
}

/// # Main HTTUN message.
///
/// This is the payload/body of the HTTP GET/POST requests.
///
/// In case of POST this is the POST content as application/octet-stream.
/// In case of GET this is base64-urlsafe encoded in the `m` query field.
/// (Because GET should not have content)
///
/// ## Physical message layout
///
/// | Byte offset | Name                 | Byte size | Area  |
/// | ----------- | -------------------- | --------- | ----- |
/// | 0           | Type                 | 1         | assoc |
/// | 1           | Nonce                | 16        | nonce |
/// | 17          | Operation            | 1         | crypt |
/// | 18          | Sequence counter     | 8 (be)    | crypt |
/// | 26          | Payload length       | 2 (be)    | crypt |
/// | 28          | Payload              | var       | crypt |
/// | var         | Authentication tag   | 16        | tag   |
///
/// ## Payload
///
/// The payload of this `Message` depends on the `Operation`.
/// It is either a OSI/ISO L4 packet, a L7 packet or other HTTUN control data.
///
/// In case of a L7 the payload must be a `L7Container`.
#[derive(Clone)]
pub struct Message {
    type_: MsgType,
    oper: Operation,
    sequence: u64,
    payload: Vec<u8>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "Message {{ type: {:?}, oper: {:?}, sequence: 0x{:X} }}",
            self.type_, self.oper, self.sequence
        )
    }
}

impl Message {
    pub fn new(type_: MsgType, oper: Operation, payload: Vec<u8>) -> ah::Result<Self> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(err!("Payload size is too big"));
        }
        Ok(Self {
            type_,
            oper,
            sequence: u64::MAX,
            payload,
        })
    }

    pub fn type_(&self) -> MsgType {
        self.type_
    }

    pub fn oper(&self) -> Operation {
        self.oper
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
        let nonce = Aes256GcmN16::generate_nonce(&mut OsRng);
        let oper: u8 = self.oper.into();
        let sequence: u64 = self.sequence;
        let len: u16 = self.payload.len().try_into().expect("Payload too big");

        let mut buf = Vec::with_capacity(MAX_PAYLOAD_LEN + OVERHEAD_LEN);
        buf.extend(&type_.to_be_bytes());
        buf.extend(&nonce);
        buf.extend(&oper.to_be_bytes());
        buf.extend(&sequence.to_be_bytes());
        buf.extend(&len.to_be_bytes());
        buf.extend(&self.payload);

        let mut assoc_data = [0_u8; SESSION_SECRET_LEN + 1];
        assoc_data[0] = type_;
        assoc_data[1..].copy_from_slice(&session_secret.unwrap_or_default());

        let cipher = Aes256GcmN16::new(key.into());
        let authtag = cipher
            .encrypt_in_place_detached(&nonce, &assoc_data, &mut buf[AREA_ASSOC_LEN + NONCE_LEN..])
            .expect("AEAD encryption failed");

        buf.extend(&authtag);

        assert_eq!(buf.len(), self.payload.len() + OVERHEAD_LEN);
        buf
    }

    pub fn serialize_b64u(&self, key: &Key, session_secret: Option<SessionSecret>) -> String {
        Self::encode_b64u(&self.serialize(key, session_secret))
    }

    pub fn encode_b64u(buf: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(buf)
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

        let cipher = Aes256GcmN16::new(key.into());
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
            sequence,
            payload,
        })
    }

    pub fn deserialize_b64u(
        buf: &str,
        key: &Key,
        session_secret: Option<SessionSecret>,
    ) -> ah::Result<Self> {
        Self::deserialize(&Self::decode_b64u(buf)?, key, session_secret)
    }

    pub fn decode_b64u(buf: &str) -> ah::Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD
            .decode(buf.as_bytes())
            .context("Base64url decode")
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

// vim: ts=4 sw=4 expandtab
