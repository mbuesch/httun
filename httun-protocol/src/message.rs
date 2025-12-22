// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::key::SessionKey;
use aes_gcm::aead::{AeadCore as _, AeadInPlace as _, KeyInit as _, OsRng};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;
use rand::prelude::*;

//TODO: Currently we only have a symmetric common secret.
// Add a way to derive a symmetric key from some sort of asymmetric key handshake.
// We should be able to have both, a symmetric user key and an asymmetric user key
// and use them both at the same time.

/// AES-256-GCM with 160 bit (20 byte) nonce.
type Aes256GcmN160 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aes::cipher::consts::U20>;
/// Nonce type.
type Nonce = [u8; 20];
/// Nonce length.
const NONCE_LEN: usize = std::mem::size_of::<Nonce>();
/// Authentication tag length.
const AUTHTAG_LEN: usize = 16;

/// Maximum httun payload length.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const OFFS_TYPE: usize = 0;
const OFFS_NONCE: usize = 1;
const OFFS_OPER: usize = 21;
const OFFS_SEQ: usize = 22;
const OFFS_LEN: usize = 30;
const OFFS_PAYLOAD: usize = 32;

const AREA_ASSOC_LEN: usize = 1;
const AREA_CRYPT_LEN: usize = 1 + 8 + 2;
pub const OVERHEAD_LEN: usize = AREA_ASSOC_LEN + NONCE_LEN + AREA_CRYPT_LEN + AUTHTAG_LEN;

/// Basic message type.
///
/// This information will *not* be encrypted.
/// It will only be authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// Initialization message.
    Init = 0,
    /// Data message.
    Data,
}

impl MsgType {
    const MASK: u8 = 0x01;
}

impl TryFrom<u8> for MsgType {
    type Error = ah::Error;

    fn try_from(ty: u8) -> ah::Result<Self> {
        let ty = ty & Self::MASK;

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
        let mut unused: u8 = rand::rng().random();
        unused &= !MsgType::MASK;
        unused | (ty as Self)
    }
}

/// Message operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Initialization.
    Init = 0,
    /// Layer 3 to server.
    L3ToSrv,
    /// Layer 3 from server.
    L3FromSrv,
    /// Layer 7 to server.
    L7ToSrv,
    /// Layer 7 from server.
    L7FromSrv,
    /// Test message to server.
    TestToSrv,
    /// Test message from server.
    TestFromSrv,
}

impl TryFrom<u8> for Operation {
    type Error = ah::Error;

    fn try_from(op: u8) -> ah::Result<Self> {
        const INIT: u8 = Operation::Init as _;
        const L3TOSRV: u8 = Operation::L3ToSrv as _;
        const L3FROMSRV: u8 = Operation::L3FromSrv as _;
        const L7TOSRV: u8 = Operation::L7ToSrv as _;
        const L7FROMSRV: u8 = Operation::L7FromSrv as _;
        const TESTTOSRV: u8 = Operation::TestToSrv as _;
        const TESTFROMSRV: u8 = Operation::TestFromSrv as _;
        match op {
            INIT => Ok(Operation::Init),
            L3TOSRV => Ok(Operation::L3ToSrv),
            L3FROMSRV => Ok(Operation::L3FromSrv),
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
/// It is either a OSI/ISO L3 packet, a L7 packet or other HTTUN control data.
///
/// In case of a L7 the payload must be a `L7Container`.
#[derive(Clone)]
pub struct Message {
    /// Message type.
    type_: MsgType,
    /// Message operation.
    oper: Operation,
    /// Sequence number and sequence type.
    sequence: u64,
    /// Message payload.
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
    /// Create a new message.
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

    /// Get message type.
    pub fn type_(&self) -> MsgType {
        self.type_
    }

    /// Get message operation.
    pub fn oper(&self) -> Operation {
        self.oper
    }

    /// Get sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Set sequence number.
    pub fn set_sequence(&mut self, sequence: u64) {
        self.sequence = sequence;
    }

    /// Get message payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume message and return payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Serialize message into bytes.
    pub fn serialize(&self, key: &SessionKey) -> ah::Result<Vec<u8>> {
        let type_: u8 = self.type_.into();
        let nonce = Aes256GcmN160::generate_nonce(&mut OsRng);
        let oper: u8 = self.oper.into();
        let sequence: u64 = self.sequence;
        let len: u16 = self
            .payload
            .len()
            .try_into()
            .context("Payload is too big (>0xFFFF)")?;

        let mut buf = Vec::with_capacity(MAX_PAYLOAD_LEN + OVERHEAD_LEN);
        buf.extend(&type_.to_be_bytes());
        buf.extend(&nonce);
        buf.extend(&oper.to_be_bytes());
        buf.extend(&sequence.to_be_bytes());
        buf.extend(&len.to_be_bytes());
        buf.extend(&self.payload);

        let assoc_data = [type_];

        let cipher = Aes256GcmN160::new(key.key().as_raw_bytes().into());
        let authtag = cipher
            .encrypt_in_place_detached(&nonce, &assoc_data, &mut buf[AREA_ASSOC_LEN + NONCE_LEN..])
            .map_err(|_| err!("AEAD encryption of httun message failed"))?;

        buf.extend(&authtag);

        assert_eq!(buf.len(), self.payload.len() + OVERHEAD_LEN);
        Ok(buf)
    }

    /// Serialize message into base64url encoded string.
    pub fn serialize_b64u(&self, key: &SessionKey) -> ah::Result<String> {
        Ok(Self::encode_b64u(&self.serialize(key)?))
    }

    /// Encode bytes into base64url string.
    pub fn encode_b64u(buf: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(buf)
    }

    /// Deserialize message from bytes.
    pub fn deserialize(buf: &[u8], key: &SessionKey) -> ah::Result<Self> {
        Self::basic_length_check(buf)?;

        let mut buf = buf.to_vec();
        let buf_len = buf.len();

        let type_ = u8::from_be_bytes(buf[OFFS_TYPE..OFFS_TYPE + 1].try_into()?);
        let nonce: [u8; NONCE_LEN] = buf[OFFS_NONCE..OFFS_NONCE + NONCE_LEN].try_into()?;
        let authtag: [u8; AUTHTAG_LEN] = buf[buf_len - AUTHTAG_LEN..].try_into()?;

        let assoc_data = [type_];

        let cipher = Aes256GcmN160::new(key.key().as_raw_bytes().into());
        cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &assoc_data,
                &mut buf[AREA_ASSOC_LEN + NONCE_LEN..buf_len - AUTHTAG_LEN],
                &authtag.into(),
            )
            .map_err(|_| err!("AEAD decryption of httun message failed."))?;

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

    /// Deserialize message from base64url encoded string.
    pub fn deserialize_b64u(buf: &[u8], key: &SessionKey) -> ah::Result<Self> {
        Self::deserialize(&Self::decode_b64u(buf)?, key)
    }

    /// Decode base64url string into bytes.
    pub fn decode_b64u(buf: &[u8]) -> ah::Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD
            .decode(buf)
            .context("Base64url decode")
    }

    /// Peek message type (`MsgType`) from raw bytes.
    ///
    /// The returned information is not authenticated.
    /// Use [Message::deserialize] to get authenticated data.
    pub fn peek_type(buf: &[u8]) -> ah::Result<MsgType> {
        Self::basic_length_check(buf)?;
        u8::from_be_bytes(buf[OFFS_TYPE..OFFS_TYPE + 1].try_into()?).try_into()
    }

    /// Basic length check of raw message bytes.
    ///
    /// This returns an error if the length is obviously invalid.
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
