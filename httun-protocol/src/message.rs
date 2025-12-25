// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{
    key::{KexPublic, SessionKey},
    ser::{De, Ser},
};
use aes_gcm::aead::{AeadCore as _, AeadInPlace as _, KeyInit as _, OsRng};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;
use rand::prelude::*;
use uuid::Uuid;

//TODO: Currently we only have a symmetric common secret.
// Add a way to derive a symmetric key from some sort of asymmetric key handshake.
// We should be able to have both, a symmetric user key and an asymmetric user key
// and use them both at the same time.

/// AES-256-GCM with 160 bit (20 byte) nonce.
type Aes256GcmN160 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aes::cipher::consts::U20>;
/// Nonce type.
type Nonce = [u8; 20];

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
    /// Nonce length.
    const NONCE_LEN: usize = std::mem::size_of::<Nonce>();
    /// Authentication tag length.
    const AUTHTAG_LEN: usize = 16;

    /// Maximum httun payload length.
    pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

    const AREA_ASSOC_LEN: usize = 1;
    const AREA_CRYPT_LEN: usize = 1 + 8 + 2;
    pub(crate) const OVERHEAD_LEN: usize =
        Self::AREA_ASSOC_LEN + Self::NONCE_LEN + Self::AREA_CRYPT_LEN + Self::AUTHTAG_LEN;

    /// Create a new message.
    pub fn new(type_: MsgType, oper: Operation, payload: Vec<u8>) -> ah::Result<Self> {
        if payload.len() > Self::MAX_PAYLOAD_LEN {
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
        // Type conversions.
        let type_: u8 = self.type_.into();
        let nonce = Aes256GcmN160::generate_nonce(&mut OsRng);
        let oper: u8 = self.oper.into();
        let sequence: u64 = self.sequence;
        let payload_len: u16 = self
            .payload
            .len()
            .try_into()
            .context("Payload is too big (>0xFFFF)")?;

        // Serialize all fields into a buffer.
        let ser_len = Self::OVERHEAD_LEN
            .checked_add(payload_len.into())
            .ok_or_else(|| err!("Overflow"))?;
        let mut ser = Ser::new_fixed_size(ser_len);
        ser.push_u8(type_)?;
        ser.push(&nonce)?;
        ser.push_u8(oper)?;
        ser.push_u64(sequence)?;
        ser.push_u16(payload_len)?;
        ser.push(&self.payload)?;

        // In-place encrypt all to-be encrypted fields and authenticate all fields.
        let assoc_data = [type_];
        let cipher = Aes256GcmN160::new(key.key().as_raw_bytes().into());
        let authtag = cipher
            .encrypt_in_place_detached(
                &nonce,
                &assoc_data,
                &mut ser.as_slice_mut()[Self::AREA_ASSOC_LEN + Self::NONCE_LEN..],
            )
            .map_err(|_| err!("AEAD encryption of httun message failed"))?;

        // Append the authentication tag.
        ser.push(&authtag)?;

        ser.into_vec()
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
    pub fn deserialize(mut buf: Vec<u8>, key: &SessionKey) -> ah::Result<Self> {
        // Deserialize the unencrypted and nonce fields at the front of the buffer.
        let mut de = De::new_min_max(
            &buf,
            Self::OVERHEAD_LEN,
            Self::OVERHEAD_LEN + Self::MAX_PAYLOAD_LEN,
        )?;
        let type_ = de.pop_u8()?;
        let nonce: [u8; Self::NONCE_LEN] = de.pop_array()?;

        // Deserialize the auth tag at the end of the buffer.
        let authtag: [u8; Self::AUTHTAG_LEN] = de.pop_back_array()?;

        let de = de.suspend();

        // In-place decrypt all encrypted fields and authenticate all fields.
        let crypt_begin = Self::AREA_ASSOC_LEN + Self::NONCE_LEN;
        let crypt_end = buf.len() - Self::AUTHTAG_LEN;
        let assoc_data = [type_];
        let cipher = Aes256GcmN160::new(key.key().as_raw_bytes().into());
        cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &assoc_data,
                &mut buf[crypt_begin..crypt_end],
                &authtag.into(),
            )
            .map_err(|_| err!("AEAD decryption of httun message failed."))?;

        let mut de = de.resume(&buf);

        // Deserialize all remaining fields that have just been decrypted.
        let oper = de.pop_u8()?;
        let sequence = de.pop_u64()?;
        let len = de.pop_u16()?;
        let remaining_range = de.into_remaining_range();
        let payload = &buf[remaining_range];

        // Type conversions.
        let type_ = type_.try_into()?;
        let oper = oper.try_into()?;
        let len: usize = len.into();
        let payload = payload.to_vec();

        // Check the authenticated message payload length against what's actually been received.
        if len != buf.len() - Self::OVERHEAD_LEN {
            return Err(err!("Invalid payload length."));
        }

        Ok(Message {
            type_,
            oper,
            sequence,
            payload,
        })
    }

    /// Deserialize message from base64url encoded string.
    pub fn deserialize_b64u(buf: Vec<u8>, key: &SessionKey) -> ah::Result<Self> {
        Self::deserialize(Self::decode_b64u(&buf)?, key)
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
        // Deserialize the type field (first field).
        let mut de = De::new_min_max(
            buf,
            Self::OVERHEAD_LEN,
            Self::OVERHEAD_LEN + Self::MAX_PAYLOAD_LEN,
        )?;
        let type_ = de.pop_u8()?;

        type_.try_into()
    }
}

/// Payload for the `Operation::Init` message.
pub struct InitPayload {
    /// The sender's UUID.
    sender_uuid: Uuid,
    /// Public session key for DH key exchange.
    session_public_key: KexPublic,
}

impl InitPayload {
    /// Size of the UUID.
    const UUID_LEN: usize = Uuid::nil().as_bytes().len();

    /// Size of the session public key.
    const SESS_PUB_LEN: usize = KexPublic::byte_len();

    /// Whole payload length.
    const LEN: usize = Self::UUID_LEN + Self::SESS_PUB_LEN;

    /// Create a new `InitPayload` from a session public key.
    pub fn new(sender_uuid: Uuid, session_public_key: KexPublic) -> Self {
        Self {
            sender_uuid,
            session_public_key,
        }
    }

    /// Get the sender UUID from this payload.
    pub fn sender_uuid(&self) -> &Uuid {
        &self.sender_uuid
    }

    /// Get the session public key from this payload.
    pub fn session_public_key(&self) -> &KexPublic {
        &self.session_public_key
    }

    /// Serialize the payload to raw bytes.
    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        let mut ser = Ser::new_fixed_size(Self::LEN);

        ser.push(self.sender_uuid.as_bytes())?;
        ser.push(self.session_public_key.as_raw_bytes())?;

        ser.into_vec()
    }

    /// Deserialize the payload from raw bytes.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        let mut de = De::new_fixed_size(buf, Self::LEN)?;

        let sender_uuid = de.pop(Self::UUID_LEN)?;
        let session_public_key = de.pop(Self::SESS_PUB_LEN)?;

        Ok(InitPayload {
            sender_uuid: Uuid::from_bytes(sender_uuid.try_into()?),
            session_public_key: session_public_key.try_into()?,
        })
    }
}

// vim: ts=4 sw=4 expandtab
