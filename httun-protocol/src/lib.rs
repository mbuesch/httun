// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore as _, AeadInPlace as _, AeadMut as _, KeyInit as _, OsRng},
};
use anyhow::{self as ah, format_err as err};
use std::fmt::{Display, Formatter};

pub type Key = [u8; 32];
type Nonce = [u8; 12];
const NONCE_LEN: usize = std::mem::size_of::<Nonce>();

const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

const OFFS_FLAGS: usize = 0;
const OFFS_LEN: usize = 2;
const OFFS_PAYLOAD: usize = 4;

const AUTHTAG_LEN: usize = 16;
pub const OVERHEAD_LEN: usize = 2 + 2 + NONCE_LEN + AUTHTAG_LEN;

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

#[derive(Debug, Clone)]
pub struct Message {
    payload: Vec<u8>,
}

impl Message {
    pub fn new(payload: Vec<u8>) -> ah::Result<Self> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(err!("Payload size is too big"));
        }
        Ok(Self { payload })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self, key: &Key) -> Vec<u8> {
        let flags: u16 = 0;
        let len: u16 = self.payload.len().try_into().expect("Payload too big");

        let mut buf = Vec::with_capacity(MAX_PAYLOAD_LEN + OVERHEAD_LEN);
        buf.extend(&flags.to_be_bytes());
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

    pub fn deserialize(buf: &[u8], key: &Key) -> ah::Result<Self> {
        if buf.len() <= OVERHEAD_LEN {
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

        let _flags = u16::from_be_bytes(plain[OFFS_FLAGS..OFFS_FLAGS + 2].try_into()?);
        let len = u16::from_be_bytes(plain[OFFS_LEN..OFFS_LEN + 2].try_into()?);

        let len: usize = len.into();
        if len != buf.len() - OVERHEAD_LEN {
            return Err(err!("Invalid payload length."));
        }
        let payload = plain[OFFS_PAYLOAD..OFFS_PAYLOAD + len].to_vec();

        Ok(Message { payload })
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let payload = &self.payload[..self.payload.len().min(16)];
        write!(f, "Message {{ payload: {:?} }}", payload)
    }
}

// vim: ts=4 sw=4 expandtab
