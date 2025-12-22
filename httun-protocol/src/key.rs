// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::random::secure_random;
use anyhow as ah;
use sha3::{Digest as _, Sha3_256};
use subtle::ConstantTimeEq as _;

/// All keys are 256 bit in size.
const KEY_SIZE: usize = 256 / 8;

/// The user provided shared secret.
#[derive(Clone, Default)]
pub struct UserSharedSecret([u8; KEY_SIZE]);

impl UserSharedSecret {
    /// Generate a new random user-shared-secret.
    pub fn random() -> Self {
        Self(secure_random())
    }

    /// Get the raw user secret.
    pub fn as_raw_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for UserSharedSecret {
    fn from(raw: [u8; KEY_SIZE]) -> Self {
        Self(raw)
    }
}

impl std::fmt::Debug for UserSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "UserSharedSecret")
    }
}

/// Key used for encryption/decryption.
#[derive(Clone, Eq)]
pub(crate) struct CipherKey([u8; KEY_SIZE]);

impl CipherKey {
    /// Get the raw key.
    pub(crate) fn as_raw_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl PartialEq for CipherKey {
    /// Constant-time compare.
    fn eq(&self, other: &Self) -> bool {
        self.as_raw_bytes().ct_eq(other.as_raw_bytes()).into()
    }
}

impl std::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "CipherKey")
    }
}

/// Session encryption key.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(CipherKey);

impl SessionKey {
    /// Generate the session key.
    ///
    /// SKEY := SHA3_256(USER_SHARED_SECRET | SESSION_SHARED_SECRET)
    fn new(user_shared_secret: &UserSharedSecret, session_shared_secret: &KexSharedSecret) -> Self {
        let mut h = Sha3_256::new();
        h.update(user_shared_secret.as_raw_bytes());
        h.update(session_shared_secret.as_raw_bytes());
        let digest = h.finalize();
        SessionKey(CipherKey(digest.into()))
    }

    /// Make a new session key for the initialization protocol.
    pub fn make_init(user_shared_secret: &UserSharedSecret) -> Self {
        Self::new(user_shared_secret, &KexSharedSecret::new_for_init())
    }

    /// Make a new session key for the normal session communication.
    pub fn make_session(
        user_shared_secret: &UserSharedSecret,
        session_shared_secret: &KexSharedSecret,
    ) -> Self {
        Self::new(user_shared_secret, session_shared_secret)
    }

    /// Get the key for encryption/decryption.
    pub(crate) fn key(&self) -> &CipherKey {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "SessionKey")
    }
}

/// Diffie-Hellman key exchange for generation of the `SessionSecret`.
pub struct KeyExchange(x25519_dalek::EphemeralSecret);

impl KeyExchange {
    pub fn new() -> Self {
        Self(x25519_dalek::EphemeralSecret::random())
    }

    /// Get the public key.
    pub fn public_key(&self) -> KexPublic {
        KexPublic((&self.0).into())
    }

    /// Do a Diffie-Hellman key exchange to generate the `SessionSecret`.
    pub fn key_exchange(self, remote_public: &KexPublic) -> KexSharedSecret {
        KexSharedSecret::new_from_kex(self.0.diffie_hellman(&remote_public.0))
    }
}

impl std::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "KeyExchange")
    }
}

/// Public key part of the Diffie-Hellman key exchange.
pub struct KexPublic(x25519_dalek::PublicKey);

impl KexPublic {
    /// Get the raw key.
    pub fn as_raw_bytes(&self) -> &[u8; KEY_SIZE] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for KexPublic {
    type Error = ah::Error;

    fn try_from(raw: &[u8]) -> ah::Result<Self> {
        let key: [u8; KEY_SIZE] = raw.try_into()?;
        Ok(Self(key.into()))
    }
}

impl std::fmt::Debug for KexPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "KexPublic")
    }
}

/// The generated shared secret from the Diffie-Hellman key exchange.
pub struct KexSharedSecret([u8; KEY_SIZE]);

impl KexSharedSecret {
    /// Create a new shared secret from key exchange.
    fn new_from_kex(shared_secret: x25519_dalek::SharedSecret) -> Self {
        Self(shared_secret.to_bytes())
    }

    /// Create a new shared secret for protocol init.
    fn new_for_init() -> Self {
        Self([0; KEY_SIZE])
    }

    /// Get the raw shared secret.
    fn as_raw_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for KexSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "KexSharedSecret")
    }
}

// vim: ts=4 sw=4 expandtab
