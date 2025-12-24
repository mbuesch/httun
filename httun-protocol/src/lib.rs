// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

//! # httun on-wire protocol

#![forbid(unsafe_code)]

mod key;
mod l7container;
mod message;
mod random;
mod sequence;

pub use crate::{
    key::{KexPublic, KexSharedSecret, KeyExchange, SessionKey, UserSharedSecret},
    l7container::L7Container,
    message::{InitPayload, Message, MsgType, Operation},
    random::secure_random,
    sequence::{SequenceGenerator, SequenceType, SequenceValidator},
};

// vim: ts=4 sw=4 expandtab
