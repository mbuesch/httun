// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

//! # httun on-wire protocol

#![forbid(unsafe_code)]

mod l7container;
mod message;
mod random;
mod sequence;

pub use crate::{
    l7container::L7Container,
    message::{Key, Message, MsgType, Operation, SessionSecret},
    random::secure_random,
    sequence::{SequenceGenerator, SequenceType, SequenceValidator},
};

// vim: ts=4 sw=4 expandtab
