// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use crate::linux::{DEFAULT_MTU, MAX_MTU, MIN_MTU, TunHandler};

// vim: ts=4 sw=4 expandtab
