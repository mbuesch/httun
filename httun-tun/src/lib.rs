// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;

/// Maximum transmission unit (MTU) size for the TUN interface.
pub const MAX_MTU: i32 = 1024 * 62;
/// Minimum transmission unit (MTU) size for the TUN interface.
pub const MIN_MTU: i32 = 64;
/// Default transmission unit (MTU) size for the TUN interface.
pub const DEFAULT_MTU: i32 = MAX_MTU;

#[cfg(target_os = "linux")]
pub use crate::linux::TunHandler;

// vim: ts=4 sw=4 expandtab
