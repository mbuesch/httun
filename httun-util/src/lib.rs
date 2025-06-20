// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod errors;
pub mod net;
mod query;
mod strings;

pub use errors::DisconnectedError;
pub use query::Query;
pub use strings::{Direction, parse_path};

pub const CHAN_R_TIMEOUT_S: u64 = 5;
pub const CHAN_R_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(CHAN_R_TIMEOUT_S);

// vim: ts=4 sw=4 expandtab
