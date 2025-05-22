// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod errors;
mod query;

pub use errors::DisconnectedError;
pub use query::Query;

pub const CHAN_R_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// vim: ts=4 sw=4 expandtab
