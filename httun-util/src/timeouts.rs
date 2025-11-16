// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::Duration;

pub const UNIX_TIMEOUT: Duration = Duration::from_secs(15);
pub const UNIX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub const CHAN_R_TIMEOUT_S: u64 = 5;
pub const CHAN_R_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S);
pub const CHAN_ACTIVITY_TIMEOUT_S: i64 = 30;

pub const HTTP_R_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S + 3);
pub const HTTP_W_TIMEOUT: Duration = Duration::from_secs(3);
pub const HTTP_TCP_USER_TIMEOUT: Duration = Duration::from_secs(2);

pub const L7_TIMEOUT_S: i64 = 30;
pub const L7_TX_TIMEOUT: Duration = Duration::from_secs(10);

// vim: ts=4 sw=4 expandtab
