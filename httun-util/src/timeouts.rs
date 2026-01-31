// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::Duration;

/// Timeout for Unix domain socket `FastCGI` connection.
/// The connection is closed after this timeout.
pub const UNIX_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for initial Unix domain socket handshake.
pub const UNIX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Channel read timeout, in seconds.
/// This is the internal channel timeout, excluding HTTP timings (see `HTTP_R_TIMEOUT`).
pub const CHAN_R_TIMEOUT_S: u64 = 5;
/// Channel read timeout.
/// This is the internal channel timeout, excluding HTTP timings (see `HTTP_R_TIMEOUT`).
pub const CHAN_R_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S);
/// Channel activity timeout, in seconds.
/// All channel state is invalidated after this timeout without activity.
pub const CHAN_ACTIVITY_TIMEOUT_S: i64 = 30;

/// HTTP read timeout.
/// This is the external HTTP timeout, including internal channel timings.
pub const HTTP_R_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S + 3);
/// HTTP write timeout.
pub const HTTP_W_TIMEOUT: Duration = Duration::from_secs(3);
/// HTTP TCP user timeout.
/// See tcp (7) man page.
pub const HTTP_TCP_USER_TIMEOUT: Duration = Duration::from_secs(2);

/// Standalone HTTP server pinning timeout.
pub const HTTP_CHANNEL_PIN_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S);

/// L7 tunnel timeout, in seconds.
/// The socket to the target is closed after this timeout of inactivity.
pub const L7_TIMEOUT_S: i64 = 30;
/// L7 socket to target transmit timeout.
pub const L7_TX_TIMEOUT: Duration = Duration::from_secs(10);
/// L7 socket to target receive timeout.
pub const L7_RX_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for receiving ping response.
pub const PONG_RX_TIMEOUT: Duration = Duration::from_millis(1500);

// vim: ts=4 sw=4 expandtab
