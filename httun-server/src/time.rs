// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::SystemTime;

/// Get the current time as seconds since the unix epoch.
///
/// Returns a `u64` representing the current time
/// in seconds since January 1, 1970 (the unix epoch).
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the system time (seconds since unix epoch)")
        .as_secs()
}

/// Compute the difference between two timestamps and get a signed result.
///
/// The result is `a - b`, wrapped around on overflow.
/// If `a` is later than `b`, the result is positive.
/// if `a` is earlier than `b`, the result is negative.
pub fn tdiff(a: u64, b: u64) -> i64 {
    a.wrapping_sub(b) as _
}

/// Check whether a timeout has occurred between two timestamps.
///
/// `now` is the current timestamp,
/// `last` is the previous timestamp,
/// `timeout_s` is the timeout duration in seconds.
///
/// Returns `true` if the difference between `now` and `last`
/// is greater than `timeout_s`.
pub fn timed_out(now: u64, last: u64, timeout_s: i64) -> bool {
    tdiff(now, last) > timeout_s
}

/// Check whether a timeout has occurred based on the current time.
pub fn timed_out_now(last: u64, timeout_s: i64) -> bool {
    timed_out(now(), last, timeout_s)
}

// vim: ts=4 sw=4 expandtab
