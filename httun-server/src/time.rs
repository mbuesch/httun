// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::SystemTime;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the system time (seconds since unix epoch)")
        .as_secs()
}

pub fn tdiff(a: u64, b: u64) -> i64 {
    a.wrapping_sub(b) as _
}

// vim: ts=4 sw=4 expandtab
