// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use httun_protocol::UserSharedSecret;
use httun_util::strings::hex;

/// Generate a new truly random and secure key.
pub async fn run_mode_genkey() -> ah::Result<()> {
    let user_shared_secret = UserSharedSecret::random();
    let key = hex(user_shared_secret.as_raw_bytes());
    println!("shared-secret = \"{key}\"");
    Ok(())
}

// vim: ts=4 sw=4 expandtab
