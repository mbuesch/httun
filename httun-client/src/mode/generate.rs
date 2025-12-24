// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use httun_protocol::UserSharedSecret;
use httun_util::strings::hex;
use uuid::Uuid;

/// Generate a new truly random and secure key.
pub async fn run_mode_genkey() -> ah::Result<()> {
    let user_shared_secret = UserSharedSecret::random();
    let key = hex(user_shared_secret.as_raw_bytes());
    println!("shared-secret = \"{key}\"");
    Ok(())
}

/// Generate a new truly random and secure UUID.
pub async fn run_mode_genuuid() -> ah::Result<()> {
    let uuid = Uuid::new_v4();
    let uuid = uuid.as_hyphenated();
    println!("uuid = \"{uuid}\"");
    Ok(())
}

// vim: ts=4 sw=4 expandtab
