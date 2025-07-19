// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use httun_protocol::{Key, secure_random};

/// Generate a new truly random and secure key.
pub async fn run_mode_genkey() -> ah::Result<()> {
    let key: Key = secure_random();
    let key: Vec<String> = key.iter().map(|b| format!("{b:02X}")).collect();
    let key: String = key.join("");
    println!("shared-secret = \"{key}\"");
    Ok(())
}

// vim: ts=4 sw=4 expandtab
