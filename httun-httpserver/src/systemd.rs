// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

/// Notify ready-status to systemd.
pub fn systemd_notify_ready() -> ah::Result<()> {
    // This function can only be called once.
    static ONCE: AtomicBool = AtomicBool::new(false);
    if ONCE.fetch_or(true, SeqCst) {
        return Err(err!("systemd_notify_ready() called twice"));
    }

    sd_notify::notify(&[sd_notify::NotifyState::Ready])?;

    Ok(())
}

// vim: ts=4 sw=4 expandtab
