// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow as ah;

/// Notify ready-status to systemd.
pub fn systemd_notify_ready() -> ah::Result<()> {
    sd_notify::notify(&[sd_notify::NotifyState::Ready])?;
    Ok(())
}

// vim: ts=4 sw=4 expandtab
