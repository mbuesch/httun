// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

/// Generate a cryptographically secure random token.
pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    // Get secure random bytes from the operating system.
    let mut buf: [u8; SZ] = [0; SZ];
    if getrandom::fill(&mut buf).is_err() {
        panic!("Failed to read secure random bytes from the operating system. (getrandom failed)");
    }

    // For lengths bigger than 11 bytes the likelyhood of the sanity checks below
    // triggering on good generator is low enough.
    if SZ >= 12 {
        // Sanity check if getrandom implementation
        // is a no-op or otherwise trivially broken.
        assert_ne!(buf, [0; SZ]);
        assert_ne!(buf, [0xFF; SZ]);
        let first = buf[0];
        assert!(!buf.iter().all(|x| *x == first));
    }

    buf
}

// vim: ts=4 sw=4 expandtab
