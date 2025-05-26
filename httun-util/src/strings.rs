// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub fn path_is_valid(path: &[u8]) -> bool {
    path.iter()
        .all(|c| c.is_ascii_alphanumeric() || [b'-', b'_', b'/'].contains(c))
}

// vim: ts=4 sw=4 expandtab
