// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[macro_export]
macro_rules! define_simple_error {
    ($name:ident) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                write!(f, std::stringify!($name))
            }
        }

        impl std::error::Error for $name {}
    };
}
pub use define_simple_error;

// Client disconnected.
define_simple_error!(DisconnectedError);

// A received message was invalid or failed validation.
// The connection is still usable.
define_simple_error!(InvalidMessageError);

// The server rejected a request as invalid.
// The connection is still usable.
define_simple_error!(RequestRejectedError);

// vim: ts=4 sw=4 expandtab
