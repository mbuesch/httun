// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

define_simple_error!(DisconnectedError);
define_simple_error!(ConnectionResetError);

// vim: ts=4 sw=4 expandtab
