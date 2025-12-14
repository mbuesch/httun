// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpHeader {
    /// Header name
    name: Vec<u8>,
    /// Header value
    value: Vec<u8>,
}

impl FromStr for HttpHeader {
    type Err = ah::Error;

    /// Creates a new `HttpHeader` from a string slice.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split(':');
        let Some(name) = s.next() else {
            return Err(err!("Http header: Header name (before colon) missing."));
        };
        let Some(value) = s.next() else {
            return Err(err!("Http header: Header value (after colon) missing."));
        };
        Ok(Self {
            name: name.trim().as_bytes().to_vec(),
            value: value.trim().as_bytes().to_vec(),
        })
    }
}

impl HttpHeader {
    /// Creates a new `HttpHeader`.
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
            value: value.to_vec(),
        }
    }

    /// Returns the header name.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the header value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

// vim: ts=4 sw=4 expandtab
