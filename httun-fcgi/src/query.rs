// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use std::{collections::HashMap, str::FromStr};

const MAX_NR_COMP: usize = 32;

pub struct Query {
    comps: HashMap<String, String>,
}

impl Query {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.comps.get(name).map(|v| v.as_str())
    }
}

impl FromStr for Query {
    type Err = ah::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Ok(Self {
                comps: HashMap::with_capacity(0),
            })
        } else {
            let mut comps = HashMap::with_capacity(MAX_NR_COMP);
            for comp in s.split('&') {
                if !comp.is_empty() {
                    let mut pair = comp.split('=');
                    let Some(name) = pair.next() else {
                        return Err(err!("Invalid query string: No name."));
                    };
                    let Some(value) = pair.next() else {
                        return Err(err!("Invalid query string: No value."));
                    };
                    if pair.next().is_some() {
                        return Err(err!("Invalid query string: Trailing garbage."));
                    }
                    if comps.len() >= MAX_NR_COMP {
                        return Err(err!("Invalid query string: Too many components."));
                    }
                    comps.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
            Ok(Self { comps })
        }
    }
}

// vim: ts=4 sw=4 expandtab
