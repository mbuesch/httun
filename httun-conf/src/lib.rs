// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Key;
use serde::Deserialize;
use std::path::Path;
use toml::{Value, map::Map};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    keys: Map<String, Value>,
}

impl Config {
    pub fn new_parse_file(path: &Path) -> ah::Result<Self> {
        let data = std::fs::read_to_string(path).context("Read configuration file")?;
        let this: Self = toml::from_str(&data).context("Parse configuration file")?;
        this.check()?;
        Ok(this)
    }

    pub fn parse_file(&mut self, path: &Path) -> ah::Result<()> {
        *self = Self::new_parse_file(path)?;
        Ok(())
    }

    fn check(&self) -> ah::Result<()> {
        // Check [keys] section.
        for (key, value) in self.keys.iter() {
            if let Err(e) = parse_key(value) {
                return Err(err!("The value of '{key}' under [keys] is invalid: {e}"));
            }
        }
        Ok(())
    }

    pub fn keys_iter(&self) -> KeysIter<'_> {
        KeysIter {
            inner_iter: self.keys.iter(),
        }
    }

    pub fn key(&self, channel: &str) -> Option<Key> {
        self.keys
            .get(channel)
            .map(|v| parse_key(v).expect("Parse key failed"))
    }
}

pub struct KeysIter<'a> {
    inner_iter: toml::map::Iter<'a>,
}

impl Iterator for KeysIter<'_> {
    type Item = (String, Key);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((k, v)) = self.inner_iter.next() {
            let v = parse_key(v).expect("Parse key failed");
            Some((k.to_string(), v))
        } else {
            None
        }
    }
}

fn parse_hexdigit(s: &str) -> ah::Result<u8> {
    assert_eq!(s.len(), 1);
    Ok(u8::from_str_radix(s, 16)?)
}

fn parse_hex<const SIZE: usize>(s: &str) -> ah::Result<[u8; SIZE]> {
    let s = s.trim();
    if !s.is_ascii() {
        return Err(err!("Hex string contains invalid characters."));
    }
    let len = s.len();
    if len != SIZE * 2 {
        return Err(err!(
            "Hex string is not correct: Expected {}, got {} chars",
            SIZE * 2,
            len,
        ));
    }
    let mut ret = [0; SIZE];
    for i in 0..SIZE {
        ret[i] = parse_hexdigit(&s[i * 2..i * 2 + 1])? << 4;
        ret[i] |= parse_hexdigit(&s[i * 2 + 1..i * 2 + 2])?;
    }
    Ok(ret)
}

fn parse_key(v: &Value) -> ah::Result<Key> {
    if let Value::String(v) = v {
        parse_hex(v)
    } else {
        Err(err!("Key is not a string"))
    }
}

// vim: ts=4 sw=4 expandtab
