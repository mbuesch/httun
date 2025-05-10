// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Key;
use serde::Deserialize;
use std::{num::NonZeroUsize, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct HttpAuth {
    user: String,
    password: Option<String>,
}

impl HttpAuth {
    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigParametersReceive {
    #[serde(alias = "window-length")]
    window_length: Option<NonZeroUsize>,
}

impl ConfigParametersReceive {
    pub fn window_length(&self) -> NonZeroUsize {
        self.window_length.unwrap_or(128.try_into().unwrap())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigParameters {
    receive: ConfigParametersReceive,
}

impl ConfigParameters {
    pub fn receive(&self) -> &ConfigParametersReceive {
        &self.receive
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigChannel {
    disabled: Option<bool>,
    #[serde(alias = "enable-test")]
    enable_test: Option<bool>,
    urls: Option<Vec<String>>,
    name: String,
    #[serde(alias = "shared-secret")]
    shared_secret: String,
    tun: Option<String>,
    #[serde(alias = "http-basic-auth")]
    http_basic_auth: Option<HttpAuth>,
    #[serde(alias = "http-allow-compression")]
    http_allow_compression: Option<bool>,
}

impl ConfigChannel {
    pub fn enable_test(&self) -> bool {
        self.enable_test.unwrap_or(false)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn urls(&self) -> Option<&Vec<String>> {
        self.urls.as_ref()
    }

    pub fn has_url(&self, url: &str) -> bool {
        fn clean(u: &str) -> String {
            u.trim().trim_end_matches('/').to_lowercase()
        }

        let url = clean(url);
        for list_url in self.urls().unwrap_or(&vec![]) {
            if clean(list_url) == url {
                return true;
            }
        }
        false
    }

    pub fn shared_secret(&self) -> Key {
        parse_hex(&self.shared_secret).expect("Invalid key format")
    }

    pub fn tun(&self) -> Option<&str> {
        self.tun.as_deref()
    }

    pub fn http_basic_auth(&self) -> &Option<HttpAuth> {
        &self.http_basic_auth
    }

    pub fn http_allow_compression(&self) -> bool {
        self.http_allow_compression.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    parameters: ConfigParameters,
    channels: Vec<ConfigChannel>,
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
        // Validate all keys
        for chan in self.channels_iter() {
            let shared_secret: ah::Result<Key> = parse_hex(&chan.shared_secret);
            if let Err(e) = shared_secret {
                return Err(err!(
                    "The value of shared-secret = \"{}\" is invalid: {}",
                    chan.shared_secret,
                    e
                ));
            }
            //TODO compare the key to http_basic_auth.password. Must not be the same!
        }
        Ok(())
    }

    pub fn channels_iter(&self) -> ChanIter<'_> {
        ChanIter {
            config: self,
            index: 0,
        }
    }

    pub fn channel(&self, channel: &str) -> Option<&ConfigChannel> {
        self.channels_iter().find(|chan| chan.name() == channel)
    }

    pub fn channel_with_url(&self, url: &str, channel: &str) -> Option<&ConfigChannel> {
        self.channels_iter()
            .find(|chan| chan.name() == channel && chan.has_url(url))
    }

    pub fn parameters(&self) -> &ConfigParameters {
        &self.parameters
    }
}

pub struct ChanIter<'a> {
    config: &'a Config,
    index: usize,
}

impl<'a> Iterator for ChanIter<'a> {
    type Item = &'a ConfigChannel;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.index >= self.config.channels.len() {
                return None;
            } else {
                let index = self.index;
                self.index += 1;
                let chan = &self.config.channels[index];
                if !chan.disabled.unwrap_or(false) {
                    return Some(chan);
                }
            }
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

// vim: ts=4 sw=4 expandtab
