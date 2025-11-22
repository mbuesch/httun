// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Key;
use httun_util::strings::hex;
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq as _;

/// The default server configuration path, relative to the install prefix.
#[cfg(not(target_os = "windows"))]
const SERVER_CONF_PATH: &str = "etc/httun/server.conf";
#[cfg(target_os = "windows")]
const SERVER_CONF_PATH: &str = "server.conf";

/// The default client configuration path, relative to the install prefix.
#[cfg(not(target_os = "windows"))]
const CLIENT_CONF_PATH: &str = "etc/httun/client.conf";
#[cfg(target_os = "windows")]
const CLIENT_CONF_PATH: &str = "client.conf";

/// Configuration variant.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ConfigVariant {
    /// Parse the configuration as a server configuration.
    #[default]
    Server,
    /// Parse the configuration as a client configuration.
    Client,
}

#[derive(Debug, Clone, Eq)]
pub struct HttpAuth {
    user: String,
    password: Option<String>,
}

impl HttpAuth {
    pub fn new(user: String, password: Option<String>) -> Self {
        HttpAuth { user, password }
    }
    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
}

impl TryFrom<&toml::Value> for HttpAuth {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value
            .as_table()
            .ok_or_else(|| err!("HttpAuth: Expected a table"))?;

        let user = table
            .get("user")
            .ok_or_else(|| err!("HttpAuth: Missing 'user'"))?
            .as_str()
            .ok_or_else(|| err!("HttpAuth: 'user' must be a string"))?
            .to_string();

        let password = table
            .get("password")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Self { user, password })
    }
}

impl PartialEq for HttpAuth {
    fn eq(&self, other: &Self) -> bool {
        let self_user = self.user().as_bytes();
        let other_user = other.user().as_bytes();

        let self_password = self.password().map(|p| p.as_bytes()).unwrap_or(b"");
        let other_password = other.password().map(|p| p.as_bytes()).unwrap_or(b"");

        let user_eq = self_user.ct_eq(other_user);
        let password_eq = self_password.ct_eq(other_password);

        (user_eq & password_eq).into()
    }
}

#[derive(Debug, Clone)]
pub struct ConfigParametersReceive {
    window_length: Option<NonZeroUsize>,
}

impl TryFrom<&toml::Value> for ConfigParametersReceive {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value
            .as_table()
            .ok_or_else(|| err!("parameters.receive: Expected a table"))?;

        let window_length = table
            .get("window-length")
            .map(|v| {
                v.as_integer()
                    .ok_or_else(|| err!("parameters.receive: 'window-length' must be an integer"))
                    .and_then(|i| {
                        if i <= 0 || i > i16::MAX as i64 {
                            Err(err!(
                                "parameters.receive: 'window-length' must between 1 and 0xFFFF"
                            ))
                        } else {
                            Ok(NonZeroUsize::new(i.try_into().unwrap()).unwrap())
                        }
                    })
            })
            .transpose()?;

        Ok(Self { window_length })
    }
}

impl ConfigParametersReceive {
    pub fn window_length(&self) -> NonZeroUsize {
        self.window_length.unwrap_or(1024.try_into().unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct ConfigParameters {
    receive: ConfigParametersReceive,
}

impl TryFrom<&toml::Value> for ConfigParameters {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value
            .as_table()
            .ok_or_else(|| err!("parameters: Expected a table"))?;

        let receive = table
            .get("receive")
            .ok_or_else(|| err!("parameters: Missing 'receive' section"))?;
        let receive = ConfigParametersReceive::try_from(receive)?;

        Ok(Self { receive })
    }
}

impl ConfigParameters {
    pub fn receive(&self) -> &ConfigParametersReceive {
        &self.receive
    }
}

#[derive(Debug, Clone)]
pub struct ConfigL7Tunnel {
    disabled: Option<bool>,
    bind_to_interface: Option<String>,
    address_allowlist: Option<Vec<String>>,
    address_denylist: Option<Vec<String>>,
}

impl TryFrom<&toml::Value> for ConfigL7Tunnel {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value
            .as_table()
            .ok_or_else(|| err!("ConfigL7Tunnel: Expected a table"))?;

        let disabled = table.get("disabled").and_then(|v| v.as_bool());

        let bind_to_interface = table
            .get("bind-to-interface")
            .and_then(|v| v.as_str())
            .map(String::from);

        let address_allowlist = table
            .get("address-allowlist")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        let address_denylist = table
            .get("address-denylist")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        Ok(Self {
            disabled,
            bind_to_interface,
            address_allowlist,
            address_denylist,
        })
    }
}

impl ConfigL7Tunnel {
    fn disabled(&self) -> bool {
        self.disabled.unwrap_or(false)
    }

    pub fn bind_to_interface(&self) -> Option<&str> {
        self.bind_to_interface.as_deref()
    }

    pub fn address_allowlist(&self) -> Option<&[String]> {
        self.address_allowlist.as_deref()
    }

    pub fn address_denylist(&self) -> Option<&[String]> {
        self.address_denylist.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct ConfigChannel {
    disabled: Option<bool>,
    enable_test: Option<bool>,
    urls: Option<Vec<String>>,
    name: String,
    shared_secret: Key,
    tun: Option<String>,
    l7_tunnel: Option<ConfigL7Tunnel>,
    http_basic_auth: Option<HttpAuth>,
    http_allow_compression: Option<bool>,
    https_ignore_tls_errors: Option<bool>,
}

impl TryFrom<&toml::Value> for ConfigChannel {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value
            .as_table()
            .ok_or_else(|| err!("channel: Expected a table"))?;

        let disabled = table.get("disabled").and_then(|v| v.as_bool());

        let enable_test = table.get("enable-test").and_then(|v| v.as_bool());

        let urls = table.get("urls").and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

        let name = table
            .get("name")
            .ok_or_else(|| err!("channel: Missing 'name'"))?
            .as_str()
            .ok_or_else(|| err!("channel: 'name' must be a string"))?
            .to_string();

        let shared_secret = table
            .get("shared-secret")
            .ok_or_else(|| err!("channel: Missing 'shared-secret'"))?
            .as_str()
            .ok_or_else(|| err!("channel: 'shared-secret' must be a string"))?;
        let shared_secret = match parse_hex(shared_secret) {
            Err(e) => {
                return Err(err!(
                    "channel: The value of shared-secret = \"{shared_secret}\" is invalid: {e}"
                ));
            }
            Ok(s) => s,
        };

        let tun = table.get("tun").and_then(|v| v.as_str()).map(String::from);

        let l7_tunnel = table
            .get("l7-tunnel")
            .map(ConfigL7Tunnel::try_from)
            .transpose()?;

        let http_basic_auth = table
            .get("http-basic-auth")
            .map(HttpAuth::try_from)
            .transpose()?;

        let http_allow_compression = table
            .get("http-allow-compression")
            .and_then(|v| v.as_bool());

        let https_ignore_tls_errors = table
            .get("https-ignore-tls-errors")
            .and_then(|v| v.as_bool());

        Ok(Self {
            disabled,
            enable_test,
            urls,
            name,
            shared_secret,
            tun,
            l7_tunnel,
            http_basic_auth,
            http_allow_compression,
            https_ignore_tls_errors,
        })
    }
}

impl ConfigChannel {
    fn disabled(&self) -> bool {
        self.disabled.unwrap_or(false)
    }

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

    pub fn shared_secret(&self) -> &Key {
        &self.shared_secret
    }

    pub fn tun(&self) -> Option<&str> {
        self.tun.as_deref()
    }

    pub fn l7_tunnel(&self) -> Option<&ConfigL7Tunnel> {
        self.l7_tunnel
            .as_ref()
            .and_then(|l| if l.disabled() { None } else { Some(l) })
    }

    pub fn http_basic_auth(&self) -> &Option<HttpAuth> {
        &self.http_basic_auth
    }

    pub fn http_allow_compression(&self) -> bool {
        self.http_allow_compression.unwrap_or(false)
    }

    pub fn https_ignore_tls_errors(&self) -> bool {
        self.https_ignore_tls_errors.unwrap_or(true)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    parameters: ConfigParameters,
    channels: Vec<ConfigChannel>,
}

impl TryFrom<&toml::Value> for Config {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let table = value.as_table().ok_or_else(|| err!("Expected a table"))?;

        let parameters = table
            .get("parameters")
            .ok_or_else(|| err!("Missing 'parameters' section"))?;
        let parameters = ConfigParameters::try_from(parameters)?;

        let channels = table
            .get("channels")
            .ok_or_else(|| err!("Missing 'channels' section"))?
            .as_array()
            .ok_or_else(|| err!("'channels' must be an array"))?
            .iter()
            .map(ConfigChannel::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            parameters,
            channels,
        })
    }
}

impl Config {
    pub fn get_default_path(variant: ConfigVariant) -> PathBuf {
        // The build-time environment variable HTTUN_CONF_PREFIX can be
        // used to give an additional prefix.
        let prefix = match option_env!("HTTUN_CONF_PREFIX") {
            Some(env_prefix) => env_prefix,
            None => {
                #[cfg(not(target_os = "windows"))]
                let prefix = "/";
                #[cfg(target_os = "windows")]
                let prefix = "";
                prefix
            }
        };

        let mut path = PathBuf::new();
        path.push(prefix);
        match variant {
            ConfigVariant::Client => {
                path.push(CLIENT_CONF_PATH);
            }
            ConfigVariant::Server => {
                path.push(SERVER_CONF_PATH);
            }
        }
        path
    }

    pub fn new_parse_file(path: &Path) -> ah::Result<Self> {
        let data = std::fs::read_to_string(path).context("Read configuration file")?;
        let value: toml::Value = toml::from_str(&data).context("Parse configuration file")?;
        let this = Self::try_from(&value)?;
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
            // Compare shared-secret to http-password.
            if let Some(http_basic_auth) = chan.http_basic_auth()
                && let Some(password) = http_basic_auth.password()
                && !password.is_empty()
                && password.trim().to_lowercase() == hex(&chan.shared_secret).trim().to_lowercase()
            {
                return Err(err!(
                    "The values of shared-secret and http_basic_auth.password \
                            are the same. Don't do that! \
                            This destroys httun's security. \
                            Please choose a unique http password."
                ));
            }
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
                if !chan.disabled() {
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
