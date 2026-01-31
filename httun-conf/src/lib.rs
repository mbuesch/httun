// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::UserSharedSecret;
use httun_util::{ChannelId, header::HttpHeader, strings::hex};
use std::{
    collections::HashSet,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

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

/// HTTP basic authentication credentials.
#[derive(Debug, Clone, Eq, Default)]
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
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("http-basic-auth: Expected a table"))?;

        this.user = table
            .get("user")
            .ok_or_else(|| err!("http-basic-auth: Missing 'user'"))?
            .as_str()
            .ok_or_else(|| err!("http-basic-auth: 'user' must be a string"))?
            .to_string();

        if let Some(v) = table.get("password") {
            this.password = Some(
                v.as_str()
                    .ok_or_else(|| err!("http-basic-auth: 'password' must be a string"))?
                    .to_string(),
            );
        }

        Ok(this)
    }
}

impl PartialEq for HttpAuth {
    /// Compares two `HttpAuth` instances in constant time.
    ///
    /// Constant time compare is used to avoid timing attacks.
    fn eq(&self, other: &Self) -> bool {
        let self_user = self.user().as_bytes();
        let other_user = other.user().as_bytes();

        let self_password = self.password().map_or(b"".as_ref(), |p| p.as_bytes());
        let other_password = other.password().map_or(b"".as_ref(), |p| p.as_bytes());

        // Compare in constant time to avoid timing attacks.
        let user_eq = self_user.ct_eq(other_user);
        let password_eq = self_password.ct_eq(other_password);

        (user_eq & password_eq).into()
    }
}

/// Configuration section `[parameters.receive]`.
#[derive(Debug, Clone)]
pub struct ConfigParametersReceive {
    window_length: NonZeroUsize,
}

impl Default for ConfigParametersReceive {
    fn default() -> Self {
        Self {
            window_length: 1024.try_into().unwrap(),
        }
    }
}

impl TryFrom<&toml::Value> for ConfigParametersReceive {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("parameters.receive: Expected a table"))?;

        if let Some(v) = table.get("window-length") {
            this.window_length = v
                .as_integer()
                .ok_or_else(|| err!("parameters.receive: 'window-length' must be an integer"))
                .and_then(|i| {
                    if i <= 0 || i > i64::from(i16::MAX) {
                        Err(err!(
                            "parameters.receive: 'window-length' must between 1 and 0xFFFF"
                        ))
                    } else {
                        Ok(NonZeroUsize::new(i.try_into().unwrap()).unwrap())
                    }
                })?;
        }

        Ok(this)
    }
}

impl ConfigParametersReceive {
    pub fn window_length(&self) -> NonZeroUsize {
        self.window_length
    }
}

/// Configuration section `[parameters]`.
#[derive(Debug, Clone, Default)]
pub struct ConfigParameters {
    receive: ConfigParametersReceive,
}

impl TryFrom<&toml::Value> for ConfigParameters {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("parameters: Expected a table"))?;

        if let Some(v) = table.get("receive") {
            this.receive = ConfigParametersReceive::try_from(v)?;
        }

        Ok(this)
    }
}

impl ConfigParameters {
    pub fn receive(&self) -> &ConfigParametersReceive {
        &self.receive
    }
}

/// Configuration section `[channel.l7-tunnel]`.
#[derive(Debug, Clone, Default)]
pub struct ConfigL7Tunnel {
    disabled: bool,
    bind_to_interface: Option<String>,
    address_allowlist: Option<Vec<String>>,
    address_denylist: Option<Vec<String>>,
}

impl TryFrom<&toml::Value> for ConfigL7Tunnel {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("l7-tunnel: Expected a table"))?;

        if let Some(v) = table.get("disabled") {
            this.disabled = v
                .as_bool()
                .ok_or_else(|| err!("l7-tunnel: 'disabled' must be a boolean"))?;
        }

        if let Some(v) = table.get("bind-to-interface") {
            this.bind_to_interface = Some(
                v.as_str()
                    .ok_or_else(|| err!("l7-tunnel: 'bind-to-interface' must be a string"))?
                    .to_string(),
            );
        }

        if let Some(v) = table.get("address-allowlist") {
            let mut address_allowlist = vec![];
            for addr in v
                .as_array()
                .ok_or_else(|| err!("l7-tunnel: 'address-allowlist' must be an array"))?
            {
                address_allowlist.push(
                    addr.as_str()
                        .ok_or_else(|| {
                            err!("l7-tunnel: 'address-allowlist' elements must be strings")
                        })?
                        .to_string(),
                );
            }
            this.address_allowlist = Some(address_allowlist);
        }

        if let Some(v) = table.get("address-denylist") {
            let mut address_denylist = vec![];
            for addr in v
                .as_array()
                .ok_or_else(|| err!("l7-tunnel: 'address-denylist' must be an array"))?
            {
                address_denylist.push(
                    addr.as_str()
                        .ok_or_else(|| {
                            err!("l7-tunnel: 'address-denylist' elements must be strings")
                        })?
                        .to_string(),
                );
            }
            this.address_denylist = Some(address_denylist);
        }

        Ok(this)
    }
}

impl ConfigL7Tunnel {
    fn disabled(&self) -> bool {
        self.disabled
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

/// Configuration section `[channel.http]`.
#[derive(Debug, Clone)]
pub struct ConfigChannelHttp {
    basic_auth: Option<HttpAuth>,
    allow_compression: bool,
    ignore_tls_errors: bool,
    extra_headers: Vec<HttpHeader>,
}

impl Default for ConfigChannelHttp {
    fn default() -> Self {
        Self {
            basic_auth: None,
            allow_compression: false,
            ignore_tls_errors: true,
            extra_headers: vec![],
        }
    }
}

impl TryFrom<&toml::Value> for ConfigChannelHttp {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("channel.http: Expected a table"))?;

        if let Some(v) = table.get("basic-auth") {
            this.basic_auth = Some(HttpAuth::try_from(v)?);
        }

        if let Some(v) = table.get("allow-compression") {
            this.allow_compression = v
                .as_bool()
                .ok_or_else(|| err!("channel.http: 'allow-compression' must be a boolean"))?;
        }

        if let Some(v) = table.get("ignore-tls-errors") {
            this.ignore_tls_errors = v
                .as_bool()
                .ok_or_else(|| err!("channel.http: 'ignore-tls-errors' must be a boolean"))?;
        }

        if let Some(v) = table.get("extra-headers") {
            for hdr in v
                .as_array()
                .ok_or_else(|| err!("channel.http: 'extra-headers' must be an array"))?
            {
                let hdr = hdr.as_str().ok_or_else(|| {
                    err!("channel.http: 'extra-headers' elements must be strings")
                })?;
                let hdr: HttpHeader = hdr.parse().map_err(|_| {
                    err!("channel.http: 'extra-headers' elements must be colon separated strings")
                })?;
                this.extra_headers.push(hdr);
            }
        }

        Ok(this)
    }
}

impl ConfigChannelHttp {
    pub fn basic_auth(&self) -> Option<&HttpAuth> {
        self.basic_auth.as_ref()
    }

    pub fn allow_compression(&self) -> bool {
        self.allow_compression
    }

    pub fn ignore_tls_errors(&self) -> bool {
        self.ignore_tls_errors
    }

    pub fn extra_headers(&self) -> &[HttpHeader] {
        &self.extra_headers
    }
}

/// Configuration section `[[channel]]`.
#[derive(Debug, Clone)]
pub struct ConfigChannel {
    disabled: bool,
    enable_test: bool,
    urls: Vec<String>,
    alias: Option<String>,
    id: ChannelId,
    shared_secret: UserSharedSecret,
    tun: Option<String>,
    l7_tunnel: Option<ConfigL7Tunnel>,
    http: ConfigChannelHttp,
}

impl Default for ConfigChannel {
    fn default() -> Self {
        Self {
            disabled: Default::default(),
            enable_test: Default::default(),
            urls: Default::default(),
            alias: Default::default(),
            id: Default::default(),
            shared_secret: UserSharedSecret::random(),
            tun: Default::default(),
            l7_tunnel: Default::default(),
            http: Default::default(),
        }
    }
}

impl TryFrom<&toml::Value> for ConfigChannel {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value
            .as_table()
            .ok_or_else(|| err!("channel: Expected a table"))?;

        if let Some(v) = table.get("disabled") {
            this.disabled = v
                .as_bool()
                .ok_or_else(|| err!("channel: 'disabled' must be a boolean"))?;
        }

        if let Some(v) = table.get("enable-test") {
            this.enable_test = v
                .as_bool()
                .ok_or_else(|| err!("channel: 'enable-test' must be a boolean"))?;
        }

        if let Some(v) = table.get("urls") {
            for url in v
                .as_array()
                .ok_or_else(|| err!("channel: 'urls' must be an array"))?
            {
                this.urls.push(
                    url.as_str()
                        .ok_or_else(|| err!("channel: 'urls' elements must be strings"))?
                        .to_string(),
                );
            }
        }

        if let Some(v) = table.get("alias") {
            this.alias = Some(
                v.as_str()
                    .ok_or_else(|| err!("channel: 'alias' must be a string"))?
                    .to_string(),
            );
        }

        this.id = table
            .get("id")
            .ok_or_else(|| err!("channel: Missing 'id'"))?
            .as_integer()
            .ok_or_else(|| err!("channel: 'id' must be an integer"))?
            .try_into()
            .map_err(|_| err!("channel: 'id' must be between 0 and {}", Self::ID_MAX))?;
        if this.id > Self::ID_MAX {
            return Err(err!("channel: 'id' must be between 0 and {}", Self::ID_MAX));
        }

        let shared_secret = table
            .get("shared-secret")
            .ok_or_else(|| err!("channel: Missing 'shared-secret'"))?
            .as_str()
            .ok_or_else(|| err!("channel: 'shared-secret' must be a string"))?;
        this.shared_secret = match parse_hex(shared_secret) {
            Err(e) => {
                return Err(err!(
                    "channel: The value of shared-secret = \"{shared_secret}\" is invalid: {e}"
                ));
            }
            Ok(s) => s.into(),
        };

        if let Some(v) = table.get("tun") {
            this.tun = Some(
                v.as_str()
                    .ok_or_else(|| err!("channel: 'tun' must be a string"))?
                    .to_string(),
            );
        }

        if let Some(v) = table.get("l7-tunnel") {
            this.l7_tunnel = Some(ConfigL7Tunnel::try_from(v)?);
        }

        if let Some(v) = table.get("http") {
            this.http = ConfigChannelHttp::try_from(v)?;
        }

        Ok(this)
    }
}

impl ConfigChannel {
    pub const ID_MAX: ChannelId = i16::MAX as ChannelId;
    pub const ID_INVALID: ChannelId = Self::ID_MAX + 1;

    fn disabled(&self) -> bool {
        self.disabled
    }

    pub fn enable_test(&self) -> bool {
        self.enable_test
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    pub fn has_url(&self, url: &str) -> bool {
        fn clean(u: &str) -> String {
            u.trim().trim_end_matches('/').to_lowercase()
        }

        let url = clean(url);
        for list_url in self.urls() {
            if clean(list_url) == url {
                return true;
            }
        }
        false
    }

    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    pub fn shared_secret(&self) -> &UserSharedSecret {
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

    pub fn http(&self) -> &ConfigChannelHttp {
        &self.http
    }
}

/// Configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    uuid: Uuid,
    parameters: ConfigParameters,
    channels: Vec<ConfigChannel>,
}

impl TryFrom<&toml::Value> for Config {
    type Error = ah::Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        let mut this: Self = Default::default();

        let table = value.as_table().ok_or_else(|| err!("Expected a table"))?;

        if let Some(v) = table.get("uuid") {
            this.uuid = v
                .as_str()
                .ok_or_else(|| err!("'uuid' must be a string"))?
                .parse()
                .context("Parse config 'uuid'")?;
        }
        if this.uuid.is_nil() || this.uuid.is_max() {
            return Err(err!(
                "The 'uuid' is invalid. Please generate a valid uuid with httun-client gen-uuid."
            ));
        }

        if let Some(v) = table.get("parameters") {
            this.parameters = ConfigParameters::try_from(v)?;
        }

        if let Some(v) = table.get("channels") {
            this.channels = v
                .as_array()
                .ok_or_else(|| err!("'channels' must be an array"))?
                .iter()
                .map(ConfigChannel::try_from)
                .collect::<Result<Vec<_>, _>>()?;
        }

        Ok(this)
    }
}

impl Config {
    #[allow(clippy::single_match_else)]
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

    pub fn new_parse_file(path: &Path, variant: ConfigVariant) -> ah::Result<Self> {
        let data = std::fs::read_to_string(path).context("Read configuration file")?;
        let value: toml::Value = toml::from_str(&data).context("Parse configuration file")?;
        let this = Self::try_from(&value)?;
        this.check(variant)?;
        Ok(this)
    }

    pub fn parse_file(&mut self, path: &Path, variant: ConfigVariant) -> ah::Result<()> {
        *self = Self::new_parse_file(path, variant)?;
        Ok(())
    }

    fn check(&self, variant: ConfigVariant) -> ah::Result<()> {
        if variant == ConfigVariant::Server {
            // Check whether channel IDs are unique.
            let ids: HashSet<ChannelId> = self.channels.iter().map(ConfigChannel::id).collect();
            if ids.len() != self.channels.len() {
                return Err(err!("The configuration contains duplicate channel IDs."));
            }
        }

        // Validate all keys
        for chan in self.channels_iter() {
            // Compare shared-secret to http-password.
            if let Some(http_basic_auth) = chan.http().basic_auth()
                && let Some(password) = http_basic_auth.password()
                && !password.is_empty()
                && password.trim().to_lowercase()
                    == hex(chan.shared_secret.as_raw_bytes()).trim().to_lowercase()
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

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn channels_iter(&self) -> ChanIter<'_> {
        ChanIter {
            config: self,
            index: 0,
        }
    }

    pub fn channel_by_id(&self, id: ChannelId) -> Option<&ConfigChannel> {
        self.channels_iter().find(|chan| chan.id() == id)
    }

    pub fn channel_by_alias(&self, alias: &str) -> Option<&ConfigChannel> {
        self.channels_iter()
            .find(|chan| chan.alias() == Some(alias))
    }

    pub fn channel_by_url(&self, id: ChannelId, url: &str) -> Option<&ConfigChannel> {
        self.channels_iter()
            .find(|chan| chan.id() == id && chan.has_url(url))
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
            }
            let index = self.index;
            self.index += 1;
            let chan = &self.config.channels[index];
            if !chan.disabled() {
                return Some(chan);
            }
        }
    }
}

/// Parse a hex digit.
/// `s` must be a string of length 1.
fn parse_hexdigit(s: &str) -> ah::Result<u8> {
    assert_eq!(s.len(), 1);
    Ok(u8::from_str_radix(s, 16)?)
}

/// Parse a hex string into a byte array.
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
        ret[i] = parse_hexdigit(&s[(i * 2)..=(i * 2)])? << 4;
        ret[i] |= parse_hexdigit(&s[(i * 2 + 1)..=(i * 2 + 1)])?;
    }
    Ok(ret)
}

// vim: ts=4 sw=4 expandtab
