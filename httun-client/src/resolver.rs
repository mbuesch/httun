// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use hickory_resolver::{
    TokioResolver,
    config::ResolverConfig,
    lookup::Lookup,
    name_server::TokioConnectionProvider,
    proto::rr::{record_data::RData, record_type::RecordType},
};
use std::net::IpAddr;

/// Host name resolution target mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ResMode {
    /// Resolve to IPv6.
    #[default]
    Ipv6,

    /// Resolve to IPv4.
    Ipv4,
}

/// Host name resolution service.
#[derive(Clone, Debug)]
pub struct ResSrv {
    /// Use the resolver from system configuration.
    pub system: bool,

    /// Use Quad9 DNS.
    pub quad9: bool,

    /// Use Google DNS.
    pub google: bool,

    /// Use Cloudflare DNS.
    pub cloudflare: bool,
}

impl Default for ResSrv {
    fn default() -> Self {
        Self {
            system: true,
            quad9: true,
            google: true,
            cloudflare: true,
        }
    }
}

/// Host name resolution encryption.
#[derive(Clone, Debug)]
pub struct ResCrypt {
    /// Try DNS over TLS.
    pub tls: bool,

    /// Try DNS over HTTPS.
    pub https: bool,

    /// Try unencrypted DNS.
    pub unencrypted: bool,
}

impl Default for ResCrypt {
    fn default() -> Self {
        Self {
            tls: true,
            https: true,
            unencrypted: true,
        }
    }
}

/// Host name resolution configuration.
#[derive(Clone, Debug, Default)]
pub struct ResConf {
    /// Resolution mode: IPv4 or IPv6?
    pub mode: ResMode,

    /// Resolution service.
    pub srv: ResSrv,

    /// Resolution encryption.
    pub crypt: ResCrypt,
}

/// Determine the DNS record type from the address resolution mode.
fn get_record_type(mode: ResMode) -> (RecordType, &'static str) {
    match mode {
        ResMode::Ipv6 => (RecordType::AAAA, "AAAA"),
        ResMode::Ipv4 => (RecordType::A, "A"),
    }
}

/// Return the first address that matches the requested address resolution mode.
fn get_first_result(lookup: Lookup, host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    for addr in lookup {
        match (mode, addr) {
            (ResMode::Ipv6, RData::AAAA(addr)) => return Ok(addr.0.into()),
            (ResMode::Ipv4, RData::A(addr)) => return Ok(addr.0.into()),
            _ => (),
        }
    }
    let (_, record_type_str) = get_record_type(mode);
    Err(err!(
        "No IP address found for host '{host}'. No '{record_type_str}' record found."
    ))
}

/// Resolve a host name into an address.
pub async fn resolve(host: &str, cfg: &ResConf) -> ah::Result<IpAddr> {
    // Try to parse host as an IP address.
    if let Ok(addr) = host.parse::<IpAddr>() {
        match cfg.mode {
            ResMode::Ipv4 if !addr.is_ipv4() => {
                return Err(err!(
                    "Supplied a raw IPv6 address, but resolution mode is set to IPv4"
                ));
            }
            ResMode::Ipv6 if !addr.is_ipv6() => {
                return Err(err!(
                    "Supplied a raw IPv4 address, but resolution mode is set to IPv6"
                ));
            }
            _ => (),
        }
        // It is an IP address. No need for DNS lookup.
        return Ok(addr);
    }

    let (record_type, record_type_str) = get_record_type(cfg.mode);

    macro_rules! lookup_and_return {
        ($conf:expr) => {
            if let Ok(l) =
                TokioResolver::builder_with_config($conf, TokioConnectionProvider::default())
                    .build()
                    .lookup(host, record_type)
                    .await
            {
                return get_first_result(l, host, cfg.mode);
            }
        };
    }

    if cfg.srv.system {
        if let Ok(builder) = TokioResolver::builder_tokio()
            && let Ok(lookup) = builder.build().lookup(host, record_type).await
        {
            return get_first_result(lookup, host, cfg.mode);
        }
        #[cfg(not(target_os = "android"))]
        eprintln!(
            "Warning: Could not create DNS resolver from system configuration. \
             Is /etc/resolv.conf present? Falling back to other DNS servers."
        );
    }

    if cfg.crypt.tls {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::quad9_tls());
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::google_tls());
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::cloudflare_tls());
        }
    }

    if cfg.crypt.https {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::quad9_https());
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::google_https());
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::cloudflare_https());
        }
    }

    if cfg.crypt.unencrypted {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::quad9());
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::google());
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::cloudflare());
        }
    }

    Err(err!(
        "DNS lookup of host '{host}' failed. No '{record_type_str}' record found."
    ))
}

// vim: ts=4 sw=4 expandtab
