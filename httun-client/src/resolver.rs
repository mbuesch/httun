// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use dns_lookup::{AddrFamily, AddrInfoHints, getaddrinfo};
use std::net::IpAddr;
use tokio::task::spawn_blocking;

/// Host name resolution target mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ResMode {
    /// Resolve to IPv6.
    #[default]
    Ipv6,

    /// Resolve to IPv4.
    Ipv4,
}

/// Resolve a host name into an address.
pub async fn resolve(host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    let hints = AddrInfoHints {
        address: if mode == ResMode::Ipv4 {
            AddrFamily::Inet.into()
        } else {
            AddrFamily::Inet6.into()
        },
        ..AddrInfoHints::default()
    };

    let sockets = spawn_blocking({
        let host = host.to_string();
        move || getaddrinfo(Some(&host), None, Some(hints))
    })
    .await
    .context("Failed to spawn blocking task for DNS lookup")?
    .map_err(|e| err!("Failed to perform DNS lookup: {e:?}"))?;

    for sock in sockets {
        if let Ok(sock) = sock
            && ((mode == ResMode::Ipv4 && sock.sockaddr.is_ipv4())
                || (mode == ResMode::Ipv6 && sock.sockaddr.is_ipv6()))
        {
            return Ok(sock.sockaddr.ip());
        }
    }

    Err(err!(
        "DNS lookup of host '{host}' failed. No '{}' record found.",
        if mode == ResMode::Ipv4 { "A" } else { "AAAA" }
    ))
}

// vim: ts=4 sw=4 expandtab
