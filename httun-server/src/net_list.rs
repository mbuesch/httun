// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

/// A list of IP networks.
#[derive(Debug)]
pub struct NetList {
    list: Option<Vec<IpNet>>,
}

/// Result of checking an address against a NetList.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetListCheck {
    NoList,
    Contains,
    Absent,
}

impl NetList {
    /// Create a new NetList from an optional list of string representations of IP addresses or networks.
    pub fn new(nets: Option<&[String]>) -> ah::Result<Self> {
        if let Some(nets) = nets {
            let mut list = Vec::with_capacity(nets.len());
            for net in nets {
                let net = net.trim();
                match net.parse::<IpAddr>() {
                    Ok(addr) => {
                        let prefix_len = match addr {
                            IpAddr::V4(_) => 32,
                            IpAddr::V6(_) => 128,
                        };
                        list.push(IpNet::new(addr, prefix_len)?);
                    }
                    Err(_) => match net.parse::<IpNet>() {
                        Ok(net) => {
                            list.push(net);
                        }
                        Err(e) => {
                            return Err(err!(
                                "Can't parse net address '{net}' from address list: {e}"
                            ));
                        }
                    },
                }
            }
            Ok(Self { list: Some(list) })
        } else {
            Ok(Self { list: None })
        }
    }

    /// Check if the given socket address is contained in the NetList.
    #[must_use]
    pub fn check(&self, sock_addr: &SocketAddr) -> NetListCheck {
        if let Some(list) = &self.list {
            let addr = sock_addr.ip();
            for net in list {
                if net.contains(&addr) {
                    return NetListCheck::Contains;
                }
            }
            NetListCheck::Absent
        } else {
            NetListCheck::NoList
        }
    }

    /// Log the contents of the NetList with the given name.
    pub fn log(&self, name: &str) {
        if log::log_enabled!(log::Level::Info) {
            if let Some(list) = &self.list {
                let list: String = list.iter().map(|a| format!("\"{a:?}\", ")).collect();
                log::info!("{name} = [ {list}]");
            } else {
                log::info!("No {name}");
            }
        }
    }

    /// Check if the NetList is empty.
    pub fn is_empty(&self) -> bool {
        self.list
            .as_ref()
            .map(|list| list.is_empty())
            .unwrap_or(true)
    }
}

// vim: ts=4 sw=4 expandtab
