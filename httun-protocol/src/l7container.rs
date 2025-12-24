// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// # Message container for L7 payload.
///
/// See `Message` for more information.
///
/// The `L7Container` contains all additional addressing information to
/// successfully deliver the L7 payload to the destination.
#[derive(Clone)]
pub struct L7Container {
    /// Destination address for the L7 payload.
    addr: SocketAddr,
    /// L7 payload data.
    payload: Vec<u8>,
}

impl std::fmt::Debug for L7Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "L7Container {{ addr: {:?} }}", self.addr)
    }
}

impl L7Container {
    // Raw byte offsets.
    const OFFS_ADDR: usize = 0;
    const OFFS_PORT: usize = 16;
    const OFFS_PAYLOAD: usize = 18;

    /// Overhead of the L7Container in bytes.
    const OVERHEAD_LEN: usize = 16 + 2;
    /// Maximum payload length of the L7Container in bytes.
    pub const MAX_PAYLOAD_LEN: usize =
        crate::message::Message::MAX_PAYLOAD_LEN - Self::OVERHEAD_LEN;

    /// Create a new L7Container.
    ///
    /// `addr` is the destination address for the L7 payload.
    /// `payload` is the L7 payload data.
    pub fn new(addr: SocketAddr, payload: Vec<u8>) -> Self {
        Self { addr, payload }
    }

    /// Get the destination address.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Get the L7 payload data.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the container and return the L7 payload data.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Serialize the L7Container into a byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let addr = match self.addr.ip() {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
            IpAddr::V6(addr) => addr.octets(),
        };
        let port = self.addr.port();

        let mut buf = Vec::with_capacity(self.payload.len() + Self::OVERHEAD_LEN);
        buf.extend(addr);
        buf.extend(port.to_be_bytes());
        buf.extend(&self.payload);

        buf
    }

    /// Deserialize a byte slice into an L7Container.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        if buf.len() < Self::OVERHEAD_LEN {
            return Err(err!("L7Container size is too small."));
        }
        if buf.len() > Self::OVERHEAD_LEN + Self::MAX_PAYLOAD_LEN {
            return Err(err!("L7Container size is too big."));
        }

        let addr = &buf[Self::OFFS_ADDR..Self::OFFS_ADDR + 16];
        let port = u16::from_be_bytes(buf[Self::OFFS_PORT..Self::OFFS_PORT + 2].try_into()?);
        let payload = &buf[Self::OFFS_PAYLOAD..];

        let addr: [u8; 16] = addr.try_into()?;
        let addr: Ipv6Addr = addr.into();
        let addr = if let Some(addr) = addr.to_ipv4_mapped() {
            IpAddr::V4(addr)
        } else {
            IpAddr::V6(addr)
        };

        Ok(Self {
            addr: SocketAddr::new(addr, port),
            payload: payload.to_vec(),
        })
    }
}

// vim: ts=4 sw=4 expandtab
