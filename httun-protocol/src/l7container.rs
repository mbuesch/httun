// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::ser::{De, Ser};
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
    /// Length of the addr field.
    const ADDR_LEN: usize = 16;

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
    pub fn serialize(&self) -> ah::Result<Vec<u8>> {
        // Type conversions.
        let addr = match self.addr.ip() {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
            IpAddr::V6(addr) => addr.octets(),
        };
        let port = self.addr.port();

        // Serialize all fields into a buffer.
        let plen = self.payload.len();
        let len = plen
            .checked_add(Self::OVERHEAD_LEN)
            .ok_or_else(|| err!("Overflow"))?;
        let mut ser = Ser::new_fixed_size(len);
        ser.push(&addr)?;
        ser.push_u16(port)?;
        ser.push(&self.payload)?;

        ser.into_vec()
    }

    /// Deserialize a byte slice into an L7Container.
    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        // Deserialize all fields from the buffer.
        let mut de = De::new_min_max(
            buf,
            Self::OVERHEAD_LEN,
            Self::OVERHEAD_LEN + Self::MAX_PAYLOAD_LEN,
        )?;
        let addr: [u8; Self::ADDR_LEN] = de.pop_array()?;
        let port = de.pop_u16()?;
        let remaining_range = de.into_remaining_range();
        let payload = &buf[remaining_range];

        // Type conversions.
        let addr: Ipv6Addr = addr.into();
        let addr = if let Some(addr) = addr.to_ipv4_mapped() {
            IpAddr::V4(addr)
        } else {
            IpAddr::V6(addr)
        };
        let addr = SocketAddr::new(addr, port);
        let payload = payload.to_vec();

        Ok(Self { addr, payload })
    }
}

// vim: ts=4 sw=4 expandtab
