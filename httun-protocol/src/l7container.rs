// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const L7C_OFFS_ADDR: usize = 0;
const L7C_OFFS_PORT: usize = 16;
const L7C_OFFS_PAYLOAD: usize = 18;

const L7C_OVERHEAD_LEN: usize = 16 + 2;
pub const L7C_MAX_PAYLOAD_LEN: usize = crate::message::MAX_PAYLOAD_LEN - L7C_OVERHEAD_LEN;

/// # Message container for L7 payload.
///
/// See `Message` for more information.
///
/// The `L7Container` contains all additional addressing information to
/// successfully deliver the L7 payload to the destination.
#[derive(Clone)]
pub struct L7Container {
    addr: SocketAddr,
    payload: Vec<u8>,
}

impl std::fmt::Debug for L7Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "L7Container {{ addr: {:?} }}", self.addr)
    }
}

impl L7Container {
    pub fn new(addr: SocketAddr, payload: Vec<u8>) -> Self {
        Self { addr, payload }
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn serialize(&self) -> Vec<u8> {
        let addr = match self.addr.ip() {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
            IpAddr::V6(addr) => addr.octets(),
        };
        let port = self.addr.port();

        let mut buf = Vec::with_capacity(self.payload.len() + L7C_OVERHEAD_LEN);
        buf.extend(addr);
        buf.extend(port.to_be_bytes());
        buf.extend(&self.payload);

        buf
    }

    pub fn deserialize(buf: &[u8]) -> ah::Result<Self> {
        if buf.len() < L7C_OVERHEAD_LEN {
            return Err(err!("L7Container size is too small."));
        }
        if buf.len() > L7C_OVERHEAD_LEN + L7C_MAX_PAYLOAD_LEN {
            return Err(err!("L7Container size is too big."));
        }

        let addr = &buf[L7C_OFFS_ADDR..L7C_OFFS_ADDR + 16];
        let port = u16::from_be_bytes(buf[L7C_OFFS_PORT..L7C_OFFS_PORT + 2].try_into()?);
        let payload = &buf[L7C_OFFS_PAYLOAD..];

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
