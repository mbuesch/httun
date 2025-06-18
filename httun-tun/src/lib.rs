// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use anyhow::{self as ah, Context as _};
use tokio_tun::Tun;

const MTU: i32 = 1024 * 62;
const RX_BUF_SIZE: usize = 1024 * 64;

pub struct TunHandler {
    tun: Tun,
}

impl TunHandler {
    pub async fn new(name: &str) -> ah::Result<Self> {
        let tun: Tun = Tun::builder()
            .name(name)
            .mtu(MTU)
            .owner(0)
            .group(0)
            .up()
            .build()
            .context("Create tun interface (build)")?
            .pop()
            .context("Create tun interface (pop)")?;
        log::info!("Tun interface: {}", tun.name());

        Ok(Self { tun })
    }

    pub async fn send(&self, buf: &[u8]) -> ah::Result<()> {
        self.tun.send_all(buf).await?;
        Ok(())
    }

    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        let mut data = vec![0; RX_BUF_SIZE];
        let count = self.tun.recv(&mut data).await?;
        data.truncate(count);
        Ok(data)
    }
}

impl std::fmt::Debug for TunHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "TunHandler")
    }
}

// vim: ts=4 sw=4 expandtab
