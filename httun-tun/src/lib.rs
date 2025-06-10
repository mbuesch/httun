// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use anyhow::{self as ah, Context as _, format_err as err};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use tokio::net::TcpStream;
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

    pub async fn bind_and_connect_socket(&self, remote_addr: &SocketAddr) -> ah::Result<TcpStream> {
        if !remote_addr.is_ipv4() {
            return Err(err!("Only IPv4 supported."));
        }

        let local_addr = self.tun.address().context("Get TUN address")?;

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("Create socket")?;
        socket
            .bind(&SocketAddr::new(IpAddr::V4(local_addr), 0).into())
            .context("Bind socket to TUN address")?;
        socket
            .connect(&(*remote_addr).into())
            .context("Connect TUN socket to remote")?;

        let stream: StdTcpStream = socket.into();
        stream
            .set_nonblocking(true)
            .context("Set socket non-blocking")?;
        let stream = TcpStream::from_std(stream).context("Create TcpStream")?;

        Ok(stream)
    }
}

impl std::fmt::Debug for TunHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "TunHandler")
    }
}

// vim: ts=4 sw=4 expandtab
