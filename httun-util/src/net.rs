// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use tokio::net::TcpStream;

pub async fn tcp_recv_until_blocking(stream: &TcpStream, buf_size: usize) -> ah::Result<Vec<u8>> {
    stream.readable().await?;
    let mut count = 0;
    let mut buf = vec![0_u8; buf_size];
    loop {
        match stream.try_read(&mut buf[count..]) {
            Ok(n) => {
                count += n;
                if n == 0 || count >= buf.len() {
                    buf.truncate(count);
                    return Ok(buf);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                buf.truncate(count);
                return Ok(buf);
            }
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                buf.truncate(0);
                return Ok(buf);
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

pub async fn tcp_send_all(stream: &TcpStream, data: &[u8]) -> ah::Result<()> {
    let mut count = 0;
    loop {
        stream.writable().await?;
        match stream.try_write(&data[count..]) {
            Ok(n) => {
                count += n;
                debug_assert!(count <= data.len());
                if count >= data.len() {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
