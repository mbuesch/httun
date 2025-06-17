// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::time::{now, tdiff};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::L7Container;
use httun_tun::TunHandler;
use std::{
    net::SocketAddr,
    sync::atomic::{self, AtomicU64},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::{Mutex, Notify},
};

const L7_TIMEOUT_S: i64 = 30;
const RX_BUF_SIZE: usize = 1024 * 64;

#[derive(Debug)]
struct L7Stream {
    remote: SocketAddr,
    stream: TcpStream,
}

impl L7Stream {
    pub fn new(remote: SocketAddr, stream: TcpStream) -> Self {
        Self { remote, stream }
    }

    pub fn remote(&self) -> &SocketAddr {
        &self.remote
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}

const NO_ACTIVITY: u64 = i64::MAX as u64;

#[derive(Debug)]
pub struct L7State {
    stream: Mutex<Option<L7Stream>>,
    last_activity: AtomicU64,
    connect_notify: Notify,
}

impl L7State {
    pub fn new() -> Self {
        Self {
            stream: Mutex::new(None),
            last_activity: AtomicU64::new(NO_ACTIVITY),
            connect_notify: Notify::new(),
        }
    }

    fn disconnect(stream: &mut Option<L7Stream>) {
        if let Some(stream) = stream.as_ref() {
            log::trace!("L7 disconnect from {}", stream.remote());
        }
        *stream = None;
    }

    pub async fn send(&self, tun: &TunHandler, data: &[u8]) -> ah::Result<()> {
        let cont = L7Container::deserialize(data).context("Unpack L7 control data")?;

        let mut stream = self.stream.lock().await;

        if cont.payload().is_empty() {
            Self::disconnect(&mut stream);
        } else {
            let mut connect = stream.is_none();
            if let Some(stream) = stream.as_ref() {
                if stream.remote() != cont.addr() {
                    connect = true;
                }
            }
            if connect {
                Self::disconnect(&mut stream);
                log::trace!("L7: Connecting to {}", cont.addr());
                *stream = Some(L7Stream::new(
                    *cont.addr(),
                    tun.bind_and_connect_socket(cont.addr())
                        .await
                        .context("Connect L7 socket")?,
                ));
                log::trace!("L7: Connected to {}", cont.addr());
            }

            if let Some(stream) = stream.as_mut() {
                log::trace!(
                    "L7: Sending {} bytes to {}",
                    cont.payload().len(),
                    cont.addr()
                );
                stream
                    .stream_mut()
                    .write_all(cont.payload())
                    .await
                    .context("L7 stream write")?;

                self.last_activity.store(now(), atomic::Ordering::Relaxed);
                if connect {
                    self.connect_notify.notify_one();
                }
            }
        }

        Ok(())
    }

    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        let mut stream = loop {
            {
                let stream = self.stream.lock().await;
                if stream.is_some() {
                    break stream;
                }
            }
            self.connect_notify.notified().await;
        };

        if let Some(stream) = stream.as_mut() {
            log::trace!("L7: Receiving from {} ...", stream.remote());
            let mut buf = vec![0; RX_BUF_SIZE];
            let count = stream
                .stream_mut()
                .read(&mut buf[..])
                .await
                .context("L7 stream read")?;
            buf.truncate(count);
            log::trace!("L7: Received {} bytes from {}", buf.len(), stream.remote());

            self.last_activity.store(now(), atomic::Ordering::Relaxed);

            let cont = L7Container::new(*stream.remote(), buf);
            let data = cont.serialize();

            Ok(data)
        } else {
            Err(err!("L7 recv: Stream is not connected"))
        }
    }

    pub async fn check_timeout(&self) {
        if tdiff(now(), self.last_activity.load(atomic::Ordering::Relaxed)) > L7_TIMEOUT_S {
            self.last_activity
                .store(NO_ACTIVITY, atomic::Ordering::Relaxed);
            log::debug!("L7: Socket timeout.");
            Self::disconnect(&mut *self.stream.lock().await);
        }
    }
}

// vim: ts=4 sw=4 expandtab
