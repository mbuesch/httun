// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::time::{now, tdiff};
use anyhow::{self as ah, Context as _, format_err as err};
use arc_swap::ArcSwapOption;
use httun_conf::ConfigL7Tunnel;
use httun_protocol::L7Container;
use httun_util::net::{tcp_recv_one, tcp_send_all};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    ffi::CString,
    net::{SocketAddr, TcpStream as StdTcpStream},
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
    time::Duration,
};
use tokio::{net::TcpStream, sync::Notify, time::timeout};

const L7_TIMEOUT_S: i64 = 30;
const RX_BUF_SIZE: usize = 1024 * 64;
const TX_TIMEOUT: Duration = Duration::from_secs(10);
const RX_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct L7Socket {
    socket: Socket,
}

impl L7Socket {
    pub fn connect(bind_device: Option<&str>, remote_addr: &SocketAddr) -> ah::Result<Self> {
        let domain = if remote_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket =
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).context("Create socket")?;

        if let Some(bind_device) = bind_device {
            log::trace!("Binding socket to network interface: {bind_device}");
            let bind_device =
                CString::new(bind_device).context("Convert interface name to C string")?;
            socket
                .bind_device(Some(bind_device.as_bytes()))
                .context("Bind socket to network interface")?;
        }

        log::trace!("Connecting socket to remote: {remote_addr}");
        socket
            .connect(&(*remote_addr).into())
            .context("Connect TUN socket to remote")?;

        Ok(Self { socket })
    }
}

impl TryFrom<L7Socket> for TcpStream {
    type Error = ah::Error;

    fn try_from(socket: L7Socket) -> ah::Result<Self> {
        let stream: StdTcpStream = socket.socket.into();
        stream
            .set_nonblocking(true)
            .context("Set socket non-blocking")?;
        let stream = TcpStream::from_std(stream).context("Create TcpStream")?;
        Ok(stream)
    }
}

#[derive(Debug)]
struct L7Stream {
    remote: SocketAddr,
    stream: TcpStream,
}

impl L7Stream {
    pub fn connect(remote: SocketAddr) -> ah::Result<Self> {
        //TODO apply allowlist/denylist filtering based on address.
        //TODO bind_device
        let stream = L7Socket::connect(None, &remote)?.try_into()?;
        Ok(Self { remote, stream })
    }

    pub fn remote(&self) -> &SocketAddr {
        &self.remote
    }

    pub async fn send_all(&self, data: &[u8]) -> ah::Result<()> {
        tcp_send_all(&self.stream, data).await
    }

    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        tcp_recv_one(&self.stream, RX_BUF_SIZE).await
    }
}

const NO_ACTIVITY: u64 = i64::MAX as u64;

#[derive(Debug)]
pub struct L7State {
    stream: ArcSwapOption<L7Stream>,
    last_activity: AtomicU64,
    connect_notify: Notify,
    disconnect_notify: Notify,
}

impl L7State {
    pub fn new(_conf: &ConfigL7Tunnel) -> Self {
        Self {
            stream: ArcSwapOption::new(None),
            last_activity: AtomicU64::new(NO_ACTIVITY),
            connect_notify: Notify::new(),
            disconnect_notify: Notify::new(),
        }
    }

    fn disconnect(&self, quiet: bool) {
        if !quiet && log::log_enabled!(log::Level::Trace) {
            if let Some(stream) = self.stream.load().as_ref() {
                log::trace!("L7 disconnect from {}", stream.remote());
            }
        }
        self.stream.store(None);
        self.disconnect_notify.notify_one();
    }

    pub async fn send(&self, data: &[u8]) -> ah::Result<()> {
        let cont = L7Container::deserialize(data).context("Unpack L7 control data")?;

        if cont.payload().is_empty() {
            self.disconnect(false);
        } else {
            let mut stream = self.stream.load();
            let mut connect = stream.is_none();
            if let Some(stream) = stream.as_ref() {
                if stream.remote() != cont.addr() {
                    connect = true;
                }
            }
            if connect {
                drop(stream);
                self.disconnect(false);
                log::trace!("Connecting to {}", cont.addr());
                self.stream
                    .store(Some(Arc::new(L7Stream::connect(*cont.addr())?)));
                log::trace!("Connected to {}", cont.addr());
                stream = self.stream.load();
            }

            if let Some(stream) = stream.as_ref() {
                log::trace!("Sending {} bytes to {}", cont.payload().len(), cont.addr());

                match timeout(TX_TIMEOUT, stream.send_all(cont.payload())).await {
                    Err(_) => {
                        // timeout
                        return Err(err!("L7 transmit timeout."));
                    }
                    Ok(Err(e)) => {
                        return Err(e.context("L7 stream send_all"));
                    }
                    Ok(Ok(_)) => (),
                }
            } else {
                return Err(err!("Stream disconnected."));
            }
            drop(stream);

            self.last_activity.store(now(), atomic::Ordering::Relaxed);
            if connect {
                self.connect_notify.notify_one();
            }
        }
        Ok(())
    }

    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        'a: loop {
            let stream = self.stream.load();
            if stream.is_none() {
                drop(stream);
                self.connect_notify.notified().await;
                continue 'a;
            }

            let buf;
            let remote_addr;
            if let Some(stream) = stream.as_ref() {
                remote_addr = *stream.remote();
                log::trace!("Trying to receive from {remote_addr} ...");

                buf = tokio::select! {
                    biased;
                    _ = self.disconnect_notify.notified() => {
                        // disconnected
                        continue 'a;
                    }
                    res = timeout(RX_TIMEOUT, stream.recv()) => {
                        match res {
                            Err(_) => {
                                // timeout
                                continue 'a;
                            }
                            Ok(Ok(buf)) => {
                                // received a buffer
                                buf
                            }
                            Ok(Err(e)) => {
                                return Err(e.context("L7 stream recv"));
                            }
                        }
                    }
                }
            } else {
                return Err(err!("L7 recv: Stream is not connected"));
            };
            drop(stream);

            if buf.is_empty() {
                log::trace!("Remote {remote_addr} disconnected.");
                self.disconnect(true);
            } else {
                log::trace!("Received {} bytes from {}.", buf.len(), remote_addr);
            }

            self.last_activity.store(now(), atomic::Ordering::Relaxed);

            let cont = L7Container::new(remote_addr, buf);
            let data = cont.serialize();

            break Ok(data);
        }
    }

    pub async fn check_timeout(&self) {
        if tdiff(now(), self.last_activity.load(atomic::Ordering::Relaxed)) > L7_TIMEOUT_S {
            self.last_activity
                .store(NO_ACTIVITY, atomic::Ordering::Relaxed);
            log::debug!("Socket timeout.");
            self.disconnect(false);
        }
    }
}

// vim: ts=4 sw=4 expandtab
