// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{
    net_list::{NetList, NetListCheck},
    time::{now, timed_out_now},
};
use anyhow::{self as ah, Context as _, format_err as err};
use arc_swap::ArcSwapOption;
use httun_conf::ConfigL7Tunnel;
use httun_protocol::L7Container;
use httun_util::{
    net::{tcp_recv_until_blocking, tcp_send_all},
    timeouts::{L7_RX_TIMEOUT, L7_TIMEOUT_S, L7_TX_TIMEOUT},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{SocketAddr, TcpStream as StdTcpStream},
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
};
use tokio::{net::TcpStream, sync::Notify, time::timeout};

/// Size of the receive buffer.
const RX_BUF_SIZE: usize = L7Container::MAX_PAYLOAD_LEN;

/// L7 socket.
///
/// Used to connect to a remote TCP address with optional binding to a specific
/// network interface.
///
/// Converts into a non-blocking tokio [TcpStream].
#[derive(Debug)]
struct L7Socket {
    socket: Socket,
}

impl L7Socket {
    /// Connect to the remote address, optionally binding to a specific network interface.
    pub fn connect(bind_device: Option<&str>, remote_addr: &SocketAddr) -> ah::Result<Self> {
        let domain = if remote_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket =
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).context("Create socket")?;

        if let Some(bind_device) = bind_device {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                log::trace!("Binding socket to network interface: {bind_device}");
                let bind_device = std::ffi::CString::new(bind_device)
                    .context("Convert interface name to C string")?;
                socket
                    .bind_device(Some(bind_device.as_bytes()))
                    .context("Bind socket to network interface")?;
            }
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            {
                let _ = bind_device;
                return Err(err!(
                    "l7-tunnel.bind-to-interface is not supported on this OS."
                ));
            }
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

    /// Convert L7Socket into a non-blocking tokio TcpStream.
    fn try_from(socket: L7Socket) -> ah::Result<Self> {
        let stream: StdTcpStream = socket.socket.into();
        stream
            .set_nonblocking(true)
            .context("Set socket non-blocking")?;
        let stream = TcpStream::from_std(stream).context("Create TcpStream")?;
        Ok(stream)
    }
}

/// L7 socket stream.
///
/// Used to send and receive data to/from a remote TCP address.
/// This is used by the tunnel endpoint to connect to the target server.
#[derive(Debug)]
struct L7Stream {
    /// Remote socket address.
    remote: SocketAddr,
    /// TCP stream.
    stream: TcpStream,
}

impl L7Stream {
    /// Connect to the remote address.
    pub fn connect(conf: &ConfigL7Tunnel, remote: SocketAddr) -> ah::Result<Self> {
        let socket = L7Socket::connect(conf.bind_to_interface(), &remote)?;
        let stream = socket.try_into()?;
        Ok(Self { remote, stream })
    }

    /// Get the remote socket address.
    pub fn remote(&self) -> &SocketAddr {
        &self.remote
    }

    /// Send all data to the remote.
    pub async fn send_all(&self, data: &[u8]) -> ah::Result<()> {
        tcp_send_all(&self.stream, data).await
    }

    /// Receive data from the remote.
    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        tcp_recv_until_blocking(&self.stream, RX_BUF_SIZE).await
    }
}

const NO_ACTIVITY: u64 = i64::MAX as u64;

/// State of an L7 (socket) tunnel connection.
#[derive(Debug)]
pub struct L7State {
    /// Configuration of the L7 tunnel.
    conf: ConfigL7Tunnel,
    /// Current L7 stream (socket) connection.
    /// This is used by the tunnel endpoint to send and receive data to/from the remote target.
    stream: ArcSwapOption<L7Stream>,
    /// Timestamp of the last activity on the L7 stream.
    last_activity: AtomicU64,
    /// Notify for new connections.
    connect_notify: Notify,
    /// Notify for disconnections.
    disconnect_notify: Notify,
    /// Address allowlist.
    allowlist: NetList,
    /// Address denylist.
    denylist: NetList,
}

impl L7State {
    /// Create a new L7 tunnel state from the configuration.
    pub fn new(conf: &ConfigL7Tunnel) -> ah::Result<Self> {
        let allowlist = NetList::new(conf.address_allowlist())
            .context("Parse config l7-tunnel.address-allowlist")?;
        allowlist.log("l7-tunnel.address-allowlist");

        let denylist = NetList::new(conf.address_denylist())
            .context("Parse config l7-tunnel.address-denylist")?;
        denylist.log("l7-tunnel.address-denylist");

        if !allowlist.is_empty() && denylist.is_empty() {
            log::warn!(
                "\
                An l7-tunnel.address-allowlist is configured, \
                but the l7-tunnel.address-denylist is empty. \
                The allowlist does not have en effect!\
            "
            );
        }

        if let Some(bind_device) = conf.bind_to_interface() {
            log::info!("l7-tunnel.bind-to-interface = \"{bind_device}\"");
        }

        Ok(Self {
            conf: conf.clone(),
            stream: ArcSwapOption::new(None),
            last_activity: AtomicU64::new(NO_ACTIVITY),
            connect_notify: Notify::new(),
            disconnect_notify: Notify::new(),
            allowlist,
            denylist,
        })
    }

    /// Do the actions required to create a new httun session.
    pub fn create_new_session(&self) {
        self.disconnect(false);
    }

    /// Disconnect the current L7 stream to/from the remote target.
    fn disconnect(&self, quiet: bool) {
        if !quiet
            && log::log_enabled!(log::Level::Trace)
            && let Some(stream) = self.stream.load().as_ref()
        {
            log::trace!("L7 disconnect from {}", stream.remote());
        }
        self.stream.store(None);
        self.disconnect_notify.notify_one();
    }

    /// Send data to the remote target.
    pub async fn send(&self, data: &[u8]) -> ah::Result<()> {
        let cont = L7Container::deserialize(data).context("Unpack L7 control data")?;
        let addr = cont.addr();

        // Check if the target address is allowed.
        match self.denylist.check(addr) {
            NetListCheck::NoList | NetListCheck::Absent => {
                // No denylist or address is not in denylist.
                // Allow address.
            }
            NetListCheck::Contains => {
                match self.allowlist.check(addr) {
                    NetListCheck::NoList | NetListCheck::Absent => {
                        // Address not in allowlist and denylist matched.
                        return Err(err!("l7-tunnel.address-denylist contains {addr}"));
                    }
                    NetListCheck::Contains => {
                        // Address is in allowlist. This overrides denylist.
                        // Allow address.
                    }
                }
            }
        }

        if cont.payload().is_empty() {
            // Payload is empty.
            // The httun-clients wants us to disconnect the socket to the target.
            self.disconnect(false);
        } else {
            let mut stream = self.stream.load();

            // Need to connect, if no stream or remote address changed.
            let mut connect = stream.is_none();
            if let Some(stream) = stream.as_ref()
                && stream.remote() != addr
            {
                // Remote address changed. Need to reconnect.
                connect = true;
            }

            // (Re-)connect if needed.
            if connect {
                drop(stream);
                self.disconnect(false);
                log::trace!("Connecting to {addr}");
                self.stream
                    .store(Some(Arc::new(L7Stream::connect(&self.conf, *addr)?)));
                log::trace!("Connected to {addr}");
                stream = self.stream.load();
            }

            // Send the payload to the remote target.
            if let Some(stream) = stream.as_ref() {
                log::trace!("Sending {} bytes to {}", cont.payload().len(), addr);

                match timeout(L7_TX_TIMEOUT, stream.send_all(cont.payload())).await {
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

            // Update last activity timestamp.
            self.last_activity.store(now(), atomic::Ordering::Relaxed);
            // Notify receivers about the new connection.
            if connect {
                self.connect_notify.notify_one();
            }
        }
        Ok(())
    }

    /// Receive data from the remote target.
    pub async fn recv(&self) -> ah::Result<Vec<u8>> {
        'a: loop {
            let stream = self.stream.load();

            // There is no connection yet. Wait for a connection.
            if stream.is_none() {
                drop(stream);
                self.connect_notify.notified().await;
                continue 'a;
            }

            // Try to receive data from the remote target.
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
                    res = timeout(L7_RX_TIMEOUT, stream.recv()) => {
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

            // Check if the remote disconnected (the receive buffer is empty).
            if buf.is_empty() {
                log::trace!("Remote {remote_addr} disconnected.");
                self.disconnect(true);
            } else {
                log::trace!("Received {} bytes from {}.", buf.len(), remote_addr);
            }

            // Update last activity timestamp.
            self.last_activity.store(now(), atomic::Ordering::Relaxed);

            // Pack the received data into an L7 container.
            let cont = L7Container::new(remote_addr, buf);
            let data = cont.serialize().context("L7 packing")?;

            break Ok(data);
        }
    }

    /// Check for timeout and disconnect if timed out.
    pub fn check_timeout(&self) {
        if timed_out_now(
            self.last_activity.load(atomic::Ordering::Relaxed),
            L7_TIMEOUT_S,
        ) {
            self.last_activity
                .store(NO_ACTIVITY, atomic::Ordering::Relaxed);
            log::debug!("Socket timeout.");
            self.disconnect(false);
        }
    }
}

// vim: ts=4 sw=4 expandtab
