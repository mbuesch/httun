// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::async_task_comm::AsyncTaskComm;
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{L7Container, Message, MsgType, Operation};
use httun_util::{
    errors::DisconnectedError,
    net::{tcp_recv_until_blocking, tcp_send_all},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task,
};

const RX_BUF_SIZE: usize = L7Container::MAX_PAYLOAD_LEN;

async fn send_close_to_httun(
    comm: &AsyncTaskComm,
    target_addr: IpAddr,
    target_port: u16,
) -> ah::Result<()> {
    let buf = vec![]; // Empty buffer signals a closed connection.
    let l7 = L7Container::new(SocketAddr::new(target_addr, target_port), buf);
    let l7 = l7.serialize().context("L7 serialize")?;
    let msg = Message::new(MsgType::Data, Operation::L7ToSrv, l7).context("Make httun packet")?;
    comm.send_to_httun(msg).await;
    Ok(())
}

async fn local_rx(
    stream: Arc<TcpStream>,
    comm: Arc<AsyncTaskComm>,
    target_addr: IpAddr,
    target_port: u16,
) -> ah::Result<()> {
    loop {
        let buf = match tcp_recv_until_blocking(&stream, RX_BUF_SIZE).await {
            Ok(buf) => buf,
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                log::trace!("Local socket: Disconnected.");
                return Err(e);
            }
            Err(e) => {
                return Err(e);
            }
        };
        if !buf.is_empty() {
            log::trace!(
                "Sending {} bytes from local socket to httun-server.",
                buf.len()
            );

            let l7 = L7Container::new(SocketAddr::new(target_addr, target_port), buf);
            let l7 = l7.serialize().context("L7 serialize")?;
            let msg =
                Message::new(MsgType::Data, Operation::L7ToSrv, l7).context("Make httun packet")?;

            comm.send_to_httun(msg).await;
        }
    }
}

async fn local_tx(
    stream: Arc<TcpStream>,
    comm: Arc<AsyncTaskComm>,
    _target_addr: IpAddr,
    _target_port: u16,
) -> ah::Result<()> {
    loop {
        let msg = comm.recv_from_httun().await;

        let l7 = L7Container::deserialize(msg.payload()).context("Deserialize L7 container")?;
        let payload = l7.into_payload();

        if payload.is_empty() {
            log::trace!("Local socket: Httun disconnected.");
        } else {
            log::trace!(
                "Sending {} bytes from httun-server to local socket.",
                payload.len()
            );
            tcp_send_all(&stream, &payload).await?;
        }
    }
}

pub struct LocalConn {
    stream: Arc<TcpStream>,
}

impl LocalConn {
    fn new(stream: TcpStream) -> ah::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_ttl(255)?;
        Ok(Self {
            stream: Arc::new(stream),
        })
    }

    pub async fn handle_packets(
        &self,
        comm: Arc<AsyncTaskComm>,
        target_addr: IpAddr,
        target_port: u16,
    ) -> ah::Result<()> {
        let mut rx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            let comm = Arc::clone(&comm);
            local_rx(stream, comm, target_addr, target_port)
        });

        let mut tx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            let comm = Arc::clone(&comm);
            local_tx(stream, comm, target_addr, target_port)
        });

        let res = tokio::select! {
            biased;
            ret = &mut rx_task => {
                tx_task.abort();
                let _ = tx_task.await;
                ret.context("Local TCP RX")
            }
            ret = &mut tx_task => {
                rx_task.abort();
                let _ = rx_task.await;
                ret.context("Local TCP TX")
            }
        };

        match res {
            Ok(Ok(())) => unreachable!(), // The tasks never return Ok.
            Ok(Err(e)) => {
                let _ = send_close_to_httun(&comm, target_addr, target_port).await;
                Err(e)
            }
            Err(_) => {
                let _ = send_close_to_httun(&comm, target_addr, target_port).await;
                Err(err!("Task join failed"))
            }
        }
    }
}

pub struct LocalListener {
    listener6: Option<TcpListener>,
    listener4: Option<TcpListener>,
}

impl LocalListener {
    pub async fn bind(port: u16) -> ah::Result<Self> {
        let listener6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await;
        let listener4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await;
        if let (Err(e6), Err(e4)) = (&listener6, &listener4) {
            return Err(err!("Failed to bind localhost port {port}: {e6}; {e4}"));
        }
        Ok(Self {
            listener6: listener6.ok(),
            listener4: listener4.ok(),
        })
    }

    async fn accept_one(listener: Option<&TcpListener>) -> std::io::Result<TcpStream> {
        match listener {
            Some(l) => l.accept().await.map(|(stream, _addr)| stream),
            None => std::future::pending().await,
        }
    }

    pub async fn accept(&self) -> ah::Result<LocalConn> {
        let stream = tokio::select! {
            biased;
            r = Self::accept_one(self.listener6.as_ref()) => r?,
            r = Self::accept_one(self.listener4.as_ref()) => r?,
        };
        LocalConn::new(stream)
    }
}

// vim: ts=4 sw=4 expandtab
