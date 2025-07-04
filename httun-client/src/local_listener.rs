// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::client::HttunComm;
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{L7C_MAX_PAYLOAD_LEN, L7Container, Message, MsgType, Operation};
use httun_util::{
    errors::DisconnectedError,
    net::{tcp_recv_until_blocking, tcp_send_all},
};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task,
};

const RX_BUF_SIZE: usize = L7C_MAX_PAYLOAD_LEN;

async fn send_close_to_httun(
    comm: &HttunComm,
    target_addr: IpAddr,
    target_port: u16,
) -> ah::Result<()> {
    let buf = vec![]; // Empty buffer signals a closed connection.
    let l7 = L7Container::new(SocketAddr::new(target_addr, target_port), buf);
    let msg = Message::new(MsgType::Data, Operation::L7ToSrv, l7.serialize())
        .context("Make httun packet")?;
    comm.send_to_httun(msg).await;
    Ok(())
}

async fn local_rx(
    stream: Arc<TcpStream>,
    comm: Arc<HttunComm>,
    target_addr: IpAddr,
    target_port: u16,
) -> ah::Result<()> {
    loop {
        let buf = tcp_recv_until_blocking(&stream, RX_BUF_SIZE).await?;

        if buf.is_empty() {
            log::trace!("Local socket: Disconnected.");
            return Err(DisconnectedError.into());
        } else {
            log::trace!(
                "Sending {} bytes from local socket to httun-server.",
                buf.len()
            );
        }

        let l7 = L7Container::new(SocketAddr::new(target_addr, target_port), buf);
        let msg = Message::new(MsgType::Data, Operation::L7ToSrv, l7.serialize())
            .context("Make httun packet")?;

        comm.send_to_httun(msg).await;
    }
}

async fn local_tx(
    stream: Arc<TcpStream>,
    comm: Arc<HttunComm>,
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
        stream.set_linger(None)?;
        stream.set_ttl(255)?;
        Ok(Self {
            stream: Arc::new(stream),
        })
    }

    pub async fn handle_packets(
        &self,
        comm: Arc<HttunComm>,
        target_addr: IpAddr,
        target_port: u16,
    ) -> ah::Result<()> {
        let rx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            let comm = Arc::clone(&comm);
            local_rx(stream, comm, target_addr, target_port)
        });
        let rx_task_handle = rx_task.abort_handle();

        let tx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            let comm = Arc::clone(&comm);
            local_tx(stream, comm, target_addr, target_port)
        });
        let tx_task_handle = tx_task.abort_handle();

        let res = tokio::select! {
            biased;
            ret = rx_task => {
                tx_task_handle.abort();
                ret.context("Local TCP RX")
            }
            ret = tx_task => {
                rx_task_handle.abort();
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
    listener: TcpListener,
}

impl LocalListener {
    pub async fn bind(port: u16) -> ah::Result<Self> {
        let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await?;
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> ah::Result<LocalConn> {
        let (stream, _addr) = self.listener.accept().await?;
        LocalConn::new(stream)
    }
}

// vim: ts=4 sw=4 expandtab
