// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::client::{FromHttun, ToHttun};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{L7Container, Message, MsgType, Operation};
use httun_util::{
    DisconnectedError,
    net::{tcp_recv_one, tcp_send_all},
};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    task,
};

const RX_BUF_SIZE: usize = 1024 * 64;

async fn local_rx(
    stream: Arc<TcpStream>,
    to_httun: Arc<Sender<ToHttun>>,
    target_addr: IpAddr,
    target_port: u16,
) -> ah::Result<()> {
    loop {
        let buf = tcp_recv_one(&stream, RX_BUF_SIZE).await?;

        let disconnected = buf.is_empty();
        if disconnected {
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

        to_httun.send(msg).await?;

        if disconnected {
            return Err(DisconnectedError.into());
        }
    }
}

async fn local_tx(
    stream: Arc<TcpStream>,
    from_httun: Arc<Mutex<Receiver<FromHttun>>>,
    _target_addr: IpAddr,
    _target_port: u16,
) -> ah::Result<()> {
    loop {
        let Some(msg) = from_httun.lock().await.recv().await else {
            return Err(err!("FromHttun IPC closed"));
        };

        let l7 = L7Container::deserialize(msg.payload()).context("Deserialize L7 container")?;
        let payload = l7.into_payload();

        if payload.is_empty() {
            log::trace!("Local socket: Httun disconnected.");
            return Err(DisconnectedError.into());
        }

        log::trace!(
            "Sending {} bytes from httun-server to local socket.",
            payload.len()
        );
        tcp_send_all(&stream, &payload).await?;
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
        to_httun: Arc<Sender<ToHttun>>,
        from_httun: Arc<Mutex<Receiver<FromHttun>>>,
        target_addr: IpAddr,
        target_port: u16,
    ) -> ah::Result<()> {
        let rx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            local_rx(stream, to_httun, target_addr, target_port)
        });
        let rx_task_handle = rx_task.abort_handle();

        let tx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            local_tx(stream, from_httun, target_addr, target_port)
        });
        let tx_task_handle = tx_task.abort_handle();

        tokio::select! {
            biased;
            ret = rx_task => {
                tx_task_handle.abort();
                ret.context("Local TCP RX")??;
            }
            ret = tx_task => {
                rx_task_handle.abort();
                ret.context("Local TCP TX")??;
            }
        }
        Ok(())
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
