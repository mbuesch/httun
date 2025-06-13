// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::client::{FromHttun, ToHttun};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{L7Container, Message, MsgType, Operation};
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
        stream.readable().await?;

        let mut buf = vec![0_u8; RX_BUF_SIZE];
        match stream.try_read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);

                if n == 0 {
                    log::trace!("Local rx: Disconnected.");
                } else {
                    log::trace!("Local rx: {}", String::from_utf8_lossy(&buf));
                }

                let l7 = L7Container::new(SocketAddr::new(target_addr, target_port), buf);
                let msg = Message::new(MsgType::Data, Operation::L7ToSrv, l7.serialize())
                    .context("Make httun packet")?;

                to_httun.send(msg).await?;

                if n == 0 {
                    return Err(err!("Disconnected."));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
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

        log::trace!("Local tx: {}", String::from_utf8_lossy(msg.payload()));

        let l7 = L7Container::deserialize(msg.payload()).context("Deserialize L7 container")?;
        let payload = l7.into_payload();

        if payload.is_empty() {
            return Err(err!("Disconnected."));
        }

        let mut count = 0;
        loop {
            stream.writable().await?;
            match stream.try_write(&payload[count..]) {
                Ok(n) => {
                    count += n;
                    assert!(count <= payload.len());
                    if count == payload.len() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
}

pub struct LocalConn {
    stream: Arc<TcpStream>,
}

impl LocalConn {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(stream),
        }
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

        let tx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            local_tx(stream, from_httun, target_addr, target_port)
        });

        tokio::select! {
            ret = rx_task => ret.context("Local TCP RX")?,
            ret = tx_task => ret.context("Local TCP TX")?,
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
        Ok(LocalConn::new(stream))
    }
}

// vim: ts=4 sw=4 expandtab
