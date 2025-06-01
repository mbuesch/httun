// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::client::{FromHttun, ToHttun};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, MsgType, Operation, SockMessage};
use std::{
    net::{IpAddr, SocketAddr},
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
                if n == 0 {
                    return Err(err!("Disconnected."));
                }
                buf.truncate(n);

                log::trace!("Local rx: {}", String::from_utf8_lossy(&buf));

                let smsg = SockMessage::new(SocketAddr::new(target_addr, target_port), buf);

                let msg = Message::new(MsgType::Data, Operation::L7ToSrv, smsg.serialize())
                    .context("Make httun packet")?;

                to_httun.send(msg).await?;
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

        let payload = msg.payload();

        log::trace!("Local tx: {}", String::from_utf8_lossy(payload));

        //TODO

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
        let listener = TcpListener::bind(("localhost", port)).await?;
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> ah::Result<LocalConn> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(LocalConn::new(stream))
    }
}

// vim: ts=4 sw=4 expandtab
