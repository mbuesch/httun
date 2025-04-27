// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{channel::Channel, unix_sock::UnixConn};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Message;
use httun_tun::TunHandler;
use httun_unix_protocol::{UnMessage, UnOperation};
use std::sync::Arc;

const DEBUG: bool = false;

pub struct ProtocolHandler {
    uconn: UnixConn,
    chan: Arc<Channel>,
    tun: Arc<TunHandler>,
}

impl ProtocolHandler {
    pub async fn new(uconn: UnixConn, chan: Arc<Channel>, tun: Arc<TunHandler>) -> Self {
        Self { uconn, chan, tun }
    }

    pub async fn run(&mut self) -> ah::Result<()> {
        let Some(umsg) = self.uconn.recv().await.context("Unix socket receive")? else {
            return Err(err!("Disconnected."));
        };

        match umsg.op() {
            UnOperation::ToSrv => {
                let msg = Message::deserialize(&umsg.into_payload(), self.chan.key())?;
                if DEBUG {
                    println!("RX msg: {msg}");
                }

                if self.chan.is_test_channel() {
                    println!(
                        "Received test mode ping: '{}'",
                        String::from_utf8_lossy(msg.payload())
                    );
                    self.chan.put_ping(msg.into_payload()).await;
                } else {
                    self.tun.send(msg.payload()).await.context("TUN send")?;
                }
            }
            UnOperation::ReqFromSrv => {
                let payload = if self.chan.is_test_channel() {
                    self.chan.get_pong().await
                } else {
                    self.tun.recv().await.context("TUN receive")?
                };

                let msg = Message::new(payload).context("Make httun packet")?;
                if DEBUG {
                    println!("TX msg: {msg}");
                }

                let upayload = msg.serialize(self.chan.key());
                let umsg = UnMessage::new_from_srv(self.chan.name().to_string(), upayload);
                self.uconn.send(&umsg).await.context("Unix socket send")?;
            }
            UnOperation::Init | UnOperation::FromSrv => {
                return Err(err!("Received invalid operation: {:?}", umsg.op()));
            }
        }

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
