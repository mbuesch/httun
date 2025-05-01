// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{channel::Channel, unix_sock::UnixConn};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, Operation, SessionNonce, secure_random};
use httun_tun::TunHandler;
use httun_unix_protocol::{UnMessage, UnOperation};
use std::sync::{
    Arc,
    atomic::{self, AtomicU32},
};
use tokio::{sync::Mutex, task};

const DEBUG: bool = false;

pub struct ProtocolHandler {
    protman: Arc<ProtocolManager>,
    uconn: UnixConn,
    chan: Arc<Channel>,
    tun: Arc<TunHandler>,
    pinned_session: AtomicU32,
}

impl ProtocolHandler {
    pub async fn new(
        protman: Arc<ProtocolManager>,
        uconn: UnixConn,
        chan: Arc<Channel>,
        tun: Arc<TunHandler>,
    ) -> Self {
        Self {
            protman,
            uconn,
            chan,
            tun,
            pinned_session: AtomicU32::new(u32::MAX),
        }
    }

    pub fn chan_name(&self) -> &str {
        self.chan.name()
    }

    pub fn pinned_session(&self) -> Option<u16> {
        let pinned_session = self.pinned_session.load(atomic::Ordering::SeqCst);
        pinned_session.try_into().ok()
    }

    fn pin_session(&self, session: u16) {
        self.pinned_session
            .store(session.into(), atomic::Ordering::SeqCst);
    }

    fn session_id(&self) -> u16 {
        self.chan.session_id()
    }

    async fn create_new_session(&self, session_nonce: SessionNonce) -> u16 {
        let session = self.chan.make_new_session_id();
        self.pin_session(session);
        self.protman
            .kill_old_sessions(self.chan_name(), session)
            .await;
        let _ = session_nonce; //TODO
        session
    }

    pub async fn run(&self) -> ah::Result<()> {
        let Some(umsg) = self.uconn.recv().await.context("Unix socket receive")? else {
            return Err(err!("Disconnected."));
        };

        let umsg_op = umsg.op();
        let msg = Message::deserialize(&umsg.into_payload(), self.chan.key())?;

        //TODO check sequence counter

        match umsg_op {
            UnOperation::ToSrv => {
                if msg.session() != self.session_id() {
                    let umsg = UnMessage::new_close(self.chan_name().to_string());
                    self.uconn.send(&umsg).await.context("Unix socket send")?;

                    return Err(err!("Session mismatch"));
                }
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

                self.chan.log_activity();
            }
            UnOperation::ReqFromSrv => {
                let reply_msg = match msg.oper() {
                    Operation::Init => {
                        let session_nonce: SessionNonce = secure_random();
                        let mut msg = Message::new(Operation::FromSrv, session_nonce.to_vec())
                            .context("Make httun packet")?;
                        msg.set_session(self.create_new_session(session_nonce).await);
                        msg
                    }
                    Operation::FromSrv => {
                        if msg.session() != self.session_id() {
                            let umsg = UnMessage::new_close(self.chan_name().to_string());
                            self.uconn.send(&umsg).await.context("Unix socket send")?;

                            return Err(err!("Session mismatch"));
                        }
                        let payload = if self.chan.is_test_channel() {
                            self.chan.get_pong().await
                        } else {
                            self.tun.recv().await.context("TUN receive")?
                        };

                        let mut msg = Message::new(Operation::FromSrv, payload)
                            .context("Make httun packet")?;
                        msg.set_session(self.session_id());
                        msg
                    }
                    Operation::ToSrv => {
                        return Err(err!(
                            "Received Operation::ToSrv in UnOperation::ReqFromSrv context"
                        ));
                    }
                };

                if DEBUG {
                    println!("TX msg: {reply_msg}");
                }

                let upayload = reply_msg.serialize(self.chan.key());
                let umsg = UnMessage::new_from_srv(self.chan_name().to_string(), upayload);
                self.uconn.send(&umsg).await.context("Unix socket send")?;

                self.chan.log_activity();
            }
            UnOperation::Init | UnOperation::FromSrv | UnOperation::Close => {
                return Err(err!("Received invalid operation: {:?}", umsg_op));
            }
        }

        Ok(())
    }
}

struct ProtocolInstance {
    handle: task::JoinHandle<()>,
    prot: Arc<ProtocolHandler>,
}

impl ProtocolInstance {
    fn new(handle: task::JoinHandle<()>, prot: Arc<ProtocolHandler>) -> Self {
        Self { handle, prot }
    }
}

impl Drop for ProtocolInstance {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub struct ProtocolManager {
    insts: Mutex<Vec<ProtocolInstance>>,
}

impl ProtocolManager {
    pub fn new() -> Arc<Self> {
        Arc::new(ProtocolManager {
            insts: Mutex::new(vec![]),
        })
    }

    pub async fn spawn(
        self: &Arc<Self>,
        uconn: UnixConn,
        chan: Arc<Channel>,
        tun: Arc<TunHandler>,
    ) {
        let prot = Arc::new(ProtocolHandler::new(Arc::clone(self), uconn, chan, tun).await);
        let handle = task::spawn({
            let prot = Arc::clone(&prot);
            async move {
                loop {
                    if let Err(e) = prot.run().await {
                        eprintln!("Client error: {e}");
                        break;
                    }
                }
            }
        });

        let inst = ProtocolInstance::new(handle, prot);
        self.insts.lock().await.push(inst);
    }

    async fn kill_old_sessions(self: &Arc<Self>, chan_name: &str, new_session_id: u16) {
        self.insts.lock().await.retain(|inst| {
            if inst.prot.chan_name() == chan_name {
                if let Some(pinned_session) = inst.prot.pinned_session() {
                    pinned_session == new_session_id
                } else {
                    false
                }
            } else {
                true
            }
        });
    }

    pub async fn check_timeouts(self: &Arc<Self>) {
        self.insts
            .lock()
            .await
            .retain(|inst| !inst.prot.chan.activity_timed_out());
    }
}

// vim: ts=4 sw=4 expandtab
