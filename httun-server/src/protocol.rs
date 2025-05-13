// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Session},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, MsgType, Operation, SequenceType, SessionSecret, secure_random};
use httun_tun::TunHandler;
use std::sync::{
    Arc,
    atomic::{self, AtomicU32},
};
use tokio::{sync::Mutex, task};

const DEBUG: bool = false;

pub struct ProtocolHandler {
    protman: Arc<ProtocolManager>,
    comm: CommBackend,
    chan: Arc<Channel>,
    pinned_session: AtomicU32,
}

impl ProtocolHandler {
    pub async fn new(protman: Arc<ProtocolManager>, comm: CommBackend, chan: Arc<Channel>) -> Self {
        Self {
            protman,
            comm,
            chan,
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

    fn session(&self) -> Session {
        self.chan.session()
    }

    async fn create_new_session(&self, session_secret: SessionSecret) -> u16 {
        let session_id = self.chan.create_new_session(session_secret);
        self.pin_session(session_id);
        self.protman
            .kill_old_sessions(self.chan_name(), session_id)
            .await;
        session_id
    }

    async fn check_rx_sequence(
        &self,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        self.chan.check_rx_sequence(msg, sequence_type).await
    }

    fn tun(&self) -> &TunHandler {
        self.chan.tun()
    }

    async fn send_close(&self) -> ah::Result<()> {
        self.comm.send_close(self.chan_name()).await
    }

    async fn send_msg(&self, msg: Message, session: Session) -> ah::Result<()> {
        if DEBUG {
            println!("TX msg: {msg}");
        }

        let payload = msg.serialize(self.chan.key(), session.secret);
        self.comm.send(self.chan_name(), payload).await?;

        self.chan.log_activity();

        Ok(())
    }

    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let session = self.session();

        let msg = Message::deserialize(&payload, self.chan.key(), session.secret)?;
        let oper = msg.oper();

        if msg.session() != session.id {
            let _ = self.send_close().await;
            return Err(err!("Session mismatch"));
        }

        self.check_rx_sequence(&msg, SequenceType::B)
            .await
            .context("rx sequence validation SequenceType::B")?;

        if DEBUG {
            println!("RX msg: {msg}");
        }

        match oper {
            Operation::ToSrv => {
                self.tun().send(msg.payload()).await.context("TUN send")?;
            }
            Operation::TestToSrv if self.chan.test_enabled() => {
                println!(
                    "Received test mode ping: '{}'",
                    String::from_utf8_lossy(msg.payload())
                );
                self.chan.put_ping(msg.into_payload()).await;
            }
            _ => {
                let _ = self.send_close().await;
                return Err(err!("Received {oper:?} in UnOperation::ToSrv context"));
            }
        }

        self.chan.log_activity();

        Ok(())
    }

    async fn handle_fromsrv_init(&self, payload: Vec<u8>) -> ah::Result<()> {
        let mut session = self.session();

        // Deserialize the received message, even though we don't use it.
        // This checks the authenticity of the message.
        let _msg = Message::deserialize(&payload, self.chan.key(), None)?;

        let new_session_secret: SessionSecret = secure_random();

        session.secret = None; // Don't use it for *this* message.

        let mut msg = Message::new(
            MsgType::Init,
            Operation::FromSrv,
            new_session_secret.to_vec(),
        )
        .context("Make httun packet")?;
        msg.set_session(self.create_new_session(new_session_secret).await);
        msg.set_sequence(u64::from_ne_bytes(secure_random()));

        self.send_msg(msg, session).await?;

        Ok(())
    }

    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let session = self.session();

        let msg = Message::deserialize(&payload, self.chan.key(), session.secret)?;
        let oper = msg.oper();

        if msg.session() != session.id {
            let _ = self.send_close().await;
            return Err(err!("Session mismatch"));
        }

        self.check_rx_sequence(&msg, SequenceType::C)
            .await
            .context("rx sequence validation SequenceType::C")?;

        let (reply_oper, payload) = match oper {
            Operation::FromSrv => (
                Operation::FromSrv,
                self.tun().recv().await.context("TUN receive")?,
            ),
            Operation::TestFromSrv if self.chan.test_enabled() => {
                (Operation::TestFromSrv, self.chan.get_pong().await)
            }
            _ => {
                let _ = self.send_close().await;
                return Err(err!("Received {oper:?} in UnOperation::ReqFromSrv context"));
            }
        };

        let mut msg =
            Message::new(MsgType::Data, reply_oper, payload).context("Make httun packet")?;
        msg.set_session(session.id);
        msg.set_sequence(session.sequence);

        self.send_msg(msg, session).await?;

        Ok(())
    }

    pub async fn run(&self) -> ah::Result<()> {
        match self.comm.recv().await? {
            CommRxMsg::ToSrv(payload) => match Message::peek_type(&payload)? {
                MsgType::Init => Err(err!("Received invalid ToSrv + MsgType::Init")),
                MsgType::Data => self.handle_tosrv_data(payload).await,
            },
            CommRxMsg::ReqFromSrv(payload) => match Message::peek_type(&payload)? {
                MsgType::Init => self.handle_fromsrv_init(payload).await,
                MsgType::Data => self.handle_fromsrv_data(payload).await,
            },
        }
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

    pub async fn spawn(self: &Arc<Self>, comm: CommBackend, chan: Arc<Channel>) {
        let prot = Arc::new(ProtocolHandler::new(Arc::clone(self), comm, chan).await);
        let handle = task::spawn({
            let prot = Arc::clone(&prot);
            async move {
                loop {
                    if let Err(e) = prot.run().await {
                        eprintln!("Client error: {e:?}");
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
