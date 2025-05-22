// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Channels, Session},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, MsgType, Operation, SequenceType, SessionSecret, secure_random};
use httun_util::DisconnectedError;
use std::sync::{
    Arc,
    atomic::{self, AtomicU32},
};
use tokio::{sync::Mutex, task};

pub struct ProtocolHandler {
    protman: Arc<ProtocolManager>,
    comm: CommBackend,
    channels: Arc<Channels>,
    pinned_session: AtomicU32,
}

impl ProtocolHandler {
    pub async fn new(
        protman: Arc<ProtocolManager>,
        comm: CommBackend,
        channels: Arc<Channels>,
    ) -> Self {
        Self {
            protman,
            comm,
            channels,
            pinned_session: AtomicU32::new(u32::MAX),
        }
    }

    pub fn chan_name(&self) -> ah::Result<String> {
        self.comm
            .chan_name()
            .ok_or_else(|| err!("Channel name is not known, yet."))
    }

    fn chan(&self) -> ah::Result<Arc<Channel>> {
        self.channels
            .get(&self.chan_name()?)
            .ok_or_else(|| err!("Channel is not configured."))
    }

    pub fn pinned_session(&self) -> Option<u16> {
        let pinned_session = self.pinned_session.load(atomic::Ordering::SeqCst);
        pinned_session.try_into().ok()
    }

    fn pin_session(&self, session: u16) {
        self.pinned_session
            .store(session.into(), atomic::Ordering::SeqCst);
    }

    async fn create_new_session(&self, chan: &Channel, session_secret: SessionSecret) -> u16 {
        let session_id = chan.create_new_session(session_secret);
        self.pin_session(session_id);
        self.protman
            .kill_old_sessions(chan.name(), session_id)
            .await;
        session_id
    }

    async fn check_rx_sequence(
        &self,
        chan: &Channel,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        chan.check_rx_sequence(msg, sequence_type).await
    }

    async fn send_close(&self) -> ah::Result<()> {
        self.comm.send_close().await
    }

    async fn send_msg(&self, chan: &Channel, msg: Message, session: Session) -> ah::Result<()> {
        let payload = msg.serialize(chan.key(), session.secret);
        self.comm.send(payload).await?;

        chan.log_activity();

        Ok(())
    }

    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("W direction packet received");

        let chan = self.chan()?;
        let session = chan.session();

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

        if msg.session() != session.id {
            let _ = self.send_close().await;
            return Err(err!("Session mismatch"));
        }

        self.check_rx_sequence(&chan, &msg, SequenceType::B)
            .await
            .context("rx sequence validation SequenceType::B")?;

        match oper {
            Operation::ToSrv => {
                chan.tun().send(msg.payload()).await.context("TUN send")?;
            }
            Operation::TestToSrv if chan.test_enabled() => {
                log::debug!(
                    "Received test mode ping: '{}'",
                    String::from_utf8_lossy(msg.payload())
                );
                chan.put_ping(msg.into_payload()).await;
            }
            _ => {
                let _ = self.send_close().await;
                return Err(err!("Received {oper:?} in UnOperation::ToSrv context"));
            }
        }

        chan.log_activity();

        Ok(())
    }

    async fn handle_fromsrv_init(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("Session init packet received");

        let chan = self.chan()?;
        let mut session = chan.session();

        // Deserialize the received message, even though we don't use it.
        // This checks the authenticity of the message.
        let msg = Message::deserialize(&payload, chan.key(), None)?;
        log::trace!("Session init message: {msg:?}");

        let new_session_secret: SessionSecret = secure_random();

        session.secret = None; // Don't use it for *this* message.

        let mut msg = Message::new(
            MsgType::Init,
            Operation::FromSrv,
            new_session_secret.to_vec(),
        )
        .context("Make httun packet")?;
        msg.set_session(self.create_new_session(&chan, new_session_secret).await);
        msg.set_sequence(u64::from_ne_bytes(secure_random()));

        self.send_msg(&chan, msg, session).await?;

        Ok(())
    }

    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("R direction packet received");

        let chan = self.chan()?;
        let session = chan.session();

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

        if msg.session() != session.id {
            let _ = self.send_close().await;
            return Err(err!("Session mismatch"));
        }

        self.check_rx_sequence(&chan, &msg, SequenceType::C)
            .await
            .context("rx sequence validation SequenceType::C")?;

        let (reply_oper, payload) = match oper {
            Operation::FromSrv => (
                Operation::FromSrv,
                chan.tun().recv().await.context("TUN receive")?,
            ),
            Operation::TestFromSrv if chan.test_enabled() => {
                (Operation::TestFromSrv, chan.get_pong().await)
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

        self.send_msg(&chan, msg, session).await?;

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

    fn activity_timed_out(&self) -> bool {
        self.chan()
            .map(|c| c.activity_timed_out())
            .unwrap_or_default()
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

    pub async fn spawn(self: &Arc<Self>, comm: CommBackend, channels: Arc<Channels>) {
        let prot = Arc::new(ProtocolHandler::new(Arc::clone(self), comm, channels).await);
        let handle = task::spawn({
            let prot = Arc::clone(&prot);
            async move {
                loop {
                    if let Err(e) = prot.run().await {
                        if e.downcast_ref::<DisconnectedError>().is_some() {
                            log::debug!("Client disconnected.");
                        } else {
                            log::error!("Client error: {e:?}");
                        }
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
            if let Ok(name) = inst.prot.chan_name() {
                if name == chan_name {
                    if let Some(pinned_session) = inst.prot.pinned_session() {
                        pinned_session == new_session_id
                    } else {
                        false
                    }
                } else {
                    true
                }
            } else {
                false
            }
        });
    }

    pub async fn check_timeouts(self: &Arc<Self>) {
        self.insts
            .lock()
            .await
            .retain(|inst| !inst.prot.activity_timed_out());
    }
}

// vim: ts=4 sw=4 expandtab
