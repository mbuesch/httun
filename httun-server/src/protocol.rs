// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Channels, Session},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, MsgType, Operation, SequenceType, SessionSecret};
use httun_util::DisconnectedError;
use std::sync::{
    Arc, RwLock as StdRwLock,
    atomic::{self, AtomicBool},
};
use tokio::{sync::Mutex, task, time::timeout};

pub struct ProtocolHandler {
    protman: Arc<ProtocolManager>,
    comm: CommBackend,
    channels: Arc<Channels>,
    pinned_session: StdRwLock<Option<SessionSecret>>,
    dead: AtomicBool,
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
            pinned_session: StdRwLock::new(None),
            dead: AtomicBool::new(false),
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

    pub fn pinned_session(&self) -> Option<SessionSecret> {
        *self.pinned_session.read().expect("RwLock poisoned")
    }

    fn pin_session(&self, session_secret: &SessionSecret) {
        *self.pinned_session.write().expect("RwLock poisoned") = Some(*session_secret);
    }

    async fn create_new_session(&self, chan: &Channel) -> SessionSecret {
        let session_secret = chan.create_new_session();
        self.pin_session(&session_secret);
        self.protman
            .kill_old_sessions(chan.name(), &session_secret)
            .await;
        session_secret
    }

    async fn check_rx_sequence(
        &self,
        chan: &Channel,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        chan.check_rx_sequence(msg, sequence_type).await
    }

    async fn close(&self) -> ah::Result<()> {
        self.comm.close().await
    }

    async fn send_reply_msg(
        &self,
        chan: &Channel,
        msg: Message,
        session: Session,
    ) -> ah::Result<()> {
        let payload = msg.serialize(chan.key(), session.secret);
        self.comm.send_reply(payload).await?;

        chan.log_activity();

        Ok(())
    }

    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("W direction packet received");

        let chan = self.chan()?;
        let session = chan.session();

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

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
                let _ = self.close().await;
                return Err(err!("Received {oper:?} in UnOperation::ToSrv context"));
            }
        }

        chan.log_activity();

        Ok(())
    }

    async fn handle_tosrv(&self, payload: Vec<u8>) -> ah::Result<()> {
        match Message::peek_type(&payload)? {
            MsgType::Init => Err(err!("Received invalid ToSrv + MsgType::Init")),
            MsgType::Data => self.handle_tosrv_data(payload).await,
        }
    }

    async fn handle_fromsrv_init(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("Session init packet received");

        let chan = self.chan()?;
        let mut session = chan.session();

        // Deserialize the received message, even though we don't use it.
        // This checks the authenticity of the message.
        let msg = Message::deserialize(&payload, chan.key(), None)?;
        log::trace!("Session init message: {msg:?}");

        let new_session_secret = self.create_new_session(&chan).await;

        session.secret = None; // Don't use it for *this* message.

        let msg = Message::new(
            MsgType::Init,
            Operation::FromSrv,
            new_session_secret.to_vec(),
        )
        .context("Make httun packet")?;

        self.send_reply_msg(&chan, msg, session).await?;

        Ok(())
    }

    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        log::debug!("R direction packet received");

        let chan = self.chan()?;
        let session = chan.session();

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

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
                let _ = self.close().await;
                return Err(err!("Received {oper:?} in UnOperation::ReqFromSrv context"));
            }
        };

        let mut msg =
            Message::new(MsgType::Data, reply_oper, payload).context("Make httun packet")?;
        msg.set_sequence(session.sequence);

        self.send_reply_msg(&chan, msg, session).await?;

        Ok(())
    }

    async fn handle_fromsrv(&self, payload: Vec<u8>) -> ah::Result<()> {
        match Message::peek_type(&payload)? {
            MsgType::Init => self.handle_fromsrv_init(payload).await,
            MsgType::Data => self.handle_fromsrv_data(payload).await,
        }
    }

    pub async fn run(&self) -> ah::Result<()> {
        match self.comm.recv().await? {
            CommRxMsg::ToSrv(payload) => self.handle_tosrv(payload).await,
            CommRxMsg::ReqFromSrv(payload) => {
                if let Some(timeout_dur) = self.comm.get_reply_timeout_duration() {
                    match timeout(timeout_dur, self.handle_fromsrv(payload)).await {
                        Err(_) => self.comm.send_reply_timeout().await,
                        Ok(ret) => ret,
                    }
                } else {
                    self.handle_fromsrv(payload).await
                }
            }
        }
    }

    fn set_dead(&self) {
        self.dead.store(true, atomic::Ordering::Relaxed);
    }

    fn is_dead(&self) -> bool {
        self.dead.load(atomic::Ordering::Relaxed)
            || self
                .chan()
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
            insts: Mutex::new(Vec::with_capacity(8)),
        })
    }

    pub async fn spawn(self: &Arc<Self>, comm: CommBackend, channels: Arc<Channels>) {
        let prot = Arc::new(ProtocolHandler::new(Arc::clone(self), comm, channels).await);

        let mut insts = self.insts.lock().await;

        let handle = task::spawn({
            let this = Arc::clone(self);
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
                prot.set_dead();
                this.check_dead_instances().await;
            }
        });

        insts.push(ProtocolInstance::new(handle, prot));
    }

    async fn kill_old_sessions(
        self: &Arc<Self>,
        chan_name: &str,
        new_session_secret: &SessionSecret,
    ) {
        self.insts.lock().await.retain(|inst| {
            if let Ok(name) = inst.prot.chan_name() {
                if name == chan_name {
                    if let Some(pinned_session) = inst.prot.pinned_session() {
                        pinned_session == *new_session_secret
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

    pub async fn check_dead_instances(self: &Arc<Self>) {
        self.insts.lock().await.retain(|inst| !inst.prot.is_dead());
    }
}

// vim: ts=4 sw=4 expandtab
