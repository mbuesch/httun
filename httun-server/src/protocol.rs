// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Channels, Session},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{Message, MsgType, Operation, SequenceType, SessionSecret};
use httun_util::errors::DisconnectedError;
use std::sync::{
    Arc, RwLock as StdRwLock,
    atomic::{self, AtomicBool},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit},
    task,
    time::timeout,
};

#[derive(Debug)]
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
        self.set_dead();
        self.comm.close().await
    }

    async fn send_reply_msg(
        &self,
        chan: &Channel,
        msg: Message,
        session: Session,
    ) -> ah::Result<()> {
        let payload = msg
            .serialize(chan.key(), session.secret)
            .context("Serialize httun message")?;
        self.comm.send_reply(payload).await?;

        chan.log_activity();

        Ok(())
    }

    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();

        log::debug!("{}: W direction packet received", chan.name());

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

        self.check_rx_sequence(&chan, &msg, SequenceType::B)
            .await
            .context("rx sequence validation SequenceType::B")?;

        match oper {
            Operation::L3ToSrv => {
                log::trace!("{}: Received Operation::L3ToSrv", chan.name());
                chan.l3send(msg.payload())
                    .await
                    .context("Channel L3 send")?;
            }
            Operation::L7ToSrv => {
                log::trace!("{}: Received Operation::L7ToSrv", chan.name());
                chan.l7send(msg.payload())
                    .await
                    .context("Channel L7 send")?;
            }
            Operation::TestToSrv if chan.test_enabled() => {
                log::trace!("{}: Received Operation::TestToSrv", chan.name());
                log::debug!(
                    "{}: Received test mode ping: '{}'",
                    chan.name(),
                    String::from_utf8_lossy(msg.payload())
                );
                chan.put_ping(msg.into_payload()).await;
            }
            _ => {
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
        let chan = self.chan()?;
        let mut session = chan.get_session_and_update_tx_sequence();

        log::debug!("{}: Session init packet received", chan.name());

        // Deserialize the received message, even though we don't use it.
        // This checks the authenticity of the message.
        let msg = Message::deserialize(&payload, chan.key(), None)?;
        let oper = msg.oper();

        if oper != Operation::Init {
            return Err(err!("Received {oper:?} in init context"));
        }

        log::trace!("{}: Session init", chan.name());

        let new_session_secret = self.create_new_session(&chan).await;

        session.secret = None; // Don't use it for *this* message.

        let msg = Message::new(MsgType::Init, Operation::Init, new_session_secret.to_vec())
            .context("Make httun packet")?;

        self.send_reply_msg(&chan, msg, session).await?;

        Ok(())
    }

    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();

        log::debug!("{}: R direction packet received", chan.name());

        let msg = Message::deserialize(&payload, chan.key(), session.secret)?;
        let oper = msg.oper();

        self.check_rx_sequence(&chan, &msg, SequenceType::C)
            .await
            .context("rx sequence validation SequenceType::C")?;

        let (reply_oper, payload) = match oper {
            Operation::L3FromSrv => {
                log::trace!("{}: Received Operation::L3FromSrv", chan.name());
                (
                    Operation::L3FromSrv,
                    chan.l3recv().await.context("Channel L3 receive")?,
                )
            }
            Operation::L7FromSrv => {
                log::trace!("{}: Received Operation::L7FromSrv", chan.name());
                (
                    Operation::L7FromSrv,
                    chan.l7recv().await.context("Channel L7 receive")?,
                )
            }
            Operation::TestFromSrv if chan.test_enabled() => {
                log::trace!("{}: Received Operation::TestFromSrv", chan.name());
                (Operation::TestFromSrv, chan.get_pong().await)
            }
            _ => {
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

    async fn do_run(&self) -> ah::Result<()> {
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
            CommRxMsg::Keepalive => {
                let chan = self.chan()?;
                chan.log_activity();
                log::trace!("{}: Unix socket: Received Keepalive", chan.name());
                Ok(())
            }
        }
    }

    pub async fn run(&self) -> ah::Result<()> {
        if let Err(e) = self.do_run().await {
            let _ = self.close().await;
            Err(e)
        } else {
            Ok(())
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

    pub async fn periodic_work(&self) {
        if let Ok(chan) = self.chan() {
            chan.periodic_work().await;
        }
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ProtocolManager {
    insts: Mutex<Vec<ProtocolInstance>>,
}

impl ProtocolManager {
    pub fn new() -> Arc<Self> {
        Arc::new(ProtocolManager {
            insts: Mutex::new(Vec::with_capacity(8)),
        })
    }

    pub async fn spawn(
        self: &Arc<Self>,
        comm: CommBackend,
        channels: Arc<Channels>,
        permit: OwnedSemaphorePermit,
    ) {
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
                this.periodic_work().await;
                drop(permit);
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

    pub async fn periodic_work(self: &Arc<Self>) {
        let mut insts = self.insts.lock().await;

        insts.retain(|inst| !inst.prot.is_dead());

        for inst in &*insts {
            inst.prot.periodic_work().await;
        }
    }
}

// vim: ts=4 sw=4 expandtab
