// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Channels},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_protocol::{
    InitPayload, KexPublic, Message, MsgType, Operation, SequenceType, SessionKey,
};
use httun_util::{ChannelId, errors::DisconnectedError};
use std::{
    collections::LinkedList,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{self, AtomicBool},
    },
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit},
    task,
    time::timeout,
};

/// Httun protocol handler on the server.
#[derive(Debug)]
pub struct ProtocolHandler {
    /// Configuration file.
    conf: Arc<Config>,
    /// Protocol manager.
    protman: Arc<ProtocolManager>,
    /// Communication backend.
    comm: CommBackend,
    /// Shared channel manager.
    channels: Arc<Channels>,
    /// Pinned session secret, if yet assigned.
    pinned_session: StdRwLock<Option<SessionKey>>,
    /// Is the protocol handler dead?
    dead: AtomicBool,
}

impl ProtocolHandler {
    /// Create a new protocol handler.
    pub async fn new(
        conf: Arc<Config>,
        protman: Arc<ProtocolManager>,
        comm: CommBackend,
        channels: Arc<Channels>,
    ) -> Self {
        Self {
            conf,
            protman,
            comm,
            channels,
            pinned_session: StdRwLock::new(None),
            dead: AtomicBool::new(false),
        }
    }

    /// Get the channel id for this protocol handler.
    ///
    /// Returns an error if the channel ID is not yet known.
    pub fn chan_id(&self) -> ah::Result<ChannelId> {
        self.comm
            .chan_id()
            .ok_or_else(|| err!("Channel ID is not known, yet."))
    }

    /// Get the channel.
    ///
    /// Returns an error if the channel is not configured.
    fn chan(&self) -> ah::Result<Arc<Channel>> {
        self.channels
            .get(self.chan_id()?)
            .ok_or_else(|| err!("Channel is not configured."))
    }

    /// Get the pinned session secret, if any.
    pub fn pinned_session(&self) -> Option<SessionKey> {
        self.pinned_session.read().expect("RwLock poisoned").clone()
    }

    /// Pin the given session secret.
    fn pin_session(&self, session_key: &SessionKey) {
        *self.pinned_session.write().expect("RwLock poisoned") = Some(session_key.clone());
    }

    /// Create a new session for the given channel.
    ///
    /// Pins the new session secret and kills old sessions.
    ///
    /// `chan`: Channel to create the new session for.
    async fn create_new_session(
        &self,
        chan: &Channel,
        remote_public_key: &KexPublic,
    ) -> (KexPublic, SessionKey) {
        let (local_public_key, session_key) = chan.create_new_session(remote_public_key);
        self.pin_session(&session_key);
        self.protman
            .kill_old_sessions(chan.id(), &session_key)
            .await;
        (local_public_key, session_key)
    }

    /// Check the received message's sequence number.
    ///
    /// `chan`: Channel.
    /// `msg`: Received message.
    /// `sequence_type`: Sequence type of the received message.
    async fn check_rx_sequence(
        &self,
        chan: &Channel,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        chan.check_rx_sequence(msg, sequence_type).await
    }

    /// Close this protocol handler.
    async fn close(&self) -> ah::Result<()> {
        self.set_dead();
        self.comm.close().await
    }

    /// Send a reply message.
    ///
    /// `chan`: Channel to send the message on.
    /// `msg`: Message to send.
    /// `session`: Session to use for sending.
    async fn send_reply_msg(&self, msg: Message, session_key: &SessionKey) -> ah::Result<()> {
        let payload = msg
            .serialize(session_key)
            .context("Serialize httun message")?;

        self.comm.send_reply(payload).await
    }

    /// Handle data communication from client to server.
    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();
        let Some(session_key) = &session.key else {
            return Err(err!("No session key in UnOperation::ToSrv context"));
        };

        log::debug!("{}: W direction packet received", chan.id());

        let msg = Message::deserialize(payload, session_key)?;
        let oper = msg.oper();

        self.check_rx_sequence(&chan, &msg, SequenceType::B)
            .await
            .context("rx sequence validation SequenceType::B")?;

        match oper {
            Operation::L3ToSrv => {
                log::trace!("{}: Received Operation::L3ToSrv", chan.id());
                chan.l3send(msg.payload())
                    .await
                    .context("Channel L3 send")?;
            }
            Operation::L7ToSrv => {
                log::trace!("{}: Received Operation::L7ToSrv", chan.id());
                chan.l7send(msg.payload())
                    .await
                    .context("Channel L7 send")?;
            }
            Operation::TestToSrv if chan.test_enabled() => {
                log::trace!("{}: Received Operation::TestToSrv", chan.id());
                log::debug!(
                    "{}: Received test mode ping: '{}'",
                    chan.id(),
                    String::from_utf8_lossy(msg.payload())
                );
                chan.put_ping(msg.into_payload()).await;
            }
            _ => {
                return Err(err!("Received {oper:?} in UnOperation::ToSrv context"));
            }
        }

        Ok(())
    }

    /// Handle communication from client to server.
    async fn handle_tosrv(&self, payload: Vec<u8>) -> ah::Result<()> {
        match Message::peek_type(&payload)? {
            MsgType::Init => Err(err!("Received invalid ToSrv + MsgType::Init")),
            MsgType::Data => self.handle_tosrv_data(payload).await,
        }
    }

    /// Handle session initialization from server to client.
    async fn handle_fromsrv_init(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let _session = chan.get_session_and_update_tx_sequence();
        let session_key = SessionKey::make_init(chan.user_shared_secret());

        log::trace!("{}: Session init packet received", chan.id());

        let msg = Message::deserialize(payload, &session_key)?;
        let oper = msg.oper();

        if oper != Operation::Init {
            return Err(err!("Received {oper:?} in init context"));
        }

        let msg_payload =
            InitPayload::deserialize(msg.payload()).context("Deserialize init payload")?;

        log::debug!(
            "{}: Session init from client {}",
            chan.id(),
            msg_payload.sender_uuid()
        );

        let (local_public_key, _) = self
            .create_new_session(&chan, msg_payload.session_public_key())
            .await;

        let reply_payload = InitPayload::new(*self.conf.uuid(), local_public_key);
        let reply_payload = reply_payload
            .serialize()
            .context("Make httun init payload")?;
        let reply = Message::new(MsgType::Init, Operation::Init, reply_payload)
            .context("Make httun packet")?;

        self.send_reply_msg(reply, &session_key).await?;

        Ok(())
    }

    /// Handle data communication from server to client.
    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();
        let Some(session_key) = &session.key else {
            return Err(err!("No session key in UnOperation::ReqFromSrv context"));
        };

        log::debug!("{}: R direction packet received", chan.id());

        let msg = Message::deserialize(payload, session_key)?;
        let oper = msg.oper();

        self.check_rx_sequence(&chan, &msg, SequenceType::C)
            .await
            .context("rx sequence validation SequenceType::C")?;

        let (reply_oper, payload) = match oper {
            Operation::L3FromSrv => {
                log::trace!("{}: Received Operation::L3FromSrv", chan.id());
                (
                    Operation::L3FromSrv,
                    chan.l3recv().await.context("Channel L3 receive")?,
                )
            }
            Operation::L7FromSrv => {
                log::trace!("{}: Received Operation::L7FromSrv", chan.id());
                (
                    Operation::L7FromSrv,
                    chan.l7recv().await.context("Channel L7 receive")?,
                )
            }
            Operation::TestFromSrv if chan.test_enabled() => {
                log::trace!("{}: Received Operation::TestFromSrv", chan.id());
                (Operation::TestFromSrv, chan.get_pong().await)
            }
            _ => {
                return Err(err!("Received {oper:?} in UnOperation::ReqFromSrv context"));
            }
        };

        let mut msg =
            Message::new(MsgType::Data, reply_oper, payload).context("Make httun packet")?;
        msg.set_sequence(session.sequence);

        self.send_reply_msg(msg, session_key).await?;

        Ok(())
    }

    /// Handle communication from server to client.
    async fn handle_fromsrv(&self, payload: Vec<u8>) -> ah::Result<()> {
        match Message::peek_type(&payload)? {
            MsgType::Init => self.handle_fromsrv_init(payload).await,
            MsgType::Data => self.handle_fromsrv_data(payload).await,
        }
    }

    /// Inner protocol handler function.
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
                log::trace!("{}: Unix socket: Received Keepalive", chan.id());
                Ok(())
            }
        }
    }

    /// Run the httun protocol handler.
    ///
    /// This function processes all incoming httun messages
    /// and performs the necessary actions and replies.
    pub async fn run(&self) -> ah::Result<()> {
        if let Err(e) = self.do_run().await {
            let _ = self.close().await;
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Mark the protocol handler as dead.
    fn set_dead(&self) {
        self.dead.store(true, atomic::Ordering::Relaxed);
    }

    /// Check if the protocol handler is dead or channel activity has timed out.
    fn is_dead(&self) -> bool {
        if self.dead.load(atomic::Ordering::Relaxed) {
            return true;
        }
        self.chan()
            .map(|chan| {
                let timed_out = chan.activity_timed_out();
                if timed_out {
                    log::debug!("Channel {} activity timed out", chan.id());
                }
                timed_out
            })
            .unwrap_or_default()
    }

    /// Perform periodic work for this protocol handler.
    pub async fn periodic_work(&self) {
        if let Ok(chan) = self.chan() {
            chan.periodic_work().await;
        }
    }
}

/// A protocol instance on the server.
#[derive(Debug)]
struct ProtocolInstance {
    // Handle to the protocol task.
    handle: task::JoinHandle<()>,
    // Protocol handler.
    prot: Arc<ProtocolHandler>,
}

impl ProtocolInstance {
    /// Create a new protocol instance.
    fn new(handle: task::JoinHandle<()>, prot: Arc<ProtocolHandler>) -> Self {
        Self { handle, prot }
    }
}

impl Drop for ProtocolInstance {
    fn drop(&mut self) {
        // Abort the protocol task when dropping the instance.
        self.handle.abort();
    }
}

/// Httun protocol manager.
///
/// This manager handles all protocol instances on the server.
#[derive(Debug)]
pub struct ProtocolManager {
    conf: Arc<Config>,
    insts: Mutex<LinkedList<ProtocolInstance>>,
}

impl ProtocolManager {
    /// Create a new protocol manager.
    pub fn new(conf: Arc<Config>) -> Arc<Self> {
        Arc::new(ProtocolManager {
            conf,
            insts: Mutex::new(LinkedList::new()),
        })
    }

    /// Spawn a new protocol handler instance task.
    ///
    /// `comm`: Communication backend for this protocol instance.
    /// `channels`: Shared channel manager.
    /// `permit`: Semaphore permit to limit the number of concurrent protocol instances.
    pub async fn spawn(
        self: &Arc<Self>,
        comm: CommBackend,
        channels: Arc<Channels>,
        permit: OwnedSemaphorePermit,
    ) {
        let prot = Arc::new(
            ProtocolHandler::new(Arc::clone(&self.conf), Arc::clone(self), comm, channels).await,
        );

        let mut insts = self.insts.lock().await;

        // Spawn the protocol handler task.
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
                // The protocol handler is done.
                prot.set_dead();
                this.periodic_work().await;
                // Release the protocol instance permit.
                drop(permit);
            }
        });

        //TODO kill all old instances.

        insts.push_back(ProtocolInstance::new(handle, prot));
    }

    /// Kill old sessions for the given channel ID.
    /// Keeps only the session with the given new session secret.
    ///
    /// `chan_id`: Channel ID to kill old sessions for.
    /// `new_session_secret`: Session secret of the new session to keep.
    async fn kill_old_sessions(&self, chan_id: ChannelId, new_session_key: &SessionKey) {
        let mut insts = self.insts.lock().await;

        insts
            .extract_if(|inst| {
                let mut retain = true;

                if let Ok(id) = inst.prot.chan_id() {
                    if id == chan_id
                        && let Some(pinned_session) = inst.prot.pinned_session()
                    {
                        retain = pinned_session == *new_session_key
                    }
                } else {
                    // TODO: It would be better to drop these after a timeout only.
                    retain = false;
                }

                if !retain {
                    inst.prot.set_dead();
                }
                !retain
            })
            .for_each(drop);
    }

    /// Perform periodic work for all protocol instances.
    pub async fn periodic_work(&self) {
        let mut insts = self.insts.lock().await;

        // Remove dead instances.
        insts.extract_if(|inst| inst.prot.is_dead()).for_each(drop);

        // Perform periodic work for all instances.
        for inst in &*insts {
            inst.prot.periodic_work().await;
        }
    }
}

// vim: ts=4 sw=4 expandtab
