// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    channel::{Channel, Channels},
    comm_backend::{CommBackend, CommRxMsg},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::{KexPublic, Message, MsgType, Operation, SequenceType, SessionKey};
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

/// Httun protocol handler on the server.
#[derive(Debug)]
pub struct ProtocolHandler {
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

    /// Get the channel name for this protocol handler.
    ///
    /// Returns an error if the channel name is not yet known.
    pub fn chan_name(&self) -> ah::Result<String> {
        self.comm
            .chan_name()
            .ok_or_else(|| err!("Channel name is not known, yet."))
    }

    /// Get the channel.
    ///
    /// Returns an error if the channel is not configured.
    fn chan(&self) -> ah::Result<Arc<Channel>> {
        self.channels
            .get(&self.chan_name()?)
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
            .kill_old_sessions(chan.name(), &session_key)
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
    async fn send_reply_msg(
        &self,
        chan: &Channel,
        msg: Message,
        session_key: &SessionKey,
    ) -> ah::Result<()> {
        let payload = msg
            .serialize(session_key)
            .context("Serialize httun message")?;

        self.comm.send_reply(payload).await?;

        chan.log_activity();

        Ok(())
    }

    /// Handle data communication from client to server.
    async fn handle_tosrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();
        let Some(session_key) = &session.key else {
            return Err(err!("No session key in UnOperation::ToSrv context"));
        };

        log::debug!("{}: W direction packet received", chan.name());

        let msg = Message::deserialize(&payload, session_key)?;
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

        log::debug!("{}: Session init packet received", chan.name());

        let msg = Message::deserialize(&payload, &session_key)?;
        let oper = msg.oper();

        if oper != Operation::Init {
            return Err(err!("Received {oper:?} in init context"));
        }

        log::trace!("{}: Session init", chan.name());

        let remote_public_key: KexPublic = msg
            .into_payload()
            .as_slice()
            .try_into()
            .context("Receive remote public key")?;

        let (local_public_key, _) = self.create_new_session(&chan, &remote_public_key).await;

        let msg = Message::new(
            MsgType::Init,
            Operation::Init,
            local_public_key.as_raw_bytes().to_vec(),
        )
        .context("Make httun packet")?;

        self.send_reply_msg(&chan, msg, &session_key).await?;

        Ok(())
    }

    /// Handle data communication from server to client.
    async fn handle_fromsrv_data(&self, payload: Vec<u8>) -> ah::Result<()> {
        let chan = self.chan()?;
        let session = chan.get_session_and_update_tx_sequence();
        let Some(session_key) = &session.key else {
            return Err(err!("No session key in UnOperation::ReqFromSrv context"));
        };

        log::debug!("{}: R direction packet received", chan.name());

        let msg = Message::deserialize(&payload, session_key)?;
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

        self.send_reply_msg(&chan, msg, &session_key).await?;

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
                log::trace!("{}: Unix socket: Received Keepalive", chan.name());
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
        self.dead.load(atomic::Ordering::Relaxed)
            || self
                .chan()
                .map(|c| c.activity_timed_out())
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
    insts: Mutex<Vec<ProtocolInstance>>,
}

impl ProtocolManager {
    /// Create a new protocol manager.
    pub fn new() -> Arc<Self> {
        Arc::new(ProtocolManager {
            insts: Mutex::new(Vec::with_capacity(8)),
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
        let prot = Arc::new(ProtocolHandler::new(Arc::clone(self), comm, channels).await);

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

        insts.push(ProtocolInstance::new(handle, prot));
    }

    /// Kill old sessions for the given channel name.
    /// Keeps only the session with the given new session secret.
    ///
    /// `chan_name`: Channel name to kill old sessions for.
    /// `new_session_secret`: Session secret of the new session to keep.
    async fn kill_old_sessions(self: &Arc<Self>, chan_name: &str, new_session_key: &SessionKey) {
        self.insts.lock().await.retain(|inst| {
            if let Ok(name) = inst.prot.chan_name() {
                if name == chan_name {
                    if let Some(pinned_session) = inst.prot.pinned_session() {
                        pinned_session == *new_session_key
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

    /// Perform periodic work for all protocol instances.
    pub async fn periodic_work(self: &Arc<Self>) {
        let mut insts = self.insts.lock().await;

        // Remove dead instances.
        insts.retain(|inst| !inst.prot.is_dead());

        // Perform periodic work for all instances.
        for inst in &*insts {
            inst.prot.periodic_work().await;
        }
    }
}

// vim: ts=4 sw=4 expandtab
