// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    l7::L7State,
    ping::PingState,
    time::{now, timed_out_now},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_protocol::{
    KexPublic, KeyExchange, Message, SequenceGenerator, SequenceType, SequenceValidator,
    SessionKey, UserSharedSecret,
};
use httun_util::timeouts::CHAN_ACTIVITY_TIMEOUT_S;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{self, AtomicU64},
    },
};

#[cfg(all(feature = "tun", target_os = "linux"))]
use httun_tun::TunHandler;

/// Represents a session for a channel.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub key: Option<SessionKey>,
    pub sequence: u64,
}

/// Internal state for a channel's session.
#[derive(Debug)]
struct SessionState {
    session: Session,
    tx_sequence_a: SequenceGenerator,
    rx_validator_b: SequenceValidator,
    rx_validator_c: SequenceValidator,
}

/// Represents a single configured channel.
#[derive(Debug)]
pub struct Channel {
    /// Name of the channel.
    name: String,
    /// Layer 3 (TUN) handler, if any.
    #[cfg(all(feature = "tun", target_os = "linux"))]
    l3: Option<TunHandler>,
    /// Layer 7 (socket) handler, if any.
    l7: Option<L7State>,
    /// Shared secret key.
    user_shared_secret: UserSharedSecret,
    /// Whether test messages are enabled.
    test_enabled: bool,
    /// Ping state, for connectivity testing.
    ping: PingState,
    /// Session state.
    session: StdMutex<SessionState>,
    /// Timestamp of last activity, in seconds since epoch.
    last_activity: AtomicU64,
}

impl Channel {
    /// Create new Channel instance.
    fn new(
        conf: &Config,
        name: &str,
        #[cfg(all(feature = "tun", target_os = "linux"))] l3: Option<TunHandler>,
        l7: Option<L7State>,
        user_shared_secret: &UserSharedSecret,
        test_enabled: bool,
    ) -> Self {
        let window_length = conf.parameters().receive().window_length();
        let session = SessionState {
            session: Default::default(),
            tx_sequence_a: SequenceGenerator::new(SequenceType::A),
            rx_validator_b: SequenceValidator::new(SequenceType::B, window_length),
            rx_validator_c: SequenceValidator::new(SequenceType::C, window_length),
        };
        Self {
            name: name.to_string(),
            #[cfg(all(feature = "tun", target_os = "linux"))]
            l3,
            l7,
            user_shared_secret: user_shared_secret.clone(),
            test_enabled,
            ping: PingState::new(),
            session: StdMutex::new(session),
            last_activity: AtomicU64::new(now()),
        }
    }

    /// Get channel name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get shared secret key.
    pub fn user_shared_secret(&self) -> &UserSharedSecret {
        &self.user_shared_secret
    }

    /// Whether test messages are enabled.
    pub fn test_enabled(&self) -> bool {
        self.test_enabled
    }

    /// Get current session, updating its TX sequence counter.
    pub fn get_session_and_update_tx_sequence(&self) -> Session {
        let mut s = self.session.lock().expect("Mutex poisoned");
        s.session.sequence = s.tx_sequence_a.next();
        s.session.clone()
    }

    /// Create a new session, resetting sequence counters.
    ///
    /// This invalidates any previous session.
    pub fn create_new_session(&self, remote_public_key: &KexPublic) -> (KexPublic, SessionKey) {
        // Do the key exchange to get the session key.
        let kex = KeyExchange::new();
        let local_public_key = kex.public_key();
        let session_shared_secret = kex.key_exchange(remote_public_key);
        let session_key =
            SessionKey::make_session(&self.user_shared_secret, &session_shared_secret);

        // Store the new session state, overwriting any previous session.
        {
            let mut s = self.session.lock().expect("Mutex poisoned");

            s.session.sequence = u64::MAX;
            s.session.key = Some(session_key.clone());
            s.tx_sequence_a.reset();
            s.rx_validator_b.reset();
            s.rx_validator_c.reset();
            if let Some(l7) = &self.l7 {
                l7.create_new_session();
            }
        }

        // Return the new session key.
        (local_public_key, session_key)
    }

    /// Check received message's sequence number.
    ///
    /// Returns an error if the sequence number
    /// is invalid or not in order or not in the receive window.
    pub async fn check_rx_sequence(
        &self,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        let mut s = self.session.lock().expect("Mutex poisoned");
        let validator = match sequence_type {
            SequenceType::B => &mut s.rx_validator_b,
            SequenceType::C => &mut s.rx_validator_c,
            t => panic!("Invalid {t:?}"),
        };
        validator
            .check_recv_seq(msg)
            .context("Message sequence validation")
    }

    /// Log activity on this channel.
    pub fn log_activity(&self) {
        self.last_activity.store(now(), atomic::Ordering::Relaxed);
    }

    /// Check whether the channel has timed out due to inactivity.
    pub fn activity_timed_out(&self) -> bool {
        timed_out_now(
            self.last_activity.load(atomic::Ordering::Relaxed),
            CHAN_ACTIVITY_TIMEOUT_S,
        )
    }

    /// Store the ping payload that was received.
    /// This will be sent back as pong payload.
    pub async fn put_ping(&self, payload: Vec<u8>) {
        self.ping.put(payload).await;
    }

    /// Generate the pong payload to send.
    pub async fn get_pong(&self) -> Vec<u8> {
        self.ping.get().await
    }

    /// Send data to the TUN interface.
    #[cfg(all(feature = "tun", target_os = "linux"))]
    pub async fn l3send(&self, data: &[u8]) -> ah::Result<()> {
        if let Some(l3) = &self.l3 {
            l3.send(data).await.context("TUN/L3 send")
        } else {
            Err(err!(
                "Can't send data to TUN interface. \
                 Channel '{}' has no configured tun=... entry.",
                self.name
            ))
        }
    }

    #[cfg(not(all(feature = "tun", target_os = "linux")))]
    pub async fn l3send(&self, _data: &[u8]) -> ah::Result<()> {
        Err(ah::format_err!("TUN is support is disabled"))
    }

    /// Receive data from the TUN interface.
    #[cfg(all(feature = "tun", target_os = "linux"))]
    pub async fn l3recv(&self) -> ah::Result<Vec<u8>> {
        if let Some(l3) = &self.l3 {
            l3.recv().await.context("TUN/L3 receive")
        } else {
            Err(err!(
                "Can't receive data from TUN interface. \
                 Channel '{}' has no configured tun=... entry.",
                self.name
            ))
        }
    }

    #[cfg(not(all(feature = "tun", target_os = "linux")))]
    pub async fn l3recv(&self) -> ah::Result<Vec<u8>> {
        Err(ah::format_err!("TUN is support is disabled"))
    }

    /// Send data to the L7 socket.
    pub async fn l7send(&self, data: &[u8]) -> ah::Result<()> {
        if let Some(l7) = &self.l7 {
            l7.send(data).await.context("L7 socket send")
        } else {
            Err(err!(
                "Can't send data to L7 socket. \
                 Channel '{}' has no configured l7-tunnel... entries.",
                self.name
            ))
        }
    }

    /// Receive data from the L7 socket.
    pub async fn l7recv(&self) -> ah::Result<Vec<u8>> {
        if let Some(l7) = &self.l7 {
            l7.recv().await.context("L7 socket receive")
        } else {
            Err(err!(
                "Can't receive data from L7 socket. \
                 Channel '{}' has no configured l7-tunnel... entries.",
                self.name
            ))
        }
    }

    /// Perform periodic work, such as checking for timeouts.
    pub async fn periodic_work(&self) {
        if let Some(l7) = &self.l7 {
            l7.check_timeout().await;
        }
    }
}

/// Manager of all configured channels.
#[derive(Debug)]
pub struct Channels {
    /// Map of channel name -> Channel
    channels: StdMutex<HashMap<String, Arc<Channel>>>,
}

impl Channels {
    /// Create Channels manager from configuration.
    pub async fn new(conf: Arc<Config>) -> ah::Result<Self> {
        let mut channels = HashMap::new();

        for chan_conf in conf.channels_iter() {
            let name = chan_conf.name();
            log::info!("Active channel: {name}");

            #[cfg(all(feature = "tun", target_os = "linux"))]
            let tun = if let Some(tun_name) = chan_conf.tun() {
                Some(
                    TunHandler::new(tun_name)
                        .await
                        .context("Tun interface init")?,
                )
            } else {
                None
            };

            let l7 = if let Some(l7_conf) = chan_conf.l7_tunnel() {
                Some(L7State::new(l7_conf)?)
            } else {
                None
            };
            let key = chan_conf.shared_secret();
            let test_enabled = chan_conf.enable_test();

            let chan = Channel::new(
                &conf,
                name,
                #[cfg(all(feature = "tun", target_os = "linux"))]
                tun,
                l7,
                key,
                test_enabled,
            );

            channels.insert(name.to_string(), Arc::new(chan));
        }
        if channels.is_empty() {
            log::warn!("There are no [[channels]] configured in the configuration file!");
        }

        Ok(Self {
            channels: StdMutex::new(channels),
        })
    }

    /// Get channel by name.
    pub fn get(&self, name: &str) -> Option<Arc<Channel>> {
        self.channels
            .lock()
            .expect("Lock poison")
            .get(name)
            .map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
