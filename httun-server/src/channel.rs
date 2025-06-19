// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    l7::L7State,
    ping::PingState,
    time::{now, tdiff},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_protocol::{
    Key, Message, SequenceGenerator, SequenceType, SequenceValidator, SessionSecret, secure_random,
};
use httun_tun::TunHandler;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{self, AtomicU64},
    },
};

const ACTIVITY_TIMEOUT_S: i64 = 30;

#[derive(Clone, Debug, Default)]
pub struct Session {
    pub secret: Option<SessionSecret>,
    pub sequence: u64,
}

#[derive(Debug)]
struct SessionState {
    session: Session,
    tx_sequence_a: SequenceGenerator,
    rx_validator_b: SequenceValidator,
    rx_validator_c: SequenceValidator,
}

#[derive(Debug)]
pub struct Channel {
    name: String,
    tun: Option<TunHandler>,
    key: Key,
    test_enabled: bool,
    l7: Option<L7State>,
    ping: PingState,
    session: StdMutex<SessionState>,
    last_activity: AtomicU64,
}

impl Channel {
    fn new(
        conf: &Config,
        name: &str,
        tun: Option<TunHandler>,
        l7: Option<L7State>,
        key: Key,
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
            tun,
            key,
            test_enabled,
            l7,
            ping: PingState::new(),
            session: StdMutex::new(session),
            last_activity: AtomicU64::new(now()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn test_enabled(&self) -> bool {
        self.test_enabled
    }

    pub fn session(&self) -> Session {
        let mut s = self.session.lock().expect("Mutex poisoned");
        s.session.sequence = s.tx_sequence_a.next();
        s.session.clone()
    }

    pub fn create_new_session(&self) -> SessionSecret {
        let session_secret: SessionSecret = secure_random();

        {
            let mut s = self.session.lock().expect("Mutex poisoned");

            s.session.sequence = u64::MAX;
            s.session.secret = Some(session_secret);
            s.tx_sequence_a.reset();
            s.rx_validator_b.reset();
            s.rx_validator_c.reset();
        }

        session_secret
    }

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

    pub fn log_activity(&self) {
        self.last_activity.store(now(), atomic::Ordering::Relaxed);
    }

    pub fn activity_timed_out(&self) -> bool {
        tdiff(now(), self.last_activity.load(atomic::Ordering::Relaxed)) > ACTIVITY_TIMEOUT_S
    }

    pub async fn put_ping(&self, payload: Vec<u8>) {
        self.ping.put(payload).await;
    }

    pub async fn get_pong(&self) -> Vec<u8> {
        self.ping.get().await
    }

    pub async fn l4send(&self, data: &[u8]) -> ah::Result<()> {
        if let Some(tun) = &self.tun {
            tun.send(data).await.context("TUN send")
        } else {
            Err(err!(
                "Can't send data to TUN interface. \
                 Channel '{}' has no configured tun=... entry.",
                self.name
            ))
        }
    }

    pub async fn l4recv(&self) -> ah::Result<Vec<u8>> {
        if let Some(tun) = &self.tun {
            tun.recv().await.context("TUN receive")
        } else {
            Err(err!(
                "Can't receive data from TUN interface. \
                 Channel '{}' has no configured tun=... entry.",
                self.name
            ))
        }
    }

    pub async fn l7send(&self, data: &[u8]) -> ah::Result<()> {
        if let Some(l7) = &self.l7 {
            l7.send(data).await
        } else {
            Err(err!(
                "Can't send data to L7 socket. \
                 Channel '{}' has no configured l7-tunnel... entries.",
                self.name
            ))
        }
    }

    pub async fn l7recv(&self) -> ah::Result<Vec<u8>> {
        if let Some(l7) = &self.l7 {
            l7.recv().await
        } else {
            Err(err!(
                "Can't receive data from L7 socket. \
                 Channel '{}' has no configured l7-tunnel... entries.",
                self.name
            ))
        }
    }

    pub async fn periodic_work(&self) {
        if let Some(l7) = &self.l7 {
            l7.check_timeout().await;
        }
    }
}

#[derive(Debug)]
pub struct Channels {
    channels: StdMutex<HashMap<String, Arc<Channel>>>,
}

impl Channels {
    pub async fn new(conf: Arc<Config>) -> ah::Result<Self> {
        let mut channels = HashMap::new();

        for chan_conf in conf.channels_iter() {
            let name = chan_conf.name();
            log::info!("Active channel: {}", name);

            let tun = if let Some(tun_name) = chan_conf.tun() {
                Some(
                    TunHandler::new(tun_name)
                        .await
                        .context("Tun interface init")?,
                )
            } else {
                None
            };
            let l7 = chan_conf.l7_tunnel().map(L7State::new);
            let key = chan_conf.shared_secret();
            let test_enabled = chan_conf.enable_test();

            let chan = Channel::new(&conf, name, tun, l7, key, test_enabled);
            channels.insert(name.to_string(), Arc::new(chan));
        }
        if channels.is_empty() {
            log::warn!("There are no [[channels]] configured in the configuration file!");
        }

        Ok(Self {
            channels: StdMutex::new(channels),
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<Channel>> {
        self.channels
            .lock()
            .expect("Lock poison")
            .get(name)
            .map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
