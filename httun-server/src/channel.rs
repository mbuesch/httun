// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::time::{now, tdiff};
use anyhow::{self as ah, Context as _};
use httun_conf::Config;
use httun_protocol::{
    Key, Message, SequenceGenerator, SequenceType, SequenceValidator, SessionSecret,
};
use httun_tun::TunHandler;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{self, AtomicU64},
    },
};
use tokio::sync::{Mutex, Notify};

const ACTIVITY_TIMEOUT_S: i64 = 30;

struct PingState {
    notify: Notify,
    buf: Mutex<Vec<u8>>,
}

impl PingState {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            buf: Mutex::new(vec![]),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Session {
    pub id: u16,
    pub secret: Option<SessionSecret>,
    pub sequence: u64,
}

struct SessionState {
    session: Session,
    tx_sequence_a: SequenceGenerator,
    rx_validator_b: SequenceValidator,
    rx_validator_c: SequenceValidator,
}

pub struct Channel {
    name: String,
    tun: TunHandler,
    key: Key,
    test_enabled: bool,
    ping: PingState,
    session: StdMutex<SessionState>,
    last_activity: AtomicU64,
}

impl Channel {
    fn new(conf: &Config, name: &str, tun: TunHandler, key: Key, test_enabled: bool) -> Self {
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
            ping: PingState::new(),
            session: StdMutex::new(session),
            last_activity: AtomicU64::new(now()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn tun(&self) -> &TunHandler {
        &self.tun
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

    pub fn create_new_session(&self, session_secret: SessionSecret) -> u16 {
        let mut s = self.session.lock().expect("Mutex poisoned");

        s.session.id = s.session.id.wrapping_add(1);
        s.session.sequence = 0;
        s.session.secret = Some(session_secret);
        s.tx_sequence_a.reset();
        s.rx_validator_b.reset();
        s.rx_validator_c.reset();

        s.session.id
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
        *self.ping.buf.lock().await = payload;
        self.ping.notify.notify_one();
    }

    pub async fn get_pong(&self) -> Vec<u8> {
        loop {
            self.ping.notify.notified().await;

            let mut ping_buf = self.ping.buf.lock().await;
            if !ping_buf.is_empty() {
                let mut payload: Vec<u8> = "Reply to: ".to_string().into();
                payload.append(&mut *ping_buf);
                return payload;
            }
        }
    }
}

pub struct Channels {
    channels: Mutex<HashMap<String, Arc<Channel>>>,
    _conf: Arc<Config>,
}

impl Channels {
    pub async fn new(conf: Arc<Config>) -> ah::Result<Self> {
        let mut channels = HashMap::new();

        for chan in conf.channels_iter() {
            println!("Active channel: {}", chan.name());
            let tun = TunHandler::new(chan.tun().unwrap_or("httun"))
                .await
                .context("Tun interface init")?;
            let key = chan.shared_secret();
            let test_enabled = chan.enable_test();
            channels.insert(
                chan.name().to_string(),
                Arc::new(Channel::new(&conf, chan.name(), tun, key, test_enabled)),
            );
        }
        if channels.is_empty() {
            eprintln!("WARNING: There are no [[channels]] configured in the configuration file!");
        }

        Ok(Self {
            channels: Mutex::new(channels),
            _conf: conf,
        })
    }

    pub async fn get(&self, name: &str) -> Option<Arc<Channel>> {
        let channels = self.channels.lock().await;
        channels.get(name).map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
