// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::time::{now, tdiff};
use anyhow::{self as ah, Context as _};
use httun_conf::Config;
use httun_protocol::{Key, Message, SequenceValidator, SessionSecret};
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

pub struct Channel {
    name: String,
    key: Key,
    ping: PingState,
    session: StdMutex<Session>,
    last_activity: AtomicU64,
    rx_validator_to_srv: StdMutex<SequenceValidator>,
    rx_validator_from_srv: StdMutex<SequenceValidator>,
}

impl Channel {
    fn new(conf: &Config, name: &str, key: Key) -> Self {
        Self {
            name: name.to_string(),
            key,
            ping: PingState::new(),
            session: StdMutex::new(Default::default()),
            last_activity: AtomicU64::new(now()),
            rx_validator_to_srv: StdMutex::new(SequenceValidator::new(conf.rx_window_length())),
            rx_validator_from_srv: StdMutex::new(SequenceValidator::new(conf.rx_window_length())),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_test_channel(&self) -> bool {
        self.name == "__test__"
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn session(&self) -> Session {
        let mut session = self.session.lock().expect("Mutex poisoned");

        session.sequence = session
            .sequence
            .checked_add(1)
            .expect("Session::sequence overflow");

        session.clone()
    }

    pub fn create_new_session(&self, session_secret: SessionSecret) -> Session {
        let session = {
            let mut session = self.session.lock().expect("Mutex poisoned");

            session.id = session.id.wrapping_add(1);
            session.sequence = 0;
            session.secret = Some(session_secret);

            session.clone()
        };

        self.rx_validator_to_srv
            .lock()
            .expect("Mutex poisoned")
            .reset();
        self.rx_validator_from_srv
            .lock()
            .expect("Mutex poisoned")
            .reset();

        session
    }

    pub async fn check_rx_sequence(&self, msg: &Message, direction_to_srv: bool) -> ah::Result<()> {
        let mut validator = if direction_to_srv {
            self.rx_validator_to_srv.lock().expect("Mutex poisoned")
        } else {
            self.rx_validator_from_srv.lock().expect("Mutex poisoned")
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
    pub async fn new(conf: Arc<Config>, enable_test: bool) -> Self {
        let mut channels = HashMap::new();

        for (chan, key) in conf.keys_iter() {
            println!("Active channel: {chan}");
            channels.insert(chan.to_string(), Arc::new(Channel::new(&conf, &chan, key)));
        }
        if channels.is_empty() {
            eprintln!("WARNING: There are no [keys] configured in the configuration file!");
        }

        if enable_test {
            println!("The __test__ channel is enabled.");
            channels.insert(
                "__test__".to_string(),
                Arc::new(Channel::new(&conf, "__test__", [0; 32])),
            );
        }

        Self {
            channels: Mutex::new(channels),
            _conf: conf,
        }
    }

    pub async fn get(&self, name: &str) -> Option<Arc<Channel>> {
        let channels = self.channels.lock().await;
        channels.get(name).map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
