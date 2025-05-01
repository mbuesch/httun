// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::time::{now, tdiff};
use httun_conf::Config;
use httun_protocol::Key;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{self, AtomicU16, AtomicU64},
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

pub struct Channel {
    name: String,
    key: Key,
    ping: PingState,
    session: AtomicU16,
    last_activity: AtomicU64,
}

impl Channel {
    fn new(name: &str, key: Key) -> Self {
        Self {
            name: name.to_string(),
            key,
            ping: PingState::new(),
            session: AtomicU16::new(0),
            last_activity: AtomicU64::new(now()),
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

    pub fn session_id(&self) -> u16 {
        self.session.load(atomic::Ordering::SeqCst)
    }

    pub fn make_new_session_id(&self) -> u16 {
        self.session
            .fetch_add(1, atomic::Ordering::SeqCst)
            .wrapping_add(1)
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
            channels.insert(chan.to_string(), Arc::new(Channel::new(&chan, key)));
        }
        if channels.is_empty() {
            eprintln!("WARNING: There are no [keys] configured in the configuration file!");
        }

        if enable_test {
            println!("The __test__ channel is enabled.");
            channels.insert(
                "__test__".to_string(),
                Arc::new(Channel::new("__test__", [0; 32])),
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
