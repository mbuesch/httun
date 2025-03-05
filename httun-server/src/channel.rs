// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use httun_protocol::Key;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Notify};

struct ChannelState {}

impl ChannelState {
    fn new() -> Self {
        Self {}
    }
}

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
    state: Mutex<ChannelState>,
    ping: PingState,
}

impl Channel {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            key: [0; 32], //TODO
            state: Mutex::new(ChannelState::new()),
            ping: PingState::new(),
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

    pub async fn put_ping(&self, payload: Vec<u8>) {
        *self.ping.buf.lock().await = payload;
        self.ping.notify.notify_one();
    }

    pub async fn get_pong(&self) -> Vec<u8> {
        self.ping.notify.notified().await;
        let mut payload: Vec<u8> = "Reply to: ".to_string().into();
        payload.append(&mut *self.ping.buf.lock().await);
        payload
    }

    pub async fn handle_new_connection(&self) {
        self.ping.buf.lock().await.clear();
        self.ping.notify.notify_waiters();
    }
}

pub struct Channels {
    channels: Mutex<HashMap<String, Arc<Channel>>>,
}

impl Channels {
    pub async fn new(enable_test: bool) -> Self {
        //TODO: Load channels from config file.
        let mut channels: HashMap<String, Arc<Channel>> =
            [("a".to_string(), Arc::new(Channel::new("a")))].into();
        if enable_test {
            println!("The __test__ channel is enabled.");
            channels.insert("__test__".to_string(), Arc::new(Channel::new("__test__")));
        }
        Self {
            channels: Mutex::new(channels),
        }
    }

    pub async fn get(&self, name: &str) -> Option<Arc<Channel>> {
        let channels = self.channels.lock().await;
        channels.get(name).map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
