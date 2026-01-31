// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::Mutex as StdMutex;
use tokio::sync::Notify;

/// State for handling ping requests and responses.
#[derive(Debug)]
pub struct PingState {
    /// Notification mechanism for new ping payloads.
    notify: Notify,
    /// Buffer to store the latest ping payload.
    buf: StdMutex<Vec<u8>>,
}

impl PingState {
    /// Creates a new `PingState` instance.
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            buf: StdMutex::new(vec![]),
        }
    }

    /// Stores a new ping payload and notifies any waiting tasks.
    pub async fn put(&self, payload: Vec<u8>) {
        *self.buf.lock().expect("Mutex poisoned") = payload;
        self.notify.notify_one();
    }

    /// Waits for and retrieves the latest ping payload.
    pub async fn get(&self) -> Vec<u8> {
        loop {
            self.notify.notified().await;

            let mut buf = self.buf.lock().expect("Mutex poisoned");
            if !buf.is_empty() {
                let mut payload: Vec<u8> = "Pong: ".to_string().into();
                payload.append(&mut *buf);
                return payload;
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
