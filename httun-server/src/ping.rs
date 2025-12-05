// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::Mutex as StdMutex;
use tokio::sync::Notify;

#[derive(Debug)]
pub struct PingState {
    notify: Notify,
    buf: StdMutex<Vec<u8>>,
}

impl PingState {
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            buf: StdMutex::new(vec![]),
        }
    }

    pub async fn put(&self, payload: Vec<u8>) {
        *self.buf.lock().expect("Mutex poisoned") = payload;
        self.notify.notify_one();
    }

    pub async fn get(&self) -> Vec<u8> {
        loop {
            self.notify.notified().await;

            let mut buf = self.buf.lock().expect("Mutex poisoned");
            if !buf.is_empty() {
                let mut payload: Vec<u8> = "Reply to: ".to_string().into();
                payload.append(&mut *buf);
                return payload;
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
