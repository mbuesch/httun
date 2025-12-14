// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use httun_protocol::Message;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use tokio::pin;
use tokio::sync::{Mutex, Notify, watch};

const COMM_DEQUE_SIZE_TO_HTTUN: usize = 1;
const COMM_DEQUE_SIZE_FROM_HTTUN: usize = 16;

struct CommDeque<T, const SIZE: usize> {
    deque: Mutex<heapless::Deque<T, SIZE>>,
    notify: Notify,
    overflow: AtomicBool,
}

impl<T, const SIZE: usize> CommDeque<T, SIZE> {
    pub fn new() -> Self {
        Self {
            deque: Mutex::new(heapless::Deque::new()),
            notify: Notify::new(),
            overflow: AtomicBool::new(false),
        }
    }

    fn clear_notification(&self) {
        let notified = self.notify.notified();
        pin!(notified);
        notified.enable(); // consume the notification.
    }

    fn notify(&self) {
        self.notify.notify_one();
    }

    async fn wait_for_notify(&self) {
        self.notify.notified().await;
    }

    pub async fn clear(&self) {
        self.deque.lock().await.clear();
        self.clear_notification();
    }

    pub async fn put(&self, mut value: T) {
        loop {
            if let Err(v) = self.deque.lock().await.push_back(value) {
                value = v;
            } else {
                break;
            }
            if SIZE > 1 && !self.overflow.swap(true, Relaxed) {
                log::warn!("Httun communication queue overflow.");
            }
            self.wait_for_notify().await;
        }
        self.notify();
    }

    pub async fn get(&self) -> T {
        let value = loop {
            if let Some(value) = self.deque.lock().await.pop_front() {
                break value;
            }
            self.wait_for_notify().await;
        };
        self.notify();
        value
    }
}

/// Communication between httun-client's async tasks.
pub struct AsyncTaskComm {
    from_httun: CommDeque<Message, COMM_DEQUE_SIZE_FROM_HTTUN>,
    to_httun: CommDeque<Message, COMM_DEQUE_SIZE_TO_HTTUN>,
    restart_watch: watch::Sender<bool>,
}

impl AsyncTaskComm {
    pub fn new() -> Self {
        let (restart_watch, _) = watch::channel(true);
        Self {
            from_httun: CommDeque::new(),
            to_httun: CommDeque::new(),
            restart_watch,
        }
    }

    pub async fn clear(&self) {
        self.from_httun.clear().await;
        self.to_httun.clear().await;
    }

    pub async fn send_from_httun(&self, msg: Message) {
        self.from_httun.put(msg).await;
    }

    pub async fn recv_from_httun(&self) -> Message {
        self.from_httun.get().await
    }

    pub async fn send_to_httun(&self, msg: Message) {
        self.to_httun.put(msg).await;
    }

    pub async fn recv_to_httun(&self) -> Message {
        self.to_httun.get().await
    }

    pub fn set_restart_request(&self) {
        self.restart_watch.send_replace(true);
    }

    pub async fn request_restart(&self) {
        self.set_restart_request();
        let _ = self.restart_watch.subscribe().wait_for(|r| !*r).await;
    }

    pub async fn wait_for_restart_request(&self) {
        let _ = self.restart_watch.subscribe().wait_for(|r| *r).await;
    }

    pub fn notify_restart_done(&self) {
        self.restart_watch.send_replace(false);
    }
}

// vim: ts=4 sw=4 expandtab
