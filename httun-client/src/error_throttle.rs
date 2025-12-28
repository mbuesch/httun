// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use std::{
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{task, time};

const OK_SUB: i32 = 1;
const ERR_ADD: i32 = 3;
const ERR_BASE: i32 = ERR_ADD * 2;
const LIMIT: i32 = ERR_BASE * 1000;
const SUB_INTERVAL: Duration = Duration::from_secs(1);

const DELAY_MIN_S: f64 = 0.01;
const DELAY_BASE_S: f64 = 0.1;
const DELAY_MAX_S: f64 = 5.0;

pub struct ErrorThrottle {
    handle: task::JoinHandle<()>,
    count: Arc<AtomicI32>,
}

impl ErrorThrottle {
    pub fn new() -> Self {
        let count = Arc::new(AtomicI32::new(0));

        let handle = task::spawn({
            let count = Arc::clone(&count);
            async move {
                let mut inter = time::interval(SUB_INTERVAL);
                loop {
                    inter.tick().await;

                    // Subtract the Ok count.
                    // There is a race condition window between sub and max
                    // which races with `self.error()`.
                    // But it handles the case of count becoming negative.
                    count.fetch_sub(OK_SUB, Relaxed);
                    count.fetch_max(0, Relaxed);
                }
            }
        });

        Self { handle, count }
    }

    pub async fn error(&self) {
        // Add the error count.
        // Count may start as negative (see Ok-subtraction above).
        // Count will end up being one less than it actually should be in this case.
        // Meh, don't care.
        self.count.fetch_add(ERR_ADD, Relaxed);
        // Don't let it grow unbounded.
        let count = self.count.fetch_min(LIMIT, Relaxed);
        // Suppress negative counts.
        let count = count.max(0);

        // Calculate the delay from the error count.
        // Higher count -> longer delay.
        let fact = count as f64 / ERR_BASE as f64;
        let delay = (DELAY_BASE_S * fact).max(DELAY_MIN_S);
        let delay = Duration::from_secs_f64(delay);
        let delay = delay.min(Duration::from_secs_f64(DELAY_MAX_S));

        // Delay to let things cool down.
        log::trace!("Fatal error. Delaying for {delay:?}.");
        time::sleep(delay).await;
    }
}

impl Drop for ErrorThrottle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// vim: ts=4 sw=4 expandtab
