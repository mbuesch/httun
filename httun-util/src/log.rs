// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::{
    sync::{
        Mutex as StdMutex,
        atomic::{self, AtomicBool},
    },
    time::Instant,
};

const QLEN: usize = 100;
const FILL_THRES: usize = QLEN / 10;

struct RateLimitedLogger<L: Log> {
    inner: L,
    max_msg_per_second_rate: f32,
    stamps: StdMutex<heapless::Deque<Instant, QLEN>>,
    limited: AtomicBool,
}

impl<L: Log> RateLimitedLogger<L> {
    pub fn new(inner: L, max_msg_per_second_rate: f32) -> Self {
        Self {
            inner,
            max_msg_per_second_rate,
            stamps: StdMutex::new(heapless::Deque::new()),
            limited: AtomicBool::new(false),
        }
    }
}

impl<L: Log> Log for RateLimitedLogger<L> {
    fn enabled(&self, m: &Metadata) -> bool {
        self.inner.enabled(m)
    }

    #[allow(clippy::cast_precision_loss)]
    fn log(&self, r: &Record) {
        let limited;
        match log::max_level() {
            LevelFilter::Debug | LevelFilter::Trace => {
                // If selected maximum log level is Debug/Trace, do not apply rate limiting.
                limited = false;
            }
            _ => {
                let now = Instant::now();
                let mut stamps = self.stamps.lock().unwrap();
                if stamps.len() == QLEN {
                    stamps.pop_front();
                }
                stamps.push_back(now).unwrap();
                if stamps.len() > FILL_THRES.max(2) {
                    let durn = now - *stamps.front().unwrap();
                    let rate = QLEN as f32 / durn.as_secs_f32();
                    limited = rate > self.max_msg_per_second_rate;
                    let was_limited = self.limited.swap(limited, atomic::Ordering::Relaxed);
                    if !was_limited && limited {
                        let record = Record::builder()
                            .args(format_args!(
                                "Log message RATE LIMIT exceeded. Dropping further messages."
                            ))
                            .level(Level::Warn)
                            .target(r.target())
                            .file(r.file())
                            .line(r.line())
                            .module_path(r.module_path())
                            .build();
                        self.inner.log(&record);
                    }
                } else {
                    limited = false;
                }
            }
        }
        if !limited {
            self.inner.log(r);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

pub fn setup_logging(max_msg_per_second_rate: f32) {
    let inner = env_logger::Builder::from_env(
        env_logger::Env::new()
            .filter_or("HTTUN_LOG", "info")
            .write_style_or("HTTUN_LOG_STYLE", "auto"),
    )
    .build();
    let max_level = inner.filter();
    let limited = RateLimitedLogger::new(inner, max_msg_per_second_rate);
    log::set_boxed_logger(Box::new(limited)).expect("Logger already set");
    log::set_max_level(max_level);
}

// vim: ts=4 sw=4 expandtab
