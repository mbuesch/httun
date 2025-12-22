// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow as ah;

#[cfg(target_family = "unix")]
mod async_main;

#[cfg(target_family = "unix")]
mod fcgi;

#[cfg(target_family = "unix")]
mod fcgi_handler;

#[cfg(target_family = "unix")]
mod server_conn;

fn main() -> ah::Result<()> {
    #[cfg(target_family = "unix")]
    {
        use anyhow::Context as _;

        const WORKER_THREADS: usize = 6;

        tokio::runtime::Builder::new_multi_thread()
            .thread_keep_alive(std::time::Duration::from_millis(5000))
            .max_blocking_threads(WORKER_THREADS * 4)
            .worker_threads(WORKER_THREADS)
            .enable_all()
            .build()
            .context("Tokio runtime builder")?
            .block_on(crate::async_main::async_main())
    }
    #[cfg(not(target_family = "unix"))]
    {
        Err(ah::format_err!("FastCGI is not supported on this OS."))
    }
}

// vim: ts=4 sw=4 expandtab
