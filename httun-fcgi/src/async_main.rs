// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    fcgi::Fcgi,
    fcgi_handler::{check_connection_timeouts, fcgi_handler, init_fcgi_handler},
};
use anyhow::{self as ah, Context as _, format_err as err};
use std::{os::fd::AsRawFd as _, sync::Arc, time::Duration};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{self, Semaphore},
    task,
};

/// Maximum number of connections from the FastCGI server.
pub const MAX_NUM_CONNECTIONS: u8 = 64;

pub async fn async_main() -> ah::Result<()> {
    println!("Spawning new httun-fcgi: {}", std::process::id());

    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Initialize FastCGI handler.
    init_fcgi_handler()?;

    // Create FastCGI listener.
    let fcgi = Fcgi::new(std::io::stdin().as_raw_fd()).context("Create FCGI")?;

    // Spawn task: Periodic task.
    task::spawn({
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                check_connection_timeouts().await;
            }
        }
    });

    // Spawn task: FastCGI handler.
    task::spawn(async move {
        let conn_semaphore = Arc::new(Semaphore::new(MAX_NUM_CONNECTIONS.into()));
        loop {
            let conn_semaphore = Arc::clone(&conn_semaphore);
            match fcgi.accept().await {
                Ok(mut conn) => {
                    if let Ok(permit) = conn_semaphore.acquire_owned().await {
                        task::spawn(async move {
                            if let Err(e) = conn.handle(fcgi_handler).await {
                                eprintln!("FCGI conn error: {e:?}");
                            }
                            drop(permit);
                        });
                    }
                }
                Err(e) => {
                    let _ = exit_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Task: Main loop.
    tokio::select! {
        biased;
        code = exit_rx.recv() => {
            code.unwrap_or_else(|| Err(err!("Unknown error code.")))
        }
        _ = sigint.recv() => {
            Err(err!("Interrupted by SIGINT."))
        }
        _ = sigterm.recv() => {
            eprintln!("SIGTERM: Terminating.");
            Ok(())
        }
    }
}

// vim: ts=4 sw=4 expandtab
