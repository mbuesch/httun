// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod protocol;
mod systemd;
mod time;
mod unix_sock;

use crate::{channel::Channels, protocol::ProtocolManager, unix_sock::UnixSock};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::Config;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync, task,
};

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Path to the configuration file.
    #[arg(long, short = 'c', default_value = "/opt/httun/etc/httun/server.conf")]
    config: String,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let conf =
        Arc::new(Config::new_parse_file(Path::new(&opts.config)).context("Parse configuration")?);

    let channels = Channels::new(Arc::clone(&conf))
        .await
        .context("Initialize channels")?;

    // Create unix socket.
    let sock = UnixSock::new().await.context("Unix socket init")?;

    //TODO: We should be able to drop root privileges here.

    let protman = ProtocolManager::new();

    // Spawn task: Periodic task.
    task::spawn({
        let protman = Arc::clone(&protman);

        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                protman.check_timeouts().await;
            }
        }
    });

    // Spawn task: Socket handler.
    task::spawn({
        let exit_tx = Arc::clone(&exit_tx);
        let protman = Arc::clone(&protman);

        async move {
            loop {
                let exit_tx = Arc::clone(&exit_tx);
                let protman = Arc::clone(&protman);

                match sock.accept().await {
                    Ok(conn) => {
                        // Socket connection handler.
                        if let Some(chan) = channels.get(conn.chan_name()).await {
                            protman.spawn(conn, chan).await;
                        } else {
                            println!(
                                "Client connection: Channel '{}' does not exist",
                                conn.chan_name()
                            );
                        }
                    }
                    Err(e) => {
                        let _ = exit_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        }
    });

    // Task: Main loop.
    let exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
                println!("SIGHUP: Ignoring.");
            }
            code = exit_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }
    exitcode
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());

    if opts.version {
        println!("httun-server version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(2)
        .worker_threads(2)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
