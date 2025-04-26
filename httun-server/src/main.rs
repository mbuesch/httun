// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod protocol;
mod systemd;
mod unix_sock;

use crate::{
    channel::Channels,
    protocol::ProtocolHandler,
    systemd::{systemd_notify_reload_done, systemd_notify_reload_start},
    unix_sock::UnixSock,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::Config;
use httun_tun::TunHandler;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync, task,
};

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Name of the tun interface to create.
    #[arg(long, short = 't', default_value = "httun-s0")]
    tun: String,

    /// Enable the special __test__ channel for communication tests.
    #[arg(long)]
    enable_test: bool,

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

    let channels = Channels::new(Arc::clone(&conf), opts.enable_test).await;

    // Create tun network interface.
    let tun = Arc::new(
        TunHandler::new(&opts.tun)
            .await
            .context("Tun interface init")?,
    );

    // Create unix socket.
    let sock = UnixSock::new().await.context("Unix socket init")?;

    // Spawn task: Socket handler.
    task::spawn({
        let exit_tx = Arc::clone(&exit_tx);
        let tun = Arc::clone(&tun);

        async move {
            loop {
                let exit_tx = Arc::clone(&exit_tx);
                let tun = Arc::clone(&tun);

                match sock.accept().await {
                    Ok(conn) => {
                        // Socket connection handler.
                        if let Some(chan) = channels.get(conn.chan_name()).await {
                            let mut prot = ProtocolHandler::new(conn, chan, tun).await;
                            task::spawn(async move {
                                loop {
                                    if let Err(e) = prot.run().await {
                                        eprintln!("Client error: {e}");
                                        break;
                                    }
                                }
                            });
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
                println!("Reloading configuration.");
                if let Err(e) = systemd_notify_reload_start() {
                    eprintln!("Reload: Failed to notify systemd (Reloading): {e}");
                }
                //TODO
                if let Err(e) = systemd_notify_reload_done() {
                    eprintln!("Reload: Failed to notify systemd (MonotonicUsec): {e}");
                }
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
