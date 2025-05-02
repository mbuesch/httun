// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

mod client;
mod local_listener;

use crate::{client::HttunClient, local_listener::LocalListener};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::{Parser, Subcommand};
use httun_conf::Config;
use httun_protocol::{Key, Message, MsgType, Operation, secure_random};
use httun_tun::TunHandler;
use std::{num::Wrapping, path::Path, sync::Arc, time::Duration};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync::{
        Mutex, Semaphore,
        mpsc::{self, Receiver, Sender},
    },
    task, time,
};

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// URL of the httun HTTP server.
    ///
    /// The URL is in the form of:
    /// http://www.example.com/httun
    ///
    /// Where '/httun' is the base path to the FCGI.
    server_url: Option<String>,

    /// The httun channel to use for communication.
    #[arg(default_value = "a")]
    channel: String,

    /// The User-Agent header to use for the HTTP connection.
    #[arg(long, default_value = "")]
    user_agent: String,

    /// Path to the configuration file.
    #[arg(long, short = 'c', default_value = "/opt/httun/etc/httun/client.conf")]
    config: String,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,

    #[command(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Create a local IP 'tun' interface as tunnel entry/exit point.
    ///
    /// This requires root privileges.
    Tun {
        /// Name of the tun interface to create.
        #[arg(long, short = 't', default_value = "httun-c0")]
        tun: String,
    },

    /// Create a local IP socket listener as tunnel entry/exit point.
    Socket {
        /// Tunnel target socket address in the format IPADDR:PORT
        target: String,

        /// The port that httun-client listens on localhost.
        #[arg(long, short = 'p', default_value = "8080")]
        local_port: u16,
    },

    /// Run a httun server connection test.
    ///
    /// This does not create an actual tunnel, but only tests
    /// the communication between httun-client and httun-server
    /// (via HTTP httun-fcgi).
    ///
    /// The transferred test data is not encrypted.
    Test {},

    /// Generate a new truly random key.
    Genkey {},
}

async fn error_delay() {
    time::sleep(Duration::from_millis(500)).await;
}

/// Generate a new truly random and secure key.
pub async fn run_genkey(channel: &str) -> ah::Result<()> {
    let key: Key = secure_random();
    let key: Vec<String> = key.iter().map(|b| format!("{b:02X}")).collect();
    let key: String = key.join("");
    println!("{channel} = \"{key}\"");
    Ok(())
}

async fn run_mode_tun(
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
    tun_name: &str,
) -> ah::Result<()> {
    let tun = Arc::new(
        TunHandler::new(tun_name)
            .await
            .context("Create TUN interface")?,
    );

    // Spawn task: TUN to HTTP.
    task::spawn({
        let tun = Arc::clone(&tun);

        async move {
            loop {
                let tun = Arc::clone(&tun);

                match tun.recv().await {
                    Ok(pkg) => {
                        let msg = match Message::new(MsgType::Data, Operation::ToSrv, pkg) {
                            Ok(msg) => msg,
                            Err(e) => {
                                eprintln!("Make httun packet failed: {e}");
                                error_delay().await;
                                continue;
                            }
                        };
                        if let Err(e) = to_httun_tx.send(msg).await {
                            eprintln!("Send to httun failed: {e}");
                            error_delay().await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Recv from TUN error: {e}");
                        error_delay().await;
                    }
                }
            }
        }
    });

    // Spawn task: HTTP to TUN.
    task::spawn({
        let tun = Arc::clone(&tun);

        async move {
            loop {
                let tun = Arc::clone(&tun);

                if let Some(pkg) = from_httun_rx.lock().await.recv().await {
                    if let Err(e) = tun.send(&pkg.into_payload()).await {
                        eprintln!("Send to TUN error: {e}");
                        error_delay().await;
                    }
                } else {
                    eprintln!("Recv from httun failed.");
                    error_delay().await;
                }
            }
        }
    });

    Ok(())
}

async fn run_mode_socket(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
    target: &str,
    local_port: u16,
) -> ah::Result<()> {
    let local = LocalListener::bind(local_port)
        .await
        .context("Connect to localhost port")?;

    let _ = target; //TODO

    // Spawn task: Local socket handler.
    task::spawn({
        async move {
            let conn_semaphore = Semaphore::new(1);

            loop {
                let exit_tx = Arc::clone(&exit_tx);
                let to_httun_tx = Arc::clone(&to_httun_tx);
                let from_httun_rx = Arc::clone(&from_httun_rx);

                match local.accept().await {
                    Ok(conn) => {
                        // Socket connection handler.
                        if let Ok(_permit) = conn_semaphore.acquire().await {
                            task::spawn(async move {
                                if let Err(e) =
                                    conn.handle_packets(to_httun_tx, from_httun_rx).await
                                {
                                    eprintln!("Local client error: {e}");
                                }
                            });
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
    Ok(())
}

async fn run_mode_test(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
) -> ah::Result<()> {
    // Spawn task: Test handler.
    task::spawn({
        let mut count = Wrapping(0_u32);

        async move {
            let mut interval = time::interval(Duration::from_millis(1000));
            loop {
                interval.tick().await;

                let testdata = format!("TEST {count:08X}");
                let expected_reply = format!("Reply to: {testdata}");
                println!("Sending test mode ping: '{testdata}'");

                let msg = match Message::new(MsgType::Data, Operation::ToSrv, testdata.into_bytes())
                {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Make httun packet failed: {e}");
                        error_delay().await;
                        continue;
                    }
                };
                to_httun_tx.send(msg).await.unwrap();

                if let Some(msg) = from_httun_rx.lock().await.recv().await {
                    let replydata = String::from_utf8_lossy(msg.payload());
                    println!("Received test mode pong: '{replydata}'");
                    if replydata != expected_reply {
                        let _ = exit_tx.send(Err(err!("Test RX: Invalid reply."))).await;
                        break;
                    }
                } else {
                    let _ = exit_tx.send(Err(err!("Test RX: No message."))).await;
                    break;
                }

                count += 1;
            }
        }
    });
    Ok(())
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    if matches!(opts.mode, Some(Mode::Genkey {})) {
        return run_genkey(&opts.channel).await;
    }

    if opts.mode.is_none() {
        return Err(err!(
            "'httun-client' requires a subcommand but one was not provided. \
            Please run 'httun --help' for more information."
        ));
    }
    if opts.server_url.is_none() {
        return Err(err!(
            "'httun-client' requires the SERVER_URL argument. \
            Please run 'httun --help' for more information."
        ));
    }

    let conf =
        Arc::new(Config::new_parse_file(Path::new(&opts.config)).context("Parse configuration")?);

    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);
    let (from_httun_tx, from_httun_rx) = mpsc::channel(1);
    let (to_httun_tx, to_httun_rx) = mpsc::channel(1);

    let to_httun_tx = Arc::new(to_httun_tx);
    let from_httun_rx = Arc::new(Mutex::new(from_httun_rx));
    let from_httun_tx = Arc::new(from_httun_tx);
    let to_httun_rx = Arc::new(Mutex::new(to_httun_rx));

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let mut client = HttunClient::connect(
        opts.server_url.as_ref().unwrap(),
        &opts.channel,
        matches!(opts.mode, Some(Mode::Test {})),
        &opts.user_agent,
        &conf,
    )
    .await
    .context("Connect to httun server (FCGI)")?;

    // Spawn task: httun client handler.
    task::spawn({
        let exit_tx = Arc::clone(&exit_tx);

        async move {
            loop {
                let _exit_tx = Arc::clone(&exit_tx);
                let from_httun_tx = Arc::clone(&from_httun_tx);
                let to_httun_rx = Arc::clone(&to_httun_rx);

                if let Err(e) = client.handle_packets(from_httun_tx, to_httun_rx).await {
                    eprintln!("httun client error: {e}");
                    error_delay().await;
                }
            }
        }
    });

    match &opts.mode {
        Some(Mode::Tun { tun }) => {
            run_mode_tun(Arc::clone(&to_httun_tx), Arc::clone(&from_httun_rx), tun).await?;
        }
        Some(Mode::Socket { target, local_port }) => {
            run_mode_socket(
                Arc::clone(&exit_tx),
                Arc::clone(&to_httun_tx),
                Arc::clone(&from_httun_rx),
                target,
                *local_port,
            )
            .await?;
        }
        Some(Mode::Test {}) => {
            run_mode_test(
                Arc::clone(&exit_tx),
                Arc::clone(&to_httun_tx),
                Arc::clone(&from_httun_rx),
            )
            .await?;
        }
        None | Some(Mode::Genkey {}) => unreachable!(),
    }

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
        println!("httun version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(4)
        .worker_threads(4)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
