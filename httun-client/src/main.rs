// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

mod client;
mod local_listener;
mod mode;
mod resolver;

use crate::{
    client::HttunClient,
    mode::{
        genkey::run_mode_genkey, socket::run_mode_socket, test::run_mode_test, tun::run_mode_tun,
    },
    resolver::ResMode,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::{Parser, Subcommand};
use httun_conf::Config;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    runtime,
    sync::{Mutex, mpsc},
    task, time,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use tokio::signal::unix::{SignalKind, signal};

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
    #[arg(long, short = 'c', default_value = "a")]
    channel: String,

    /// The User-Agent header to use for the HTTP connection.
    #[arg(long, default_value = "")]
    user_agent: String,

    /// Resolve host names to IPv4 addresses.
    #[arg(short = '4')]
    resolve_ipv4: bool,

    /// Resolve host names to IPv6 addresses.
    ///
    /// This option takes precedence over -4, if both are specified.
    #[arg(short = '6')]
    resolve_ipv6: bool,

    /// Path to the configuration file.
    #[arg(
        long,
        short = 'C',
        id = "PATH",
        default_value = "/opt/httun/etc/httun/client.conf"
    )]
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
        #[arg(long, short = 't', id = "INTERFACE-NAME", default_value = "httun-c-0")]
        tun: String,
    },

    /// Create a local IP socket listener as tunnel entry/exit point.
    Socket {
        /// Tunnel target socket address.
        ///
        /// This can either be in the format IPADDR:PORT or HOSTNAME:PORT.
        #[arg(id = "TARGETHOSTNAME:PORT")]
        target: String,

        /// The port that httun-client listens on localhost.
        #[arg(long, short = 'p', id = "PORT", default_value = "8080")]
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

pub async fn error_delay() {
    time::sleep(Duration::from_millis(500)).await;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
macro_rules! register_signal {
    ($kind:ident) => {
        signal(SignalKind::$kind()).unwrap()
    };
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
macro_rules! register_signal {
    ($kind:ident) => {
        ()
    };
}

#[cfg(any(target_os = "linux", target_os = "android"))]
macro_rules! recv_signal {
    ($sig:ident) => {
        $sig.recv()
    };
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn signal_dummy(_: &mut ()) {
    loop {
        time::sleep(Duration::MAX).await;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
macro_rules! recv_signal {
    ($sig:ident) => {
        signal_dummy(&mut $sig)
    };
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    if matches!(opts.mode, Some(Mode::Genkey {})) {
        return run_mode_genkey(&opts.channel).await;
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
    let mut sigterm = register_signal!(terminate);
    let mut sigint = register_signal!(interrupt);
    let mut sighup = register_signal!(hangup);

    let res_mode = match (opts.resolve_ipv6, opts.resolve_ipv4) {
        (false, false) | (true, false) | (true, true) => ResMode::Ipv6,
        (false, true) => ResMode::Ipv4,
    };

    //TODO resolve server_url host name.

    let mut client = HttunClient::connect(
        opts.server_url.as_ref().unwrap(),
        &opts.channel,
        matches!(opts.mode, Some(Mode::Test {})),
        &opts.user_agent,
        Arc::clone(&conf),
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
                    log::error!("httun client: {e:?}");
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
                res_mode,
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
            _ = recv_signal!(sigterm) => {
                log::info!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = recv_signal!(sigint) => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = recv_signal!(sighup) => {
                log::info!("SIGHUP: Ignoring.");
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
    env_logger::init_from_env(
        env_logger::Env::new()
            .filter_or("HTTUN_LOG", "info")
            .write_style_or("HTTUN_LOG_STYLE", "auto"),
    );

    let opts = Arc::new(Opts::parse());

    if opts.version {
        println!("httun version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    const WORKER_THREADS: usize = 6;
    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(WORKER_THREADS * 2)
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
