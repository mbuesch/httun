// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

mod async_task_comm;
mod client;
mod error_throttle;
mod local_listener;
mod mode;
mod resolver;

use crate::{
    async_task_comm::AsyncTaskComm,
    client::{HttunClient, HttunClientMode},
    error_throttle::ErrorThrottle,
    mode::{
        generate::{run_mode_genkey, run_mode_genuuid},
        socket::run_mode_socket,
        test::run_mode_test,
        tun::run_mode_tun,
    },
    resolver::ResMode,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::{CommandFactory, Parser, Subcommand};
use httun_conf::{Config, ConfigVariant};
use httun_util::{header::HttpHeader, ChannelId};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{runtime, signal::ctrl_c, sync::mpsc, task, time};

#[cfg(target_family = "unix")]
use tokio::signal::unix::{SignalKind, signal};

/// Connect to a httun tunnel server.
#[derive(Parser, Debug, Clone)]
struct Opts {
    /// URL of the httun HTTP server.
    ///
    /// The URL is in the form of:
    /// http://www.example.com/httun
    ///
    /// Where '/httun' is the base path to the FCGI.
    server_url: Option<String>,

    /// Identify the local channel configuration by alias rather than by URL.
    #[arg(long, short = 'a', value_name = "CHAN-ALIAS")]
    alias: Option<String>,

    /// The httun server's channel ID to use for communication.
    #[arg(long, short = 'c', value_name = "ID")]
    channel: Option<ChannelId>,

    /// The User-Agent header to use for the HTTP connection.
    ///
    /// By default no User-Agent header will be sent.
    #[arg(long, default_value = "", value_name = "UA")]
    user_agent: String,

    /// Pass an arbitrary extra HTTP header with every request sent on the HTTP connection.
    ///
    /// This option must be formatted as a colon separated name:value pair:
    ///
    /// MYHEADER:MYVALUE
    ///
    /// This option can be specified multiple times to add multiple headers.
    #[arg(long = "extra-header", value_name = "HEADER:VALUE")]
    extra_headers: Vec<HttpHeader>,

    /// Resolve host names to IPv4 addresses.
    #[arg(short = '4')]
    resolve_ipv4: bool,

    /// Resolve host names to IPv6 addresses.
    ///
    /// This option takes precedence over -4, if both are specified.
    #[arg(short = '6')]
    resolve_ipv6: bool,

    /// Override the default path to the configuration file.
    #[arg(long, short = 'C', value_name = "PATH")]
    config: Option<PathBuf>,

    /// Enable `tokio-console` tracing support.
    ///
    /// See https://crates.io/crates/tokio-console
    #[arg(long, hide = true)]
    tokio_console: bool,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,

    #[command(subcommand)]
    mode: Option<Mode>,
}

impl Opts {
    /// Get the configuration path from command line or default.
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Client)
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Create a local IP 'tun' interface as tunnel entry/exit point.
    ///
    /// This requires root privileges.
    Tun {
        /// Name of the tun interface to create.
        #[arg(
            long,
            short = 't',
            value_name = "INTERFACE-NAME",
            default_value = "httun-c-0"
        )]
        tun: String,
    },

    /// Create a local IP socket listener as tunnel entry/exit point.
    Socket {
        /// Tunnel target socket address.
        ///
        /// This can either be in the format IPADDR:PORT or HOSTNAME:PORT.
        #[arg(value_name = "TARGETHOSTNAME:PORT")]
        target: String,

        /// The port that httun-client listens on localhost.
        #[arg(long, short = 'p', value_name = "PORT", default_value = "8080")]
        local_port: u16,
    },

    /// Run a httun server connection test.
    ///
    /// This does not create an actual tunnel, but only tests
    /// the communication between httun-client and httun-server
    /// (via HTTP httun-fcgi).
    ///
    /// The transferred test data is not encrypted.
    Test {
        /// Delay time between test messages.
        ///
        /// By default test messages are sent as fast as possible.
        /// But this options lets you reduce the test message frequency
        /// by increasing the period.
        #[arg(long, short, default_value = "0.0")]
        period: f32,
    },

    /// Generate a new truly random key.
    GenKey {},

    /// Generate a new UUID.
    GenUuid {},
}

/// Default delay after errors before retrying.
pub async fn error_delay() {
    time::sleep(Duration::from_millis(100)).await;
}

#[cfg(target_family = "unix")]
macro_rules! register_signal {
    ($kind:ident) => {
        signal(SignalKind::$kind())
    };
}

#[cfg(not(target_family = "unix"))]
macro_rules! register_signal {
    ($kind:ident) => {{
        let result: ah::Result<u32> = Ok(0_u32);
        result
    }};
}

#[cfg(target_family = "unix")]
macro_rules! recv_signal {
    ($sig:ident) => {
        $sig.recv()
    };
}

#[cfg(not(target_family = "unix"))]
async fn signal_dummy<T>(_: &mut T) {
    loop {
        time::sleep(Duration::MAX).await;
    }
}

#[cfg(not(target_family = "unix"))]
macro_rules! recv_signal {
    ($sig:ident) => {
        signal_dummy(&mut $sig)
    };
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    match opts.mode {
        Some(Mode::GenKey {}) => {
            return run_mode_genkey().await;
        }
        Some(Mode::GenUuid {}) => {
            return run_mode_genuuid().await;
        }
        _ => (),
    }

    if opts.mode.is_none() {
        Opts::command()
            .print_help()
            .context("Failed to print help")?;
        println!();
        return Err(err!(
            "'httun-client' requires a subcommand but one was not provided."
        ));
    }
    if opts.server_url.is_none() {
        Opts::command()
            .print_help()
            .context("Failed to print help")?;
        println!();
        return Err(err!("'httun-client' requires the SERVER_URL argument."));
    }

    let conf = Arc::new(
        Config::new_parse_file(&opts.get_config(), ConfigVariant::Client)
            .context("Parse configuration")?,
    );

    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = register_signal!(terminate).context("Register SIGTERM")?;
    let mut sigint = register_signal!(interrupt).context("Register SIGINT")?;

    // Get the resolver mode from the options.
    let res_mode = match (opts.resolve_ipv6, opts.resolve_ipv4) {
        (true, false) | (true, true) => ResMode::Ipv6,
        (false, false) | (false, true) => ResMode::Ipv4,
    };

    // Initialize communication between the async tasks.
    let task_comm = Arc::new(AsyncTaskComm::new());

    // Spawn task: httun client handler.
    task::spawn({
        let opts = Arc::clone(&opts);
        let exit_tx = Arc::clone(&exit_tx);
        let task_comm = Arc::clone(&task_comm);

        async move {
            let ethrottle = ErrorThrottle::new();

            let client_mode = match opts.mode {
                Some(Mode::Tun { .. }) => HttunClientMode::L3,
                Some(Mode::Socket { .. }) => HttunClientMode::L7,
                Some(Mode::Test { .. }) => HttunClientMode::Test,
                None | Some(Mode::GenKey {}) | Some(Mode::GenUuid {}) => unreachable!(),
            };

            // Connect to the httun server.
            let mut client = match HttunClient::connect(
                opts.server_url.as_ref().expect("opts.server_url is None"),
                res_mode,
                opts.alias.as_deref(),
                opts.channel,
                client_mode,
                &opts.user_agent,
                (&*opts.extra_headers).into(),
                Arc::clone(&conf),
            )
            .await
            .context("Connect to httun server (FCGI)")
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = exit_tx.send(Err(e)).await;
                    return;
                }
            };

            loop {
                let _exit_tx = Arc::clone(&exit_tx);
                let task_comm = Arc::clone(&task_comm);

                if let Err(e) = client.handle_packets(task_comm).await {
                    log::error!("httun client: {e:?}");
                } else {
                    log::error!("httun client: Unexpected: handle_packets() returned Ok.");
                }
                ethrottle.error().await;
            }
        }
    });

    // Spawn task: Mode handler.
    task::spawn({
        let opts = Arc::clone(&opts);
        let exit_tx = Arc::clone(&exit_tx);
        let task_comm = Arc::clone(&task_comm);

        async move {
            match &opts.mode {
                Some(Mode::Tun { tun }) => {
                    if let Err(e) = run_mode_tun(Arc::clone(&task_comm), tun).await {
                        let _ = exit_tx.send(Err(e)).await;
                    }
                }
                Some(Mode::Socket { target, local_port }) => {
                    if let Err(e) = run_mode_socket(
                        Arc::clone(&exit_tx),
                        Arc::clone(&task_comm),
                        target,
                        res_mode,
                        *local_port,
                    )
                    .await
                    {
                        let _ = exit_tx.send(Err(e)).await;
                    }
                }
                Some(Mode::Test { period }) => {
                    if let Err(e) =
                        run_mode_test(Arc::clone(&exit_tx), Arc::clone(&task_comm), *period).await
                    {
                        let _ = exit_tx.send(Err(e)).await;
                    }
                }
                None | Some(Mode::GenKey {}) | Some(Mode::GenUuid {}) => unreachable!(),
            }
        }
    });

    // Task: Main loop.
    tokio::select! {
        biased;
        code = exit_rx.recv() => {
            code.unwrap_or_else(|| Err(err!("Unknown error code.")))
        }
        _ = ctrl_c() => {
            Err(err!("Interrupted by Ctrl+C."))
        }
        _ = recv_signal!(sigint) => {
            Err(err!("Interrupted by SIGINT."))
        }
        _ = recv_signal!(sigterm) => {
            log::info!("SIGTERM: Terminating.");
            Ok(())
        }
    }
}

fn main() -> ah::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::new()
            .filter_or("HTTUN_LOG", "info")
            .write_style_or("HTTUN_LOG_STYLE", "auto"),
    );

    let opts = Arc::new(Opts::parse());

    if opts.tokio_console {
        console_subscriber::init();
    }

    if opts.version {
        println!("httun version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    const WORKER_THREADS: usize = 6;
    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(WORKER_THREADS * 4)
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
