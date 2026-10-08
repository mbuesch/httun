// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use http_server::{HttpConn, HttpServer};
use httun_conf::{Config, ConfigVariant};
#[cfg(target_family = "unix")]
use httun_unix_protocol::UNIX_SOCK;
#[cfg(target_family = "windows")]
use httun_unix_protocol::WINDOWS_PIPE;
use httun_util::{
    errors::DisconnectedError,
    header::HttpHeader,
    signal::{recv_signal, register_signal},
    strings::Direction,
    timeouts::CHAN_R_TIMEOUT,
};
use server_conn::{IpcClientConn, connect};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime,
    signal::ctrl_c,
    sync::{self, Semaphore},
    task,
    time::timeout,
};

#[cfg(target_family = "unix")]
use tokio::signal::unix::{SignalKind, signal};

mod http_server;
mod server_conn;

const WORKER_THREADS: usize = 4;

/// Command line options.
#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(long, short = 'C', value_name = "PATH")]
    config: Option<PathBuf>,

    /// The address or address:port to listen on for HTTP connections.
    ///
    /// For example:
    ///
    /// `0.0.0.0:80` Listen on all IPv4 interfaces on port 80.
    ///
    /// `[::]:80` Listen on all IPv4 + IPv6 interfaces on port 80.
    ///
    /// `192.168.1.1:8080` Listen on IPv4 `192.168.1.1` on port 8080.
    ///
    /// `all` Listen on all IPv4 + IPv6 on port 80
    ///
    /// `any` Listen on all IPv4 + IPv6 on port 80
    ///
    /// `localhost` Listen on `127.0.0.1` port 80
    ///
    /// `ip6-localhost` Listen on `::1` port 80
    ///
    /// If you don't specify the port, then it will default to 80.
    #[arg(long, short = 'l', value_name = "ADDR:PORT")]
    listen: Option<String>,

    /// Path to the Unix socket for communication with httun-server.
    ///
    /// Defaults to the standard httun-server socket path.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "PATH")]
    unix_socket: Option<PathBuf>,

    /// Name of the Windows named pipe for communication with httun-server.
    ///
    /// Defaults to the standard httun-server named pipe.
    #[cfg(target_family = "windows")]
    #[arg(long, value_name = "NAME")]
    ipc_pipe: Option<PathBuf>,

    /// Pass an arbitrary extra HTTP header with every response.
    ///
    /// This option must be formatted as a colon separated name:value pair:
    ///
    /// MYHEADER:MYVALUE
    ///
    /// This option can be specified multiple times to add multiple headers.
    #[arg(long = "extra-header", value_name = "HEADER:VALUE")]
    extra_headers: Vec<HttpHeader>,

    /// Maximum number of simultaneous connections.
    ///
    /// Note that two simultaneous connections are required per user.
    #[arg(short, long, value_name = "NUMBER", default_value = "64")]
    num_connections: usize,

    /// Enable `tokio-console` tracing support.
    ///
    /// See <https://crates.io/crates/tokio-console>
    #[arg(long, hide = true)]
    tokio_console: bool,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

impl Opts {
    /// Get the configuration path from command line or default.
    fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Server)
        }
    }

    /// Get the `--unix-socket` path or the default `UNIX_SOCK` path.
    #[cfg(target_family = "unix")]
    fn get_unix_sock(&self) -> PathBuf {
        if let Some(path) = &self.unix_socket {
            path.clone()
        } else {
            PathBuf::from(UNIX_SOCK)
        }
    }

    /// Get the `--ipc-pipe` name or the default Windows named pipe.
    #[cfg(target_family = "windows")]
    fn get_ipc_pipe(&self) -> PathBuf {
        if let Some(path) = &self.ipc_pipe {
            path.clone()
        } else {
            PathBuf::from(WINDOWS_PIPE)
        }
    }

    /// Parse the --listen option into a `SocketAddr`.
    fn get_listen(&self) -> ah::Result<SocketAddr> {
        const DEFAULT_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        const DEFAULT_PORT: u16 = 80;

        let Some(listen) = &self.listen else {
            return Ok(SocketAddr::new(DEFAULT_ADDR, DEFAULT_PORT));
        };

        if let Ok(addr) = listen.parse::<SocketAddr>() {
            return Ok(addr);
        }
        if let Ok(addr) = listen.parse::<IpAddr>() {
            return Ok(SocketAddr::new(addr, DEFAULT_PORT));
        }

        let (host, port) = if let Some(p) = listen.rfind(':') {
            (
                &listen[..p],
                listen[p + 1..]
                    .parse::<u16>()
                    .context("Parse port number")?,
            )
        } else {
            (listen.as_str(), DEFAULT_PORT)
        };
        let host = host.trim().to_lowercase();

        if ["all", "any"].contains(&host.as_str()) {
            Ok(SocketAddr::new(DEFAULT_ADDR, port))
        } else if host == "localhost" {
            Ok(SocketAddr::new(
                "127.0.0.1".parse().expect("localhost"),
                port,
            ))
        } else if host == "ip6-localhost" {
            Ok(SocketAddr::new("::1".parse().expect("ip6-localhost"), port))
        } else {
            Err(err!("Failed to parse the command line option --listen"))
        }
    }
}

/// Handle a single HTTP connection, proxying requests to httun-server via unix socket.
async fn handle_connection(conn: Arc<HttpConn>, unix_sock_path: Arc<Path>) {
    // Spawn the task to handle incoming HTTP requests.
    conn.spawn_rx_task().await;

    // Wait until the HTTP connection is pinned to a channel.
    let pinned = match conn.wait_pinned().await {
        Ok(p) => p,
        Err(e) => {
            log::error!("Wait channel pin: {e:?}");
            let _ = conn.close().await;
            return;
        }
    };
    if !pinned {
        let _ = conn.close().await;
        return;
    }

    let Some(chan_id) = conn.chan_id() else {
        log::error!("No channel ID after pin");
        let _ = conn.close().await;
        return;
    };

    // Lazily-created unix socket connections to httun-server.
    let mut from_srv: Option<IpcClientConn> = None; // Direction::R
    let mut to_srv: Option<IpcClientConn> = None; // Direction::W

    loop {
        let req = match conn.recv().await {
            Ok(r) => r,
            Err(e) => {
                if e.downcast_ref::<DisconnectedError>().is_some() {
                    log::debug!("HTTP connection closed (chan {chan_id})");
                } else {
                    log::warn!("HTTP recv error (chan {chan_id}): {e:?}");
                }
                break;
            }
        };

        match req.direction() {
            Direction::R => {
                // Ensure we have a FromSrv unix connection.
                if from_srv.is_none() {
                    match connect(&unix_sock_path, chan_id, false).await {
                        Ok(c) => from_srv = Some(c),
                        Err(e) => {
                            log::error!(
                                "Connect to httun-server unix socket '{}' \
                                (FromSrv, chan {chan_id}): {e:?}",
                                unix_sock_path.display()
                            );
                            let _ = conn.send_reply_badrequest(&[]).await;
                            break;
                        }
                    }
                }

                let from_srv = from_srv.as_ref().expect("from_srv is Some");
                let extra_headers = from_srv.extra_headers().to_vec();
                let body = req.into_body();

                let result = timeout(CHAN_R_TIMEOUT, from_srv.recv(body)).await;

                match result {
                    Err(_) => {
                        if let Err(e) = conn.send_reply_timeout(&extra_headers).await {
                            log::error!("Send 408 reply (chan {chan_id}): {e:?}");
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        log::error!("Unix recv (chan {chan_id}): {e:?}");
                        let _ = conn.send_reply_badrequest(&extra_headers).await;
                        break;
                    }
                    Ok(Ok(payload)) => {
                        if let Err(e) = conn.send_reply_ok(&payload, &extra_headers).await {
                            log::error!("HTTP send reply (chan {chan_id}): {e:?}");
                            break;
                        }
                    }
                }
            }

            Direction::W => {
                // Ensure we have a ToSrv unix connection.
                if to_srv.is_none() {
                    match connect(&unix_sock_path, chan_id, true).await {
                        Ok(c) => to_srv = Some(c),
                        Err(e) => {
                            log::error!(
                                "Connect to httun-server unix socket '{}' \
                                (ToSrv, chan {chan_id}): {e:?}",
                                unix_sock_path.display()
                            );
                            let _ = conn.send_reply_badrequest(&[]).await;
                            break;
                        }
                    }
                }

                let to_srv = to_srv.as_ref().expect("to_srv is Some");
                let extra_headers = to_srv.extra_headers().to_vec();
                let body = req.into_body();

                match to_srv.send(body).await {
                    Ok(()) => {
                        if let Err(e) = conn.send_reply_ok(&[], &extra_headers).await {
                            log::error!("HTTP send reply W (chan {chan_id}): {e:?}");
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Unix send (chan {chan_id}): {e:?}");
                        let _ = conn.send_reply_badrequest(&extra_headers).await;
                        break;
                    }
                }
            }
        }
    }

    let _ = conn.close().await;
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel::<ah::Result<()>>(1);
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = register_signal!(terminate).context("Register SIGTERM")?;
    let mut sigint = register_signal!(interrupt).context("Register SIGINT")?;
    let mut sighup = register_signal!(hangup).context("Register SIGHUP")?;

    let conf = Arc::new(
        Config::new_parse_file(&opts.get_config(), ConfigVariant::Server)
            .context("Parse configuration")?,
    );

    let addr = opts.get_listen().context("Parse --listen")?;
    #[cfg(target_family = "unix")]
    let ipc_path: Arc<Path> = Arc::from(opts.get_unix_sock().as_path());
    #[cfg(target_family = "windows")]
    let ipc_path: Arc<Path> = Arc::from(opts.get_ipc_pipe().as_path());

    let http_srv = HttpServer::new(addr, Arc::clone(&conf), (&*opts.extra_headers).into())
        .await
        .context("HTTP server init")?;
    log::info!("HTTP server listening on {addr}");

    // Spawn task: HTTP connection handler.
    task::spawn({
        let opts = Arc::clone(&opts);
        let exit_tx = Arc::clone(&exit_tx);

        async move {
            let conn_semaphore = Arc::new(Semaphore::new(opts.num_connections));
            loop {
                let exit_tx = Arc::clone(&exit_tx);
                let conn_semaphore = Arc::clone(&conn_semaphore);
                let ipc_path = Arc::clone(&ipc_path);

                match http_srv.accept().await {
                    Ok(conn) => {
                        if let Ok(permit) = conn_semaphore.acquire_owned().await {
                            task::spawn(async move {
                                handle_connection(conn, ipc_path).await;
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
        }
    });

    // Task: Main loop.
    loop {
        tokio::select! {
            biased;
            code = exit_rx.recv() => {
                break code.unwrap_or_else(|| Err(err!("Unknown error code.")));
            }
            _ = ctrl_c() => {
                break Err(err!("Interrupted by Ctrl+C."));
            }
            _ = recv_signal!(sigint) => {
                break Err(err!("Interrupted by SIGINT."));
            }
            _ = recv_signal!(sigterm) => {
                log::info!("SIGTERM: Terminating.");
                break Ok(());
            }
            _ = recv_signal!(sighup) => {
                log::info!("SIGHUP: Ignoring.");
            }
        }
    }
}

fn main() -> ah::Result<()> {
    // Initialize logging.
    env_logger::init_from_env(
        env_logger::Env::new()
            .filter_or("HTTUN_LOG", "info")
            .write_style_or("HTTUN_LOG_STYLE", "auto"),
    );

    // Parse command line options.
    let opts = Arc::new(Opts::parse());

    // Initialize tokio-console for debugging if requested.
    if opts.tokio_console {
        console_subscriber::init();
    }

    // Show version and exit if requested.
    if opts.version {
        println!("httun-httpserver version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Build Tokio runtime and run the async main function.
    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_secs(5))
        .max_blocking_threads(WORKER_THREADS * 4)
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
