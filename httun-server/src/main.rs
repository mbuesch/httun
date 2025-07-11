// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod comm_backend;
mod http_server;
mod l7;
mod ping;
mod protocol;
mod systemd;
mod time;
mod unix_sock;

use crate::{
    channel::Channels, comm_backend::CommBackend, http_server::HttpServer,
    protocol::ProtocolManager, systemd::systemd_notify_ready, unix_sock::UnixSock,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::Config;
use nix::unistd::{Group, User, setgid, setuid};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{self, AtomicU32},
    },
    time::Duration,
};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync::{self, Semaphore},
    task,
};

static WEBSERVER_UID: AtomicU32 = AtomicU32::new(u32::MAX);
static WEBSERVER_GID: AtomicU32 = AtomicU32::new(u32::MAX);

fn drop_privileges() -> ah::Result<()> {
    log::info!("Dropping root privileges.");

    let user_name = "httun";
    let group_name = "httun";

    let user = User::from_name(user_name)
        .context("Get httun uid from /etc/passwd")?
        .ok_or_else(|| err!("User '{user_name}' not found in /etc/passwd"))?;
    let group = Group::from_name(group_name)
        .context("Get httun gid from /etc/group")?
        .ok_or_else(|| err!("Group '{group_name}' not found in /etc/group"))?;

    setgid(group.gid).context("Drop privileges: Set httun group id")?;
    setuid(user.uid).context("Drop privileges: Set httun user id")?;

    Ok(())
}

/// Get web server UID and GID.
fn get_webserver_uid_gid(opts: &Opts) -> ah::Result<()> {
    let user_name = &opts.webserver_user;
    let group_name = &opts.webserver_group;

    let uid = User::from_name(user_name)
        .context("Get web server uid from /etc/passwd")?
        .ok_or_else(|| err!("User '{user_name}' not found in /etc/passwd"))?
        .uid
        .as_raw();
    let gid = Group::from_name(group_name)
        .context("Get web server gid from /etc/group")?
        .ok_or_else(|| err!("Group '{group_name}' not found in /etc/group"))?
        .gid
        .as_raw();

    WEBSERVER_UID.store(uid, atomic::Ordering::Relaxed);
    WEBSERVER_GID.store(gid, atomic::Ordering::Relaxed);

    Ok(())
}

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Path to the configuration file.
    #[arg(
        long,
        short = 'C',
        id = "PATH",
        default_value = "/opt/httun/etc/httun/server.conf"
    )]
    config: String,

    /// Do not drop root privileges after startup.
    #[arg(long)]
    no_drop_root: bool,

    /// User name the web server FastCGI runs as.
    ///
    /// This option is only used, if --http-listen is not used.
    #[arg(long, id = "USER", default_value = "www-data")]
    webserver_user: String,

    /// Group name the web server FastCGI runs as.
    ///
    /// This option is only used, if --http-listen is not used.
    #[arg(long, id = "GROUP", default_value = "www-data")]
    webserver_group: String,

    /// Instead of running as an FastCGI backend run a simple HTTP server.
    ///
    /// If you don't specify this option, then httun-server will act as FastCGI backend.
    ///
    /// If you specify this option, then this is the address or address:port to listen on.
    /// For example:
    ///
    /// `0.0.0.0:80` Listen on all IPv4 interfaces on port 80.
    ///
    /// `[::]:80` Listen on all IPv4 + IPv6 interfaces on port 80.
    ///
    /// `192.168.1.1:8080` Listen on IPv4 192.168.1.1 on port 8080.
    ///
    /// `all` Listen on all IPv4 + IPv6 on port 80
    ///
    /// `any` Listen on all IPv4 + IPv6 on port 80
    ///
    /// If you don't specify the port, then it will default to 80.
    #[arg(long, id = "ADDR:PORT")]
    http_listen: Option<String>,

    /// Maximum number of simultaneous connections.
    ///
    /// Note that two simultaneous connections are required per user.
    #[arg(short, long, id = "NUMBER", default_value = "64")]
    num_connections: usize,

    /// Enable `tokio-console` tracing support.
    ///
    /// See https://crates.io/crates/tokio-console
    #[arg(long)]
    tokio_console: bool,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

impl Opts {
    pub fn get_http_listen(&self) -> ah::Result<Option<SocketAddr>> {
        const DEFAULT_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        const DEFAULT_PORT: u16 = 80;

        if let Some(http_listen) = &self.http_listen {
            if ["all", "any"].contains(&http_listen.trim().to_lowercase().as_str()) {
                Ok(Some(SocketAddr::new(DEFAULT_ADDR, DEFAULT_PORT)))
            } else if let Ok(addr) = http_listen.parse::<SocketAddr>() {
                Ok(Some(addr))
            } else if let Ok(addr) = http_listen.parse::<IpAddr>() {
                Ok(Some(SocketAddr::new(addr, DEFAULT_PORT)))
            } else {
                Err(err!(
                    "Failed to parse the command line option --http-listen"
                ))
            }
        } else {
            Ok(None)
        }
    }
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

    let mut http_srv = None;
    let mut unix_sock = None;
    if let Some(addr) = opts.get_http_listen()? {
        http_srv = Some(
            HttpServer::new(addr, Arc::clone(&conf))
                .await
                .context("HTTP server init")?,
        );
    } else {
        get_webserver_uid_gid(&opts).context("Get web server UID/GID")?;
        unix_sock = Some(UnixSock::new().await.context("Unix socket init")?);
    }

    let channels = Arc::new(
        Channels::new(Arc::clone(&conf))
            .await
            .context("Initialize channels")?,
    );

    if !opts.no_drop_root {
        drop_privileges().context("Drop root privileges")?;
    }

    let protman = ProtocolManager::new();

    systemd_notify_ready()?;

    // Spawn task: Periodic task.
    task::spawn({
        let protman = Arc::clone(&protman);

        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                protman.periodic_work().await;
            }
        }
    });

    // Spawn task: Unix socket handler (from/to FCGI).
    if let Some(unix_sock) = unix_sock {
        task::spawn({
            let opts = Arc::clone(&opts);
            let exit_tx = Arc::clone(&exit_tx);
            let channels = Arc::clone(&channels);
            let protman = Arc::clone(&protman);

            async move {
                let conn_semaphore = Arc::new(Semaphore::new(opts.num_connections));
                loop {
                    let exit_tx = Arc::clone(&exit_tx);
                    let channels = Arc::clone(&channels);
                    let protman = Arc::clone(&protman);
                    let conn_semaphore = Arc::clone(&conn_semaphore);

                    match unix_sock.accept().await {
                        Ok(conn) => {
                            if let Ok(permit) = conn_semaphore.acquire_owned().await {
                                protman
                                    .spawn(CommBackend::new_unix(conn), channels, permit)
                                    .await;
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
    }

    // Spawn task: HTTP server handler.
    if let Some(http_srv) = http_srv {
        task::spawn({
            let opts = Arc::clone(&opts);
            let channels = Arc::clone(&channels);
            let protman = Arc::clone(&protman);

            async move {
                let conn_semaphore = Arc::new(Semaphore::new(opts.num_connections));
                loop {
                    let channels = Arc::clone(&channels);
                    let protman = Arc::clone(&protman);
                    let conn_semaphore = Arc::clone(&conn_semaphore);

                    match http_srv.accept().await {
                        Ok(conn) => {
                            if let Ok(permit) = conn_semaphore.acquire_owned().await {
                                conn.spawn_rx_task().await;
                                protman
                                    .spawn(CommBackend::new_http(conn), channels, permit)
                                    .await;
                            }
                        }
                        Err(e) => {
                            log::error!("HTTP accept: {e:?}");
                            break;
                        }
                    }
                }
            }
        });
    }

    // Task: Main loop.
    let exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
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

    if opts.tokio_console {
        console_subscriber::init();
    }

    if opts.version {
        println!("httun-server version {}", env!("CARGO_PKG_VERSION"));
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
