// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod comm_backend;
mod http_server;
mod protocol;
mod systemd;
mod time;
mod uid_gid;
mod unix_sock;

use crate::{
    channel::Channels,
    comm_backend::CommBackend,
    http_server::HttpServer,
    protocol::ProtocolManager,
    uid_gid::{os_get_gid, os_get_uid},
    unix_sock::UnixSock,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::Config;
use nix::unistd::{Gid, Uid, setgid, setuid};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync, task,
};

fn drop_privileges() -> ah::Result<()> {
    log::info!("Dropping root privileges.");

    let uid = Uid::from_raw(os_get_uid("httun").context("Get httun user from /etc/passwd")?);
    let gid = Gid::from_raw(os_get_gid("httun").context("Get httun group from /etc/group")?);

    setgid(gid).context("Drop privileges: Set httun group id")?;
    setuid(uid).context("Drop privileges: Set httun user id")?;

    Ok(())
}

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Path to the configuration file.
    #[arg(long, short = 'c', default_value = "/opt/httun/etc/httun/server.conf")]
    config: String,

    /// Do not drop root privileges after startup.
    #[arg(long)]
    no_drop_root: bool,

    /// Instead of running as an FastCGI backend run a simple HTTP server.
    ///
    /// If you don't specify this option, then httun-server will act as FastCGI backend.
    ///
    /// If you specify this option, then this is the address or address:port to listen on.
    /// For example:
    ///
    /// 0.0.0.0:80 Listen on all IPv4 interfaces on port 80.
    ///
    /// [::]:80 Listen on all IPv4 + IPv6 interfaces on port 80.
    ///
    /// 192.168.1.1:8080 Listen on IPv4 192.168.1.1 on port 8080.
    ///
    /// If you don't specify the port, then it will default to 80.
    #[arg(long)]
    http_listen: Option<String>,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

impl Opts {
    pub fn get_http_listen(&self) -> ah::Result<Option<SocketAddr>> {
        if let Some(http_listen) = &self.http_listen {
            if let Ok(addr) = http_listen.parse::<SocketAddr>() {
                Ok(Some(addr))
            } else if let Ok(addr) = http_listen.parse::<IpAddr>() {
                Ok(Some(SocketAddr::new(addr, 80)))
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
        http_srv = Some(HttpServer::new(addr).await.context("HTTP server init")?);
    } else {
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

    // Spawn task: Unix socket handler (from/to FCGI).
    if let Some(unix_sock) = unix_sock {
        task::spawn({
            let exit_tx = Arc::clone(&exit_tx);
            let channels = Arc::clone(&channels);
            let protman = Arc::clone(&protman);

            async move {
                loop {
                    let exit_tx = Arc::clone(&exit_tx);
                    let channels = Arc::clone(&channels);
                    let protman = Arc::clone(&protman);

                    match unix_sock.accept().await {
                        Ok(conn) => {
                            protman.spawn(CommBackend::new_unix(conn), channels).await;
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
            let exit_tx = Arc::clone(&exit_tx);
            let channels = Arc::clone(&channels);
            let protman = Arc::clone(&protman);

            async move {
                loop {
                    let exit_tx = Arc::clone(&exit_tx);
                    let channels = Arc::clone(&channels);
                    let protman = Arc::clone(&protman);

                    match http_srv.accept().await {
                        Ok(conn) => {
                            conn.spawn_rx_task().await;
                            protman.spawn(CommBackend::new_http(conn), channels).await;
                        }
                        Err(e) => {
                            //TODO do not exit here
                            let _ = exit_tx.send(Err(e)).await;
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
