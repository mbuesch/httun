// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod comm_backend;
mod http_server;
mod l7;
mod net_list;
mod ping;
mod protocol;
mod time;

#[cfg(target_os = "linux")]
mod systemd;

#[cfg(target_family = "unix")]
mod unix_sock;

use crate::{
    channel::Channels, comm_backend::CommBackend, http_server::HttpServer,
    protocol::ProtocolManager,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::{Config, ConfigVariant};
use httun_util::header::HttpHeader;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime,
    sync::{self, Semaphore},
    task,
};

#[cfg(target_os = "linux")]
use crate::systemd::systemd_notify_ready;

#[cfg(target_family = "unix")]
use crate::unix_sock::UnixSock;
#[cfg(target_family = "unix")]
use nix::unistd::{Group, User, setgid, setuid};
#[cfg(target_family = "unix")]
use std::sync::atomic::{self, AtomicU32};
#[cfg(target_family = "unix")]
use tokio::signal::unix::{SignalKind, signal};

/// The web server's UID (for FastCGI socket ownership).
#[cfg(target_family = "unix")]
static WEBSERVER_UID: AtomicU32 = AtomicU32::new(u32::MAX);
/// The web server's GID (for FastCGI socket ownership).
#[cfg(target_family = "unix")]
static WEBSERVER_GID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Drop root privileges.
#[cfg(target_family = "unix")]
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
#[cfg(target_family = "unix")]
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
        tokio::time::sleep(Duration::MAX).await;
    }
}

#[cfg(not(target_family = "unix"))]
macro_rules! recv_signal {
    ($sig:ident) => {
        signal_dummy(&mut $sig)
    };
}

/// Command line options.
#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(long, short = 'C', value_name = "PATH")]
    config: Option<PathBuf>,

    /// Do not drop root privileges after startup.
    #[cfg(target_family = "unix")]
    #[arg(long)]
    no_drop_root: bool,

    /// User name the web server FastCGI runs as.
    ///
    /// This option is only used, if --http-listen is not used.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "USER", default_value = "www-data")]
    webserver_user: String,

    /// Group name the web server FastCGI runs as.
    ///
    /// This option is only used, if --http-listen is not used.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "GROUP", default_value = "www-data")]
    webserver_group: String,

    /// Optional path to the socket for communication with httun-fcgi.
    ///
    /// If not given and if on Linux, the socket will be fetched from systemd.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "PATH")]
    unix_socket: Option<PathBuf>,

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
    /// `localhost` Listen on 127.0.0.1 port 80
    ///
    /// 'ip6-localhost' Listen on ::1 port 80
    ///
    /// If you don't specify the port, then it will default to 80.
    #[arg(long, value_name = "ADDR:PORT")]
    http_listen: Option<String>,

    /// Pass an arbitrary extra HTTP header with every request sent on the HTTP connection.
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
    /// See https://crates.io/crates/tokio-console
    #[arg(long, hide = true)]
    tokio_console: bool,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

impl Opts {
    /// Get the configuration path from command line or default.
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Server)
        }
    }

    /// Get the --http-listen option.
    pub fn get_http_listen(&self) -> ah::Result<Option<SocketAddr>> {
        const DEFAULT_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        const DEFAULT_PORT: u16 = 80;

        if let Some(http_listen) = &self.http_listen {
            if let Ok(addr) = http_listen.parse::<SocketAddr>() {
                Ok(Some(addr))
            } else if let Ok(addr) = http_listen.parse::<IpAddr>() {
                Ok(Some(SocketAddr::new(addr, DEFAULT_PORT)))
            } else {
                let (host, port) = if let Some(p) = http_listen.rfind(':') {
                    (
                        &http_listen[..p],
                        http_listen[p + 1..]
                            .parse::<u16>()
                            .context("Parse port number")?,
                    )
                } else {
                    (http_listen.as_str(), DEFAULT_PORT)
                };
                let host = host.trim().to_lowercase();

                if ["all", "any"].contains(&host.as_str()) {
                    Ok(Some(SocketAddr::new(DEFAULT_ADDR, port)))
                } else if host == "localhost" {
                    Ok(Some(SocketAddr::new("127.0.0.1".parse().unwrap(), port)))
                } else if host == "ip6-localhost" {
                    Ok(Some(SocketAddr::new("::1".parse().unwrap(), port)))
                } else {
                    Err(err!(
                        "Failed to parse the command line option --http-listen"
                    ))
                }
            }
        } else {
            Ok(None)
        }
    }
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel::<ah::Result<()>>(1);
    #[allow(unused_variables)]
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = register_signal!(terminate).context("Register SIGTERM")?;
    let mut sigint = register_signal!(interrupt).context("Register SIGINT")?;
    let mut sighup = register_signal!(hangup).context("Register SIGHUP")?;

    let conf = Arc::new(
        Config::new_parse_file(&opts.get_config(), ConfigVariant::Server)
            .context("Parse configuration")?,
    );

    // Either start simple standalone HTTP server or Unix socket for FastCGI.
    let mut http_srv = None;
    #[cfg(target_family = "unix")]
    let mut unix_sock = None;
    if let Some(addr) = opts.get_http_listen()? {
        http_srv = Some(
            HttpServer::new(addr, Arc::clone(&conf), (&*opts.extra_headers).into())
                .await
                .context("HTTP server init")?,
        );
        log::info!("HTTP server listening on {addr}");
    } else {
        #[cfg(target_family = "unix")]
        {
            get_webserver_uid_gid(&opts).context("Get web server UID/GID")?;
            unix_sock = Some(
                UnixSock::new(
                    Arc::clone(&conf),
                    opts.unix_socket.as_deref(),
                    (&*opts.extra_headers).into(),
                )
                .await
                .context("Unix socket init")?,
            );
        }
    }

    // Initialize channel manager.
    let channels = Arc::new(
        Channels::new(Arc::clone(&conf))
            .await
            .context("Initialize channels")?,
    );

    // Drop root privileges because we are done with privileged operations.
    #[cfg(target_family = "unix")]
    {
        if opts.no_drop_root {
            log::warn!("Not dropping root privileges as requested (--no-drop-root).");
        } else {
            drop_privileges().context("Drop root privileges")?;
        }
    }

    // Initialize the httun protocol manager.
    let protman = ProtocolManager::new(Arc::clone(&conf));

    // Notify systemd that we are ready.
    #[cfg(target_os = "linux")]
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

    // Spawn task: Unix socket handler (from/to FastCGI).
    #[cfg(target_family = "unix")]
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
            code = recv_signal!(exit_rx) => {
                #[cfg(target_family = "unix")]
                {
                    exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                    break;
                }
                #[cfg(not(target_family = "unix"))]
                {
                    let _: () = code;
                    unreachable!();
                }
            }
        }
    }
    exitcode
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
        println!("httun-server version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Build Tokio runtime and run the async main function.
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
