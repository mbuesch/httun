// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

mod channel;
mod l7;
mod net_list;
mod ping;
mod protocol;
mod time;

#[cfg(target_os = "linux")]
mod systemd;

#[cfg(target_family = "unix")]
mod unix_sock;
#[cfg(target_family = "windows")]
mod win_pipe;

use crate::{channel::Channels, protocol::ProtocolManager};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use httun_conf::{Config, ConfigVariant};
use httun_util::{
    header::HttpHeader,
    log::setup_logging,
    signal::{recv_signal, register_signal},
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    runtime,
    signal::ctrl_c,
    sync::{self, Semaphore},
    task,
};

#[cfg(target_os = "linux")]
use crate::systemd::systemd_notify_ready;

#[cfg(target_family = "unix")]
use crate::unix_sock::UnixSock;
#[cfg(target_family = "windows")]
use crate::win_pipe::WinPipe;
#[cfg(target_family = "windows")]
use httun_unix_protocol::WINDOWS_PIPE;
#[cfg(target_family = "unix")]
use nix::unistd::{Group, User, setgid, setuid};
#[cfg(target_family = "unix")]
use std::sync::atomic::{self, AtomicBool, AtomicU32};
#[cfg(target_family = "unix")]
use tokio::signal::unix::{SignalKind, signal};

const WORKER_THREADS: usize = 6;

/// The web server's UID (for `FastCGI` socket ownership).
#[cfg(target_family = "unix")]
static WEBSERVER_UID: AtomicU32 = AtomicU32::new(u32::MAX);
/// The web server's GID (for `FastCGI` socket ownership).
#[cfg(target_family = "unix")]
static WEBSERVER_GID: AtomicU32 = AtomicU32::new(u32::MAX);
/// Verification of the web server's UID and GID for unix socket connections is disabled?
#[cfg(target_family = "unix")]
static WEBSERVER_CRED_CHECK_DISABLED: AtomicBool = AtomicBool::new(false);

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
    if opts.no_webserver_cred_check {
        WEBSERVER_CRED_CHECK_DISABLED.store(true, atomic::Ordering::Relaxed);
        log::warn!(
            "The peer credentials of processes connecting \
            to the httun-server unix socket will not be verified \
            (--no-webserver-cred-check)."
        );
    } else {
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
        WEBSERVER_CRED_CHECK_DISABLED.store(false, atomic::Ordering::Relaxed);
    }

    Ok(())
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

    /// User name the web server `FastCGI` or httun-httpserver runs as.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "USER", default_value = "www-data")]
    webserver_user: String,

    /// Group name the web server `FastCGI` or httun-httpserver runs as.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "GROUP", default_value = "www-data")]
    webserver_group: String,

    /// Disable verification of the web server user and group for unix socket connections.
    ///
    /// When this option is set, the httun-server will not check the UID and GID of the
    /// connecting process against --webserver-user and --webserver-group.
    ///
    /// This option is not meant to be used in production environments.
    /// Only use this option for testing.
    #[cfg(target_family = "unix")]
    #[arg(long)]
    no_webserver_cred_check: bool,

    /// Optional path to the socket for communication with httun-fcgi / httun-httpserver.
    ///
    /// If not given and if on Linux, the socket will be fetched from systemd.
    #[cfg(target_family = "unix")]
    #[arg(long, value_name = "PATH")]
    unix_socket: Option<PathBuf>,

    /// Name of the named pipe for communication with httun-httpserver.
    #[cfg(target_family = "windows")]
    #[arg(long, value_name = "NAME")]
    win_pipe: Option<PathBuf>,

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
    /// See <https://crates.io/crates/tokio-console>
    #[arg(long, hide = true)]
    tokio_console: bool,

    /// Maximum number of log messages per second.
    #[arg(long, value_name = "MSG_PER_SEC", default_value = "100.0")]
    log_rate_limit: f32,

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

    // Create the Unix socket for communication with httun-fcgi / httun-httpserver.
    #[cfg(target_family = "unix")]
    let local_ipc = {
        get_webserver_uid_gid(&opts).context("Get web server UID/GID")?;
        UnixSock::new(
            Arc::clone(&conf),
            opts.unix_socket.as_deref(),
            (&*opts.extra_headers).into(),
        )
        .await
        .context("Unix socket init")?
    };

    // Create the Windows named pipe for communication with httun-httpserver.
    #[cfg(target_family = "windows")]
    let local_ipc = {
        let pipe_name = opts
            .win_pipe
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new(WINDOWS_PIPE));
        WinPipe::new(Arc::clone(&conf), pipe_name, (&*opts.extra_headers).into())
            .context("Windows named pipe init")?
    };

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
                protman.periodic_work();
            }
        }
    });

    // Spawn task: IPC to/from fcgi or httun-httpserver.
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

                match local_ipc.accept().await {
                    Ok(conn) => {
                        if let Ok(permit) = conn_semaphore.acquire_owned().await {
                            protman.spawn(conn, channels, permit).await;
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
    // Parse command line options.
    let opts = Arc::new(Opts::parse());

    // Initialize logging.
    setup_logging(opts.log_rate_limit);

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
