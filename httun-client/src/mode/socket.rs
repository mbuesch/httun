// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{
    async_task_comm::AsyncTaskComm,
    local_listener::LocalListener,
    resolver::{ResConf, ResMode, resolve},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_util::errors::DisconnectedError;
use std::sync::Arc;
use tokio::{
    sync::{Semaphore, mpsc::Sender},
    task,
};

fn split_host_port_string(hostport: &str) -> ah::Result<(&str, u16)> {
    let Some(pos) = hostport.rfind(':') else {
        return Err(err!("Invalid address. No colon/port."));
    };
    let mut host = &hostport[..pos];
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(err!("Invalid IPv6 address. No closing ]."));
        }
        if host.len() <= 2 {
            return Err(err!("Invalid IPv6 address. Nothing inbetween [ ]."));
        }
        host = &host[1..host.len() - 1];
    }
    let Ok(port) = hostport[pos + 1..].parse::<u16>() else {
        return Err(err!("Invalid port number."));
    };

    Ok((host, port))
}

pub async fn run_mode_socket(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    httun_comm: Arc<AsyncTaskComm>,
    target: &str,
    res_mode: ResMode,
    local_port: u16,
) -> ah::Result<()> {
    let (target_host, target_port) =
        split_host_port_string(target).context("Parse target address")?;

    let target_addr = resolve(
        target_host,
        &ResConf {
            mode: res_mode,
            ..Default::default()
        },
    )
    .await
    .context("Resolve host name")?;

    let local = LocalListener::bind(local_port)
        .await
        .context("Bind to port")?;

    log::info!("Listening on port {local_port}");

    // Start the tunnel.
    httun_comm.request_restart().await;

    // Spawn task: Local socket handler.
    task::spawn({
        async move {
            let conn_semaphore = Arc::new(Semaphore::new(1));

            loop {
                let exit_tx = Arc::clone(&exit_tx);
                let httun_comm = Arc::clone(&httun_comm);
                let conn_semaphore = Arc::clone(&conn_semaphore);

                match local.accept().await {
                    Ok(conn) => {
                        log::info!("New connection on local socket port {local_port}.");
                        if let Ok(permit) = conn_semaphore.acquire_owned().await {
                            task::spawn(async move {
                                match conn
                                    .handle_packets(
                                        Arc::clone(&httun_comm),
                                        target_addr,
                                        target_port,
                                    )
                                    .await
                                {
                                    Ok(()) => unreachable!(),
                                    Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                                        log::info!("Local client disconnected.");
                                    }
                                    Err(e) => {
                                        log::error!("Local client: {e:?}");
                                    }
                                }

                                // Restart the tunnel.
                                httun_comm.request_restart().await;

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
    Ok(())
}

// vim: ts=4 sw=4 expandtab
