// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{
    local_listener::LocalListener,
    resolver::{ResConf, ResMode, resolve},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Message;
use std::sync::Arc;
use tokio::{
    sync::{
        Mutex, Semaphore,
        mpsc::{Receiver, Sender},
    },
    task,
};

pub async fn run_mode_socket(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
    target: &str,
    res_mode: ResMode,
    local_port: u16,
) -> ah::Result<()> {
    let Some(pos) = target.find(':') else {
        return Err(err!("Invalid target address. No colon/port."));
    };
    let target_host = &target[..pos];
    let Ok(target_port) = target[pos + 1..].parse::<u16>() else {
        return Err(err!("Invalid target address. Invalid port number."));
    };

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
        .context("Connect to localhost port")?;

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
                                if let Err(e) = conn
                                    .handle_packets(
                                        to_httun_tx,
                                        from_httun_rx,
                                        target_addr,
                                        target_port,
                                    )
                                    .await
                                {
                                    log::error!("Local client: {e:?}");
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

// vim: ts=4 sw=4 expandtab
