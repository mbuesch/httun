// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use httun_protocol::Message;
use std::sync::Arc;
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn run_mode_tun(
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
    tun_name: &str,
) -> ah::Result<()> {
    use crate::error_delay;
    use anyhow::Context as _;
    use httun_protocol::{Message, MsgType, Operation};
    use tokio::task;

    let tun = Arc::new(
        httun_tun::TunHandler::new(tun_name)
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
                                log::error!("Make httun packet failed: {e:?}");
                                error_delay().await;
                                continue;
                            }
                        };
                        if let Err(e) = to_httun_tx.send(msg).await {
                            log::error!("Send to httun failed: {e:?}");
                            error_delay().await;
                        }
                    }
                    Err(e) => {
                        log::error!("Recv from TUN error: {e:?}");
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
                        log::error!("Send to TUN error: {e:?}");
                        error_delay().await;
                    }
                } else {
                    log::error!("Recv from httun failed.");
                    error_delay().await;
                }
            }
        }
    });

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub async fn run_mode_tun(
    _to_httun_tx: Arc<Sender<Message>>,
    _from_httun_rx: Arc<Mutex<Receiver<Message>>>,
    _tun_name: &str,
) -> ah::Result<()> {
    Err(ah::format_err!("TUN is only supported on Linux."))
}

// vim: ts=4 sw=4 expandtab
