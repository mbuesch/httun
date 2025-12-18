// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::async_task_comm::AsyncTaskComm;
use anyhow as ah;
use std::sync::Arc;

#[cfg(all(feature = "tun", target_os = "linux"))]
pub async fn run_mode_tun(httun_comm: Arc<AsyncTaskComm>, tun_name: &str) -> ah::Result<()> {
    use crate::error_delay;
    use anyhow::Context as _;
    use httun_protocol::{Message, MsgType, Operation};
    use tokio::task;

    let tun = Arc::new(
        httun_tun::TunHandler::new(tun_name)
            .await
            .context("Create TUN interface")?,
    );

    // Start the tunnel.
    httun_comm.request_restart().await;

    // Spawn task: TUN to HTTP.
    task::spawn({
        let tun = Arc::clone(&tun);
        let httun_comm = Arc::clone(&httun_comm);

        async move {
            loop {
                match tun.recv().await {
                    Ok(pkg) => {
                        let msg = match Message::new(MsgType::Data, Operation::L3ToSrv, pkg) {
                            Ok(msg) => msg,
                            Err(e) => {
                                log::error!("Make httun packet failed: {e:?}");
                                error_delay().await;
                                httun_comm.request_restart().await;
                                continue;
                            }
                        };
                        httun_comm.send_to_httun(msg).await;
                    }
                    Err(e) => {
                        log::error!("Recv from TUN error: {e:?}");
                        error_delay().await;
                        httun_comm.request_restart().await;
                    }
                }
            }
        }
    });

    // Spawn task: HTTP to TUN.
    task::spawn({
        let tun = Arc::clone(&tun);
        let httun_comm = Arc::clone(&httun_comm);

        async move {
            loop {
                let pkg = httun_comm.recv_from_httun().await;
                if let Err(e) = tun.send(&pkg.into_payload()).await {
                    log::error!("Send to TUN error: {e:?}");
                    error_delay().await;
                    httun_comm.request_restart().await;
                }
            }
        }
    });

    Ok(())
}

#[cfg(not(all(feature = "tun", target_os = "linux")))]
pub async fn run_mode_tun(_httun_comm: Arc<AsyncTaskComm>, _tun_name: &str) -> ah::Result<()> {
    Err(ah::format_err!("TUN is support is disabled"))
}

// vim: ts=4 sw=4 expandtab
