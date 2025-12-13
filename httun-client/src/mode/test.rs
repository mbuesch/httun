// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{client::HttunComm, error_delay};
use anyhow::{self as ah, format_err as err};
use httun_protocol::{Message, MsgType, Operation};
use std::{num::Wrapping, sync::Arc, time::Duration};
use tokio::{sync::mpsc::Sender, task, time::interval};

pub async fn run_mode_test(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    httun_comm: Arc<HttunComm>,
    period_secs: f32,
) -> ah::Result<()> {
    // Spawn task: Test handler.
    task::spawn({
        let mut count = Wrapping(0_u32);

        async move {
            // Connect to the tunnel.
            httun_comm.request_restart().await;

            let mut inter = if period_secs > 0.0 {
                Some(interval(Duration::from_secs_f32(period_secs)))
            } else {
                None
            };

            loop {
                if let Some(inter) = &mut inter {
                    inter.tick().await;
                }

                let testdata = format!("TEST {count:08X}");
                let expected_reply = format!("Reply to: {testdata}");
                log::info!("Sending test mode ping: '{testdata}'");

                let msg = match Message::new(
                    MsgType::Data,
                    Operation::TestToSrv,
                    testdata.into_bytes(),
                ) {
                    Ok(msg) => msg,
                    Err(e) => {
                        log::error!("Make httun packet failed: {e:?}");
                        error_delay().await;
                        continue;
                    }
                };
                httun_comm.send_to_httun(msg).await;

                let msg = httun_comm.recv_from_httun().await;
                let replydata = String::from_utf8_lossy(msg.payload());
                log::info!("Received test mode pong: '{replydata}'");
                if replydata != expected_reply {
                    let _ = exit_tx.send(Err(err!("Test RX: Invalid reply."))).await;
                    break;
                }

                count += 1;
            }
        }
    });
    Ok(())
}

// vim: ts=4 sw=4 expandtab
