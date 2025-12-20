// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{async_task_comm::AsyncTaskComm, error_delay};
use anyhow::{self as ah, format_err as err};
use httun_protocol::{Message, MsgType, Operation, secure_random};
use httun_util::strings::hex;
use movavg::MovAvg;
use std::{
    num::Wrapping,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc::Sender, task, time::interval};

pub async fn run_mode_test(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    httun_comm: Arc<AsyncTaskComm>,
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

            let mut num_bytes = 0;
            let mut meas_start = Instant::now();
            let mut avgrate: MovAvg<f32, f32, 3> = MovAvg::new();

            loop {
                if let Some(inter) = &mut inter {
                    inter.tick().await;
                }

                let testbase = format!("{count:08X}");
                let testpayload: [u8; 1024 * 16] = secure_random();
                let testpayload = hex(&testpayload);
                let testdata = format!("{testbase} {testpayload}");
                let expected_reply = format!("Pong: {testdata}");

                num_bytes += testdata.len();

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
                if replydata != expected_reply {
                    let _ = exit_tx.send(Err(err!("Test RX: Invalid reply."))).await;
                    break;
                }

                let secs = 1.0;
                let now = Instant::now();
                if now >= meas_start + Duration::from_secs_f32(secs) {
                    let rate = avgrate.feed(num_bytes as f32 / secs);
                    meas_start = now;
                    num_bytes = 0;

                    let mut fmt = humansize::BINARY;
                    fmt.decimal_places = 1;
                    let rate = humansize::format_size(rate as u64, fmt);
                    log::info!("Test mode data rate {}/s.", rate);
                }

                count += 1;
            }
        }
    });
    Ok(())
}

// vim: ts=4 sw=4 expandtab
