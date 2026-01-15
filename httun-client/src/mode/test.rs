// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{async_task_comm::AsyncTaskComm, error_delay};
use anyhow::{self as ah, format_err as err};
use httun_protocol::{Message, MsgType, Operation};
use httun_util::{strings::hex, timeouts::PONG_RX_TIMEOUT};
use movavg::MovAvg;
use rand::prelude::*;
use std::{
    num::Wrapping,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc::Sender,
    task,
    time::{interval, timeout},
};

const NR_RAND_BYTES: usize = 1024 * 16;

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

            let mut num_bytes_tx = 0;
            let mut num_bytes_rx = 0;
            let mut avgrate_tx: MovAvg<f32, f32, 3> = MovAvg::new();
            let mut avgrate_rx: MovAvg<f32, f32, 3> = MovAvg::new();
            let mut meas_start = Instant::now();

            loop {
                if let Some(inter) = &mut inter {
                    inter.tick().await;
                }

                let testrand: [u8; NR_RAND_BYTES] = rand::rng().random();
                let testrand = hex(&testrand);
                let testpayload = format!("{count:08X} {testrand}");
                let expected_reply_payload = format!("Pong: {testpayload}");

                num_bytes_tx += testpayload.len();

                let msg = match Message::new(
                    MsgType::Data,
                    Operation::TestToSrv,
                    testpayload.into_bytes(),
                ) {
                    Ok(msg) => msg,
                    Err(e) => {
                        log::error!("Make httun packet failed: {e:?}");
                        error_delay().await;
                        httun_comm.request_restart().await;
                        continue;
                    }
                };
                httun_comm.send_to_httun(msg).await;

                let Ok(msg) = timeout(PONG_RX_TIMEOUT, httun_comm.recv_from_httun()).await else {
                    log::error!("Timeout receiving PONG.");
                    httun_comm.request_restart().await;
                    continue;
                };

                let reply_payload = String::from_utf8_lossy(msg.payload());
                if reply_payload != expected_reply_payload {
                    let _ = exit_tx
                        .send(Err(err!("Test: Received invalid ping reply payload.")))
                        .await;
                    break;
                }

                num_bytes_rx += reply_payload.len();

                let secs = 1.0;
                let now = Instant::now();
                if now >= meas_start + Duration::from_secs_f32(secs) {
                    let rate_tx = avgrate_tx.feed(num_bytes_tx as f32 / secs);
                    let rate_rx = avgrate_rx.feed(num_bytes_rx as f32 / secs);
                    meas_start = now;
                    num_bytes_tx = 0;
                    num_bytes_rx = 0;

                    let mut fmt = humansize::BINARY;
                    fmt.decimal_places = 1;
                    let rate_tx = humansize::format_size(rate_tx as u64, fmt);
                    let rate_rx = humansize::format_size(rate_rx as u64, fmt);
                    log::info!("Test Ok. Payload data rate tx: {rate_tx}/s, rx: {rate_rx}/s.");
                }

                count += 1;
            }
        }
    });
    Ok(())
}

// vim: ts=4 sw=4 expandtab
