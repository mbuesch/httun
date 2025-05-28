// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::error_delay;
use anyhow::{self as ah, format_err as err};
use httun_protocol::{Message, MsgType, Operation};
use std::{num::Wrapping, sync::Arc};
use tokio::{
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    task,
};

pub async fn run_mode_test(
    exit_tx: Arc<Sender<ah::Result<()>>>,
    to_httun_tx: Arc<Sender<Message>>,
    from_httun_rx: Arc<Mutex<Receiver<Message>>>,
) -> ah::Result<()> {
    // Spawn task: Test handler.
    task::spawn({
        let mut count = Wrapping(0_u32);

        async move {
            loop {
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
                to_httun_tx.send(msg).await.unwrap();

                if let Some(msg) = from_httun_rx.lock().await.recv().await {
                    let replydata = String::from_utf8_lossy(msg.payload());
                    log::info!("Received test mode pong: '{replydata}'");
                    if replydata != expected_reply {
                        let _ = exit_tx.send(Err(err!("Test RX: Invalid reply."))).await;
                        break;
                    }
                } else {
                    let _ = exit_tx.send(Err(err!("Test RX: No message."))).await;
                    break;
                }

                count += 1;
            }
        }
    });
    Ok(())
}

// vim: ts=4 sw=4 expandtab
