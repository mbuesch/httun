// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_protocol::{Key, Message};
use rand::prelude::*;
use reqwest::{Client, StatusCode};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    task,
    time::sleep,
};

const DEBUG: bool = false;
const HTTP_R_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_W_TIMEOUT: Duration = Duration::from_secs(10);

pub type ToHttun = Message;
pub type FromHttun = Message;

fn make_url(base_url: &str, serial: u64) -> String {
    format!("{}/{:010X}", base_url, serial & 0x000000FF_FFFFFFFF)
}

struct DirectionR {
    url: String,
    serial: AtomicU64,
}

impl DirectionR {
    fn new(base_url: &str) -> Self {
        Self {
            url: format!("{base_url}/r"),
            serial: AtomicU64::new(0),
        }
    }
}

async fn direction_r(
    chan: Arc<DirectionR>,
    loc: Arc<Sender<FromHttun>>,
    user_agent: &str,
    key: &Key,
) -> ah::Result<()> {
    chan.serial.store(rand::rng().random(), Relaxed);

    let client = Client::builder()
        .user_agent(user_agent)
        .referer(false)
        .timeout(HTTP_R_TIMEOUT)
        .tcp_nodelay(true)
        .build()
        .context("httun HTTP-r build HTTP client")?;

    loop {
        let mut resp;

        'http: loop {
            let url = make_url(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let req = client.get(&url).header("Cache-Control", "no-store");
            resp = req.send().await.context("httun HTTP-r send")?;

            match resp.status() {
                StatusCode::OK => {
                    break 'http;
                }
                StatusCode::REQUEST_TIMEOUT => {
                    // Fast retry.
                    continue 'http;
                }
                StatusCode::BAD_GATEWAY
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::TOO_MANY_REQUESTS => {
                    // Slow retry.
                    sleep(Duration::from_millis(100)).await;
                    continue 'http;
                }
                status => {
                    // Hard error.
                    sleep(Duration::from_millis(100)).await;
                    return Err(err!("httun HTTP-r response: {status}"));
                }
            }
        }

        let data: &[u8] = &resp.bytes().await.context("httun HTTP-r get body")?;
        if !data.is_empty() {
            if DEBUG {
                println!("Received from HTTP-r: {data:?}");
            }

            let msg = Message::deserialize(data, key).context("Message deserialize")?;

            loc.send(msg).await?;
        }
    }
}

struct DirectionW {
    url: String,
    serial: AtomicU64,
}

impl DirectionW {
    fn new(base_url: &str) -> Self {
        Self {
            url: format!("{base_url}/w"),
            serial: AtomicU64::new(0),
        }
    }
}

async fn direction_w(
    chan: Arc<DirectionW>,
    loc: Arc<Mutex<Receiver<ToHttun>>>,
    user_agent: &str,
    key: &Key,
) -> ah::Result<()> {
    chan.serial.store(rand::rng().random(), Relaxed);

    let client = Client::builder()
        .user_agent(user_agent)
        .referer(false)
        .timeout(HTTP_W_TIMEOUT)
        .tcp_nodelay(true)
        .build()
        .context("httun HTTP-w build HTTP client")?;

    loop {
        let Some(msg) = loc.lock().await.recv().await else {
            return Err(err!("ToHttun IPC closed"));
        };

        let data = msg.serialize(key);

        if DEBUG {
            println!("Send to HTTP-w: {data:?}");
        }

        'http: loop {
            let url = make_url(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let req = client
                .post(&url)
                .header("Cache-Control", "no-store")
                .header("Content-Type", "application/octet-stream")
                .body(data.clone());
            let resp = req.send().await.context("httun HTTP-w send")?;

            match resp.status() {
                StatusCode::OK => {
                    break 'http;
                }
                StatusCode::REQUEST_TIMEOUT => {
                    // Fast retry.
                    continue 'http;
                }
                StatusCode::BAD_GATEWAY
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::TOO_MANY_REQUESTS => {
                    // Slow retry.
                    sleep(Duration::from_millis(100)).await;
                    continue 'http;
                }
                status => {
                    // Hard error.
                    sleep(Duration::from_millis(100)).await;
                    return Err(err!("httun HTTP-w response: {status}"));
                }
            }
        }
    }
}

pub struct HttunClient {
    r: Arc<DirectionR>,
    w: Arc<DirectionW>,
    user_agent: String,
    key: Arc<Key>,
}

impl HttunClient {
    pub async fn connect(
        url: &str,
        mut channel: &str,
        test_mode: bool,
        user_agent: &str,
        conf: &Config,
    ) -> ah::Result<Self> {
        let key;
        if test_mode {
            key = [0; 32];
            channel = "__test__";
        } else {
            key = conf.key(channel).context("Get key from configuration")?;
        }
        let url = format!("{}/{}", url, channel);
        Ok(Self {
            r: Arc::new(DirectionR::new(&url)),
            w: Arc::new(DirectionW::new(&url)),
            user_agent: user_agent.to_string(),
            key: Arc::new(key),
        })
    }

    pub async fn handle_packets(
        &mut self,
        from_httun: Arc<Sender<FromHttun>>,
        to_httun: Arc<Mutex<Receiver<ToHttun>>>,
    ) -> ah::Result<()> {
        let r_task = task::spawn({
            let r = Arc::clone(&self.r);
            let user_agent = self.user_agent.clone();
            let key = Arc::clone(&self.key);
            async move { direction_r(r, from_httun, &user_agent, &key).await }
        });

        let w_task = task::spawn({
            let w = Arc::clone(&self.w);
            let user_agent = self.user_agent.clone();
            let key = Arc::clone(&self.key);
            async move { direction_w(w, to_httun, &user_agent, &key).await }
        });

        tokio::select! {
            ret = r_task => ret.context("httun HTTP-r")?,
            ret = w_task => ret.context("httun HTTP-w")?,
        }
    }
}

// vim: ts=4 sw=4 expandtab
