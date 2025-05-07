// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_protocol::{
    Key, Message, MsgType, Operation, SequenceGenerator, SequenceType, SequenceValidator,
    SessionSecret, secure_random,
};
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
const SESSION_INIT_RETRIES: usize = 5;

pub type ToHttun = Message;
pub type FromHttun = Message;

fn make_url(base_url: &str, serial: u64) -> String {
    format!("{}/{:010X}", base_url, serial & 0x000000FF_FFFFFFFF)
}

macro_rules! define_direction {
    ($struct:ident, $urlpath:literal) => {
        struct $struct {
            #[allow(dead_code)]
            conf: Arc<Config>,
            name: String,
            url: String,
            session_id: u16,
            session_secret: SessionSecret,
            serial: AtomicU64,
        }

        impl $struct {
            fn new(
                conf: Arc<Config>,
                name: &str,
                base_url: &str,
                session_id: u16,
                session_secret: SessionSecret,
            ) -> Self {
                Self {
                    conf,
                    name: name.to_string(),
                    url: format!("{base_url}/{}", $urlpath),
                    session_id,
                    session_secret,
                    serial: AtomicU64::new(0),
                }
            }
        }
    };
}

define_direction!(DirectionR, "r");
define_direction!(DirectionW, "w");

async fn direction_r(
    chan: Arc<DirectionR>,
    loc: Arc<Sender<FromHttun>>,
    user_agent: &str,
    key: &Key,
) -> ah::Result<()> {
    chan.serial
        .store(u64::from_ne_bytes(secure_random()), Relaxed);

    let tx_sequence_c = SequenceGenerator::new(SequenceType::C);
    let mut rx_validator_a = SequenceValidator::new(SequenceType::A, chan.conf.rx_window_length());

    let client = Client::builder()
        .user_agent(user_agent)
        .referer(false)
        .timeout(HTTP_R_TIMEOUT)
        .tcp_nodelay(true)
        .build()
        .context("httun HTTP-r build HTTP client")?;

    let http_auth = chan.conf.http_auth(&chan.name);

    loop {
        let mut resp;

        'http: loop {
            let mut msg = Message::new(MsgType::Data, Operation::FromSrv, vec![])?;
            msg.set_session(chan.session_id);
            msg.set_sequence(tx_sequence_c.next());
            let msg = msg.serialize_b64u(key, Some(chan.session_secret));

            let url = make_url(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let mut req = client
                .get(&url)
                .query(&[("m", &msg)])
                .header("Cache-Control", "no-store");
            if let Some(http_auth) = &http_auth {
                req = req.basic_auth(&http_auth.user, http_auth.password.as_ref());
            }
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

            let msg = Message::deserialize(data, key, Some(chan.session_secret))
                .context("Message deserialize")?;
            if msg.type_() != MsgType::Data {
                return Err(err!("Received invalid message type"));
            }
            if msg.oper() != Operation::FromSrv {
                return Err(err!("Received invalid message operation"));
            }
            if msg.session() != chan.session_id {
                return Err(err!("Received invalid message session"));
            }
            rx_validator_a
                .check_recv_seq(&msg)
                .context("rx sequence validation SequenceType::A")?;

            loc.send(msg).await?;
        }
    }
}

async fn direction_w(
    chan: Arc<DirectionW>,
    loc: Arc<Mutex<Receiver<ToHttun>>>,
    user_agent: &str,
    key: &Key,
) -> ah::Result<()> {
    chan.serial
        .store(u64::from_ne_bytes(secure_random()), Relaxed);

    let tx_sequence_b = SequenceGenerator::new(SequenceType::B);

    let client = Client::builder()
        .user_agent(user_agent)
        .referer(false)
        .timeout(HTTP_W_TIMEOUT)
        .tcp_nodelay(true)
        .build()
        .context("httun HTTP-w build HTTP client")?;

    let http_auth = chan.conf.http_auth(&chan.name);

    loop {
        let Some(mut msg) = loc.lock().await.recv().await else {
            return Err(err!("ToHttun IPC closed"));
        };

        msg.set_session(chan.session_id);
        msg.set_sequence(tx_sequence_b.next());

        let msg = msg.serialize(key, Some(chan.session_secret));

        if DEBUG {
            println!("Send to HTTP-w: {msg:?}");
        }

        'http: loop {
            let url = make_url(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let mut req = client
                .post(&url)
                .header("Cache-Control", "no-store")
                .header("Content-Type", "application/octet-stream")
                .body(msg.clone());
            if let Some(http_auth) = &http_auth {
                req = req.basic_auth(&http_auth.user, http_auth.password.as_ref());
            }
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

async fn get_session(
    conf: &Config,
    chan_name: &str,
    base_url: &str,
    user_agent: &str,
    key: &Key,
) -> ah::Result<(u16, SessionSecret)> {
    let client = Client::builder()
        .user_agent(user_agent)
        .referer(false)
        .timeout(Duration::from_secs(5))
        .tcp_nodelay(true)
        .build()
        .context("httun session build HTTP client")?;

    let http_auth = conf.http_auth(chan_name);

    for _ in 0..SESSION_INIT_RETRIES {
        let mut msg = Message::new(MsgType::Init, Operation::FromSrv, vec![])?;
        msg.set_session(u16::from_ne_bytes(secure_random()));
        msg.set_sequence(u64::from_ne_bytes(secure_random()));
        let msg = msg.serialize_b64u(key, None);

        let url = make_url(
            &format!("{base_url}/r"),
            u64::from_ne_bytes(secure_random()),
        );
        let mut req = client
            .get(&url)
            .query(&[("m", &msg)])
            .header("Cache-Control", "no-store");
        if let Some(http_auth) = &http_auth {
            req = req.basic_auth(&http_auth.user, http_auth.password.as_ref());
        }
        let resp = req.send().await.context("httun session send")?;

        match resp.status() {
            StatusCode::OK => (),
            _ => {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        }

        let data: &[u8] = &resp.bytes().await.context("httun session get body")?;
        let msg = Message::deserialize(data, key, None).context("Message deserialize")?;
        if msg.type_() != MsgType::Init {
            return Err(err!("Received invalid message type"));
        }
        if msg.oper() != Operation::FromSrv {
            return Err(err!("Received invalid message operation"));
        }
        let session_id = msg.session();
        let Ok(session_secret) = msg.into_payload().try_into() else {
            return Err(err!("Received invalid session secret"));
        };

        return Ok((session_id, session_secret));
    }

    Err(err!("Failed to get session ID from server."))
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
        conf: Arc<Config>,
    ) -> ah::Result<Self> {
        let key;
        if test_mode {
            key = [0; 32];
            channel = "__test__";
        } else {
            key = conf.key(channel).context("Get key from configuration")?;
        }

        let url = format!("{}/{}", url, channel);

        let (session_id, session_secret) =
            get_session(&conf, channel, &url, user_agent, &key).await?;
        if DEBUG {
            println!("Got session ID: {session_id}");
        }

        Ok(Self {
            r: Arc::new(DirectionR::new(
                Arc::clone(&conf),
                channel,
                &url,
                session_id,
                session_secret,
            )),
            w: Arc::new(DirectionW::new(
                Arc::clone(&conf),
                channel,
                &url,
                session_id,
                session_secret,
            )),
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
