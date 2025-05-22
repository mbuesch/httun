// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::{Config, ConfigChannel};
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

const HTTP_R_TIMEOUT: Duration = Duration::from_secs(8);
const HTTP_W_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_INIT_RETRIES: usize = 5;

pub type ToHttun = Message;
pub type FromHttun = Message;

fn make_client(
    user_agent: &str,
    timeout: Duration,
    chan_conf: &ConfigChannel,
) -> ah::Result<Client> {
    let mut c = Client::builder();

    if !user_agent.trim().is_empty() {
        c = c.user_agent(user_agent);
    }
    c = c.referer(false);
    c = c.timeout(timeout);
    c = c.tcp_nodelay(true);

    c = c.gzip(chan_conf.http_allow_compression());
    c = c.deflate(chan_conf.http_allow_compression());
    c = c.brotli(chan_conf.http_allow_compression());
    c = c.zstd(chan_conf.http_allow_compression());

    c = c.hickory_dns(true);

    // Allow proxies (or any other MiM) to manipulate the TLS connection.
    c = c.danger_accept_invalid_hostnames(chan_conf.https_ignore_tls_errors());
    c = c.danger_accept_invalid_certs(chan_conf.https_ignore_tls_errors());

    Ok(c.build()?)
}

fn format_url_serial(url: &str, serial: u64) -> String {
    let url = url.trim_end_matches('/');
    format!("{}/{:010X}", url, serial & 0x000000FF_FFFFFFFF)
}

fn format_url(base_url: &str, chan_name: &str, direction: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    let chan_name = chan_name.trim_matches('/');
    let direction = direction.trim_matches('/');
    format!("{base_url}/{chan_name}/{direction}")
}

macro_rules! define_direction {
    ($struct:ident, $urlpath:literal) => {
        struct $struct {
            #[allow(dead_code)]
            conf: Arc<Config>,
            base_url: String,
            name: String,
            url: String,
            #[allow(dead_code)]
            test_mode: bool,
            serial: AtomicU64,
        }

        impl $struct {
            fn new(conf: Arc<Config>, base_url: &str, name: &str, test_mode: bool) -> Self {
                Self {
                    conf,
                    name: name.to_string(),
                    base_url: base_url.to_string(),
                    url: format_url(base_url, name, $urlpath),
                    test_mode,
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
    session_id: u16,
    session_secret: SessionSecret,
) -> ah::Result<()> {
    let chan_conf = chan
        .conf
        .channel_with_url(&chan.base_url, &chan.name)
        .expect("Chan conf");

    chan.serial
        .store(u64::from_ne_bytes(secure_random()), Relaxed);

    let tx_sequence_c = SequenceGenerator::new(SequenceType::C);
    let window_length = chan.conf.parameters().receive().window_length();
    let mut rx_validator_a = SequenceValidator::new(SequenceType::A, window_length);

    let client = make_client(user_agent, HTTP_R_TIMEOUT, chan_conf)
        .context("httun HTTP-r build HTTP client")?;

    let http_auth = chan_conf.http_basic_auth().clone();

    loop {
        let oper = if chan.test_mode {
            Operation::TestFromSrv
        } else {
            Operation::FromSrv
        };
        let mut resp;

        'http: loop {
            let mut msg = Message::new(MsgType::Data, oper, vec![])?;
            msg.set_session(session_id);
            msg.set_sequence(tx_sequence_c.next());
            let msg = msg.serialize_b64u(key, Some(session_secret));

            let url = format_url_serial(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let mut req = client
                .get(&url)
                .query(&[("m", &msg)])
                .header("Cache-Control", "no-store");
            if let Some(http_auth) = &http_auth {
                req = req.basic_auth(http_auth.user(), http_auth.password());
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
            log::trace!("Received from HTTP-r: {data:?}");

            let msg = Message::deserialize(data, key, Some(session_secret))
                .context("Message deserialize")?;
            if msg.type_() != MsgType::Data {
                return Err(err!("Received invalid message type"));
            }
            if msg.oper() != oper {
                return Err(err!("Received invalid message operation"));
            }
            if msg.session() != session_id {
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
    session_id: u16,
    session_secret: SessionSecret,
) -> ah::Result<()> {
    let chan_conf = chan
        .conf
        .channel_with_url(&chan.base_url, &chan.name)
        .expect("Chan conf");

    chan.serial
        .store(u64::from_ne_bytes(secure_random()), Relaxed);

    let tx_sequence_b = SequenceGenerator::new(SequenceType::B);

    let client = make_client(user_agent, HTTP_W_TIMEOUT, chan_conf)
        .context("httun HTTP-w build HTTP client")?;

    let http_auth = chan_conf.http_basic_auth().clone();

    loop {
        let Some(mut msg) = loc.lock().await.recv().await else {
            return Err(err!("ToHttun IPC closed"));
        };

        msg.set_session(session_id);
        msg.set_sequence(tx_sequence_b.next());

        let msg = msg.serialize(key, Some(session_secret));

        log::trace!("Send to HTTP-w: {msg:?}");

        'http: loop {
            let url = format_url_serial(&chan.url, chan.serial.fetch_add(1, Relaxed));
            let mut req = client
                .post(&url)
                .header("Cache-Control", "no-store")
                .header("Content-Type", "application/octet-stream")
                .body(msg.clone());
            if let Some(http_auth) = &http_auth {
                req = req.basic_auth(http_auth.user(), http_auth.password());
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
    base_url: &str,
    chan_name: &str,
    user_agent: &str,
    key: &Key,
) -> ah::Result<(u16, SessionSecret)> {
    let chan_conf = conf
        .channel_with_url(base_url, chan_name)
        .expect("Chan conf");

    let client = make_client(user_agent, Duration::from_secs(5), chan_conf)
        .context("httun session build HTTP client")?;

    let http_auth = chan_conf.http_basic_auth().clone();

    for i in 0..SESSION_INIT_RETRIES {
        let last_try = i == SESSION_INIT_RETRIES - 1;

        let mut msg = Message::new(MsgType::Init, Operation::FromSrv, vec![])?;
        msg.set_session(u16::from_ne_bytes(secure_random()));
        msg.set_sequence(u64::from_ne_bytes(secure_random()));
        let msg = msg.serialize_b64u(key, None);

        let url = format_url_serial(
            &format_url(base_url, chan_name, "r"),
            u64::from_ne_bytes(secure_random()),
        );
        let mut req = client
            .get(&url)
            .query(&[("m", &msg)])
            .header("Cache-Control", "no-store");
        if let Some(http_auth) = &http_auth {
            req = req.basic_auth(http_auth.user(), http_auth.password());
        }
        let resp = req.send().await.context("httun session send")?;

        match resp.status() {
            StatusCode::OK => (),
            StatusCode::UNAUTHORIZED => {
                if last_try {
                    return Err(err!(
                        "The server replied with \"HTTP 401 Unauthorized\". \
                        You probably need to use http basic-auth. \
                        See the configuration file help."
                    ));
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }
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
    conf: Arc<Config>,
    base_url: String,
    chan_name: String,
    r: Arc<DirectionR>,
    w: Arc<DirectionW>,
    user_agent: String,
    key: Arc<Key>,
}

impl HttunClient {
    pub async fn connect(
        base_url: &str,
        chan_name: &str,
        test_mode: bool,
        user_agent: &str,
        conf: Arc<Config>,
    ) -> ah::Result<Self> {
        let Some(chan) = conf.channel_with_url(base_url, chan_name) else {
            return Err(err!(
                "Did not find a configuration for URL '{}' channel '{}'.",
                base_url,
                chan_name
            ));
        };
        let key = chan.shared_secret();

        Ok(Self {
            conf: Arc::clone(&conf),
            base_url: base_url.to_string(),
            chan_name: chan_name.to_string(),
            r: Arc::new(DirectionR::new(
                Arc::clone(&conf),
                base_url,
                chan_name,
                test_mode,
            )),
            w: Arc::new(DirectionW::new(
                Arc::clone(&conf),
                base_url,
                chan_name,
                test_mode,
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
        let (session_id, session_secret) = get_session(
            &self.conf,
            &self.base_url,
            &self.chan_name,
            &self.user_agent,
            &self.key,
        )
        .await?;
        log::debug!("Got session ID: {session_id}");

        let r_task = task::spawn({
            let r = Arc::clone(&self.r);
            let user_agent = self.user_agent.clone();
            let key = Arc::clone(&self.key);
            async move {
                direction_r(r, from_httun, &user_agent, &key, session_id, session_secret).await
            }
        });

        let w_task = task::spawn({
            let w = Arc::clone(&self.w);
            let user_agent = self.user_agent.clone();
            let key = Arc::clone(&self.key);
            async move { direction_w(w, to_httun, &user_agent, &key, session_id, session_secret).await }
        });

        tokio::select! {
            ret = r_task => ret.context("httun HTTP-r")?,
            ret = w_task => ret.context("httun HTTP-w")?,
        }
    }
}

// vim: ts=4 sw=4 expandtab
