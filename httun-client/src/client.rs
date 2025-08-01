// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::{Config, ConfigChannel};
use httun_protocol::{
    Key, Message, MsgType, Operation, SequenceGenerator, SequenceType, SequenceValidator,
    SessionSecret, secure_random,
};
use httun_util::consts::CHAN_R_TIMEOUT_S;
use reqwest::{Client, StatusCode};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    pin,
    sync::{Mutex, Notify, watch},
    task,
    time::sleep,
};

const COMM_DEQUE_SIZE_TO_HTTUN: usize = 1;
const COMM_DEQUE_SIZE_FROM_HTTUN: usize = 16;
const HTTP_R_TIMEOUT: Duration = Duration::from_secs(CHAN_R_TIMEOUT_S + 3);
const HTTP_W_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_INIT_RETRIES: usize = 5;

struct CommDeque<T, const SIZE: usize> {
    deque: Mutex<heapless::Deque<T, SIZE>>,
    notify: Notify,
    overflow: AtomicBool,
}

impl<T, const SIZE: usize> CommDeque<T, SIZE> {
    pub fn new() -> Self {
        Self {
            deque: Mutex::new(heapless::Deque::new()),
            notify: Notify::new(),
            overflow: AtomicBool::new(false),
        }
    }

    fn clear_notification(&self) {
        let notified = self.notify.notified();
        pin!(notified);
        notified.enable(); // consume the notification.
    }

    fn notify(&self) {
        self.notify.notify_one();
    }

    async fn wait_for_notify(&self) {
        self.notify.notified().await;
    }

    pub async fn clear(&self) {
        self.deque.lock().await.clear();
        self.clear_notification();
    }

    pub async fn put(&self, mut value: T) {
        loop {
            if let Err(v) = self.deque.lock().await.push_back(value) {
                value = v;
            } else {
                break;
            }
            if SIZE > 1 && !self.overflow.swap(true, Relaxed) {
                log::warn!("Httun communication queue overflow.");
            }
            self.wait_for_notify().await;
        }
        self.notify();
    }

    pub async fn get(&self) -> T {
        let value = loop {
            if let Some(value) = self.deque.lock().await.pop_front() {
                break value;
            }
            self.wait_for_notify().await;
        };
        self.notify();
        value
    }
}

pub struct HttunComm {
    from_httun: CommDeque<Message, COMM_DEQUE_SIZE_FROM_HTTUN>,
    to_httun: CommDeque<Message, COMM_DEQUE_SIZE_TO_HTTUN>,
    restart_watch: watch::Sender<bool>,
}

impl HttunComm {
    pub fn new() -> Self {
        let (restart_watch, _) = watch::channel(true);
        Self {
            from_httun: CommDeque::new(),
            to_httun: CommDeque::new(),
            restart_watch,
        }
    }

    async fn clear(&self) {
        self.from_httun.clear().await;
        self.to_httun.clear().await;
    }

    async fn send_from_httun(&self, msg: Message) {
        self.from_httun.put(msg).await;
    }

    pub async fn recv_from_httun(&self) -> Message {
        self.from_httun.get().await
    }

    pub async fn send_to_httun(&self, msg: Message) {
        self.to_httun.put(msg).await;
    }

    async fn recv_to_httun(&self) -> Message {
        self.to_httun.get().await
    }

    pub async fn request_restart(&self) {
        let _ = self.restart_watch.send(true);
        let _ = self.restart_watch.subscribe().wait_for(|r| !*r).await;
    }

    async fn wait_for_restart_request(&self) {
        let _ = self.restart_watch.subscribe().wait_for(|r| *r).await;
    }

    fn notify_restart_done(&self) {
        let _ = self.restart_watch.send(false);
    }
}

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
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        c = c.tcp_user_timeout(TCP_USER_TIMEOUT);
    }
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
            mode: HttunClientMode,
            serial: AtomicU64,
        }

        impl $struct {
            fn new(conf: Arc<Config>, base_url: &str, name: &str, mode: HttunClientMode) -> Self {
                Self {
                    conf,
                    name: name.to_string(),
                    base_url: base_url.to_string(),
                    url: format_url(base_url, name, $urlpath),
                    mode,
                    serial: AtomicU64::new(0),
                }
            }
        }
    };
}

define_direction!(DirectionR, "r");
define_direction!(DirectionW, "w");

async fn direction_r(
    chan: &DirectionR,
    ready: &Notify,
    comm: &HttunComm,
    user_agent: &str,
    key: &Key,
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

    ready.notify_one();
    loop {
        let oper = match chan.mode {
            HttunClientMode::L4 => Operation::L4FromSrv,
            HttunClientMode::L7 => Operation::L7FromSrv,
            HttunClientMode::Test => Operation::TestFromSrv,
        };
        let mut resp;

        'http: loop {
            let mut msg = Message::new(MsgType::Data, oper, vec![])?;
            msg.set_sequence(tx_sequence_c.next());
            let msg = msg.serialize_b64u(key, Some(session_secret));

            log::trace!("Requesting from HTTP-r");

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
            log::trace!("Received from HTTP-r");

            let msg = Message::deserialize(data, key, Some(session_secret))
                .context("Message deserialize")?;
            if msg.type_() != MsgType::Data {
                return Err(err!("Received invalid message type"));
            }
            if msg.oper() != oper {
                return Err(err!("Received invalid message operation"));
            }
            rx_validator_a
                .check_recv_seq(&msg)
                .context("rx sequence validation SequenceType::A")?;

            comm.send_from_httun(msg).await;
        }
    }
}

async fn direction_w(
    chan: &DirectionW,
    ready: &Notify,
    comm: &HttunComm,
    user_agent: &str,
    key: &Key,
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

    ready.notify_one();
    loop {
        let mut msg = comm.recv_to_httun().await;
        msg.set_sequence(tx_sequence_b.next());

        let msg = msg.serialize(key, Some(session_secret));

        log::trace!("Send to HTTP-w");

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
) -> ah::Result<SessionSecret> {
    let chan_conf = conf
        .channel_with_url(base_url, chan_name)
        .expect("Chan conf");

    let client = make_client(user_agent, Duration::from_secs(5), chan_conf)
        .context("httun session build HTTP client")?;

    let http_auth = chan_conf.http_basic_auth().clone();

    for i in 0..SESSION_INIT_RETRIES {
        let last_try = i == SESSION_INIT_RETRIES - 1;

        let msg = Message::new(MsgType::Init, Operation::Init, vec![])?;
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
        if msg.oper() != Operation::Init {
            return Err(err!("Received invalid message operation"));
        }
        let Ok(session_secret) = msg.into_payload().try_into() else {
            return Err(err!("Received invalid session secret"));
        };

        return Ok(session_secret);
    }

    Err(err!("Failed to get session ID from server."))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttunClientMode {
    L4,
    L7,
    Test,
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
        mode: HttunClientMode,
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
                mode,
            )),
            w: Arc::new(DirectionW::new(
                Arc::clone(&conf),
                base_url,
                chan_name,
                mode,
            )),
            user_agent: user_agent.to_string(),
            key: Arc::new(key),
        })
    }

    pub async fn handle_packets(&mut self, comm: Arc<HttunComm>) -> ah::Result<()> {
        // Initially wait for the user side to start us.
        comm.wait_for_restart_request().await;

        loop {
            let session_secret = get_session(
                &self.conf,
                &self.base_url,
                &self.chan_name,
                &self.user_agent,
                &self.key,
            )
            .await?;
            log::debug!("Initialized new session.");

            comm.clear().await;

            let r_task_ready = Arc::new(Notify::new());
            let w_task_ready = Arc::new(Notify::new());

            let mut r_task = task::spawn({
                let r = Arc::clone(&self.r);
                let ready = Arc::clone(&r_task_ready);
                let comm = Arc::clone(&comm);
                let user_agent = self.user_agent.clone();
                let key = Arc::clone(&self.key);
                async move {
                    let res =
                        direction_r(&r, &ready, &comm, &user_agent, &key, session_secret).await;
                    ready.notify_one();
                    res
                }
            });

            let mut w_task = task::spawn({
                let w = Arc::clone(&self.w);
                let ready = Arc::clone(&w_task_ready);
                let comm = Arc::clone(&comm);
                let user_agent = self.user_agent.clone();
                let key = Arc::clone(&self.key);
                async move {
                    let res =
                        direction_w(&w, &ready, &comm, &user_agent, &key, session_secret).await;
                    ready.notify_one();
                    res
                }
            });

            r_task_ready.notified().await;
            w_task_ready.notified().await;
            comm.notify_restart_done();

            tokio::select! {
                biased;
                _ = comm.wait_for_restart_request() => (),
                ret = &mut r_task => {
                    w_task.abort();
                    let _ = w_task.await;
                    ret.context("httun HTTP-r")??;
                    unreachable!(); // Task never returns Ok.
                }
                ret = &mut w_task => {
                    r_task.abort();
                    let _ = r_task.await;
                    ret.context("httun HTTP-w")??;
                    unreachable!(); // Task never returns Ok.
                }
            }

            log::trace!("Client restart was requested.");
            r_task.abort();
            w_task.abort();
            let _ = r_task.await;
            let _ = w_task.await;
        }
    }
}

// vim: ts=4 sw=4 expandtab
