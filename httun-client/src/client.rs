// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::{
    async_task_comm::AsyncTaskComm,
    resolver::{ResConf, ResMode, resolve},
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::{Config, ConfigChannel};
use httun_protocol::{
    Key, Message, MsgType, Operation, SequenceGenerator, SequenceType, SequenceValidator,
    SessionSecret, secure_random,
};
use httun_util::{
    header::HttpHeader,
    timeouts::{HTTP_R_TIMEOUT, HTTP_W_TIMEOUT},
};
use reqwest::{
    Client, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{sync::Notify, task, time::sleep};
use url::{Host, Url};

/// Number of retries for HTTP read/write operations.
const HTTP_RW_TRIES: usize = 3;
/// Number of retries for session initialization.
const SESSION_INIT_TRIES: usize = 5;

/// Creates a new `reqwest::Client` instance for HTTP communication with common settings.
fn make_client(
    user_agent: &str,
    extra_headers: &[HttpHeader],
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
        c = c.tcp_user_timeout(httun_util::timeouts::HTTP_TCP_USER_TIMEOUT);
    }
    c = c.tcp_nodelay(true);

    c = c.gzip(chan_conf.http().allow_compression());
    c = c.deflate(chan_conf.http().allow_compression());
    c = c.brotli(chan_conf.http().allow_compression());
    c = c.zstd(chan_conf.http().allow_compression());

    c = c.hickory_dns(true);

    // Allow proxies (or any other MiM) to manipulate the TLS connection.
    c = c.danger_accept_invalid_hostnames(chan_conf.http().ignore_tls_errors());
    c = c.danger_accept_invalid_certs(chan_conf.http().ignore_tls_errors());

    let mut header_map = HeaderMap::new();
    header_map.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    for hdr in extra_headers
        .iter()
        .chain(chan_conf.http().extra_headers().iter())
    {
        let name = HeaderName::from_bytes(hdr.name()).context("Convert headers name")?;
        if hdr.value().is_empty() {
            header_map.remove(name);
        } else {
            let value = HeaderValue::from_bytes(hdr.value()).context("Convert headers value")?;
            header_map.insert(name, value);
        }
    }
    c = c.default_headers(header_map);

    Ok(c.build()?)
}

/// Append the serial to the URL.
fn format_url_serial(url: &str, serial: u64) -> String {
    let url = url.trim_end_matches('/');
    format!("{}/{:010X}", url, serial & 0x000000FF_FFFFFFFF)
}

/// Format the URL for a channel and direction.
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
            chan_conf: ConfigChannel,
            url: String,
            #[allow(dead_code)]
            mode: HttunClientMode,
            user_agent: Arc<String>,
            extra_headers: Arc<[HttpHeader]>,
            key: Arc<Key>,
            serial: AtomicU64,
        }

        impl $struct {
            fn new(
                conf: Arc<Config>,
                chan_conf: ConfigChannel,
                base_url: &str,
                mode: HttunClientMode,
                user_agent: Arc<String>,
                extra_headers: Arc<[HttpHeader]>,
                key: Arc<Key>,
            ) -> Self {
                let url = format_url(base_url, chan_conf.name(), $urlpath);
                Self {
                    conf,
                    chan_conf,
                    url,
                    mode,
                    user_agent,
                    extra_headers,
                    key,
                    serial: AtomicU64::new(0),
                }
            }
        }
    };
}

define_direction!(DirectionR, "r");
define_direction!(DirectionW, "w");

impl DirectionR {
    /// Run the channel read direction ("/r/").
    async fn run(
        &self,
        ready: &Notify,
        comm: &AsyncTaskComm,
        session_secret: SessionSecret,
    ) -> ah::Result<()> {
        self.serial
            .store(u64::from_ne_bytes(secure_random()), Relaxed);

        let tx_sequence_c = SequenceGenerator::new(SequenceType::C);
        let window_length = self.conf.parameters().receive().window_length();
        let mut rx_validator_a = SequenceValidator::new(SequenceType::A, window_length);

        let client = make_client(
            &self.user_agent,
            &self.extra_headers,
            HTTP_R_TIMEOUT,
            &self.chan_conf,
        )
        .context("httun HTTP-r build HTTP client")?;

        let http_auth = self.chan_conf.http().basic_auth().clone();

        ready.notify_one();
        loop {
            let oper = match self.mode {
                HttunClientMode::L3 => Operation::L3FromSrv,
                HttunClientMode::L7 => Operation::L7FromSrv,
                HttunClientMode::Test => Operation::TestFromSrv,
            };
            let mut resp;

            let mut tries = 0;
            'http: loop {
                if tries >= HTTP_RW_TRIES {
                    return Err(err!("httun HTTP-r: Maximum number of retries exceeded."));
                }
                tries += 1;

                let mut msg = Message::new(MsgType::Data, oper, vec![])?;
                msg.set_sequence(tx_sequence_c.next());
                let msg = msg
                    .serialize_b64u(&self.key, Some(session_secret))
                    .context("httun HTTP-r message serialize")?;

                log::trace!("Requesting from HTTP-r");

                let url = format_url_serial(&self.url, self.serial.fetch_add(1, Relaxed));
                let mut req = client.get(&url).query(&[("m", &msg)]);
                if let Some(http_auth) = &http_auth {
                    req = req.basic_auth(http_auth.user(), http_auth.password());
                }
                resp = req.send().await.context("httun HTTP-r send")?;

                match resp.status() {
                    StatusCode::OK => {
                        break 'http;
                    }
                    StatusCode::REQUEST_TIMEOUT => {
                        // This is normal behavior, if the inferface is idle.
                        tries = 0;
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

                let msg = Message::deserialize(data, &self.key, Some(session_secret))
                    .context("httun HTTP-r message deserialize")?;
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
}

impl DirectionW {
    /// Run the channel write direction ("/w/").
    async fn run(
        &self,
        ready: &Notify,
        comm: &AsyncTaskComm,
        session_secret: SessionSecret,
    ) -> ah::Result<()> {
        self.serial
            .store(u64::from_ne_bytes(secure_random()), Relaxed);

        let tx_sequence_b = SequenceGenerator::new(SequenceType::B);

        let client = make_client(
            &self.user_agent,
            &self.extra_headers,
            HTTP_W_TIMEOUT,
            &self.chan_conf,
        )
        .context("httun HTTP-w build HTTP client")?;

        let http_auth = self.chan_conf.http().basic_auth().clone();

        ready.notify_one();
        loop {
            let mut msg = comm.recv_to_httun().await;
            msg.set_sequence(tx_sequence_b.next());

            let msg = msg
                .serialize(&self.key, Some(session_secret))
                .context("httun HTTP-w message serialize")?;

            log::trace!("Send to HTTP-w");

            let mut tries = 0;
            'http: loop {
                if tries >= HTTP_RW_TRIES {
                    return Err(err!("httun HTTP-w: Maximum number of retries exceeded."));
                }
                tries += 1;

                let url = format_url_serial(&self.url, self.serial.fetch_add(1, Relaxed));
                let mut req = client
                    .post(&url)
                    .header("content-type", "application/octet-stream")
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
}

/// Initialize a new httun session.
async fn get_session(
    chan_conf: &ConfigChannel,
    base_url: &str,
    user_agent: &str,
    extra_headers: &[HttpHeader],
    key: &Key,
) -> ah::Result<SessionSecret> {
    let client = make_client(user_agent, extra_headers, Duration::from_secs(5), chan_conf)
        .context("httun session build HTTP client")?;

    let http_auth = chan_conf.http().basic_auth().clone();

    for i in 0..SESSION_INIT_TRIES {
        let last_try = i == SESSION_INIT_TRIES - 1;

        let msg = Message::new(MsgType::Init, Operation::Init, vec![])?;
        let msg = msg
            .serialize_b64u(key, None)
            .context("httun session message serialize")?;

        let url = format_url_serial(
            &format_url(base_url, chan_conf.name(), "r"),
            u64::from_ne_bytes(secure_random()),
        );
        let mut req = client.get(&url).query(&[("m", &msg)]);
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

/// The httun client operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttunClientMode {
    L3,
    L7,
    Test,
}

/// The httun client.
///
/// This struct manages the client-side of an httun tunnel. It handles session
/// establishment, and the read/write directions of the tunnel.
pub struct HttunClient {
    base_url: String,
    chan_conf: ConfigChannel,
    r: Arc<DirectionR>,
    w: Arc<DirectionW>,
    user_agent: Arc<String>,
    extra_headers: Arc<[HttpHeader]>,
    key: Arc<Key>,
}

impl HttunClient {
    /// Connect to a httun server.
    pub async fn connect(
        base_url: &str,
        res_mode: ResMode,
        chan_name: &str,
        mode: HttunClientMode,
        user_agent: &str,
        extra_headers: Arc<[HttpHeader]>,
        conf: Arc<Config>,
    ) -> ah::Result<Self> {
        let Some(chan_conf) = conf.channel_with_url(base_url, chan_name) else {
            return Err(err!(
                "Did not find a configuration for URL '{base_url}' channel '{chan_name}'.",
            ));
        };

        // Try to resolve the server-url domain name (if any) into an IP address.
        let mut base_url = Url::parse(base_url).context("Parse server URL")?;
        if let Some(Host::Domain(domain)) = base_url.host() {
            // Resolve the domain with the given settings.
            let server_ip = resolve(
                domain,
                &ResConf {
                    mode: res_mode,
                    ..Default::default()
                },
            )
            .await
            .context("Resolve server URL domain")?;

            // Replace the host part of the URL.
            if let Err(e) = base_url.set_ip_host(server_ip) {
                return Err(err!(
                    "Replace server-url domain with IP address failed: {e:?}"
                ));
            }
        }

        let user_agent = Arc::new(user_agent.to_string());
        let key = Arc::new(*chan_conf.shared_secret());

        Ok(Self {
            base_url: base_url.to_string(),
            chan_conf: chan_conf.clone(),
            r: Arc::new(DirectionR::new(
                Arc::clone(&conf),
                chan_conf.clone(),
                base_url.as_str(),
                mode,
                Arc::clone(&user_agent),
                Arc::clone(&extra_headers),
                Arc::clone(&key),
            )),
            w: Arc::new(DirectionW::new(
                Arc::clone(&conf),
                chan_conf.clone(),
                base_url.as_str(),
                mode,
                Arc::clone(&user_agent),
                Arc::clone(&extra_headers),
                Arc::clone(&key),
            )),
            user_agent: Arc::clone(&user_agent),
            extra_headers: Arc::clone(&extra_headers),
            key: Arc::clone(&key),
        })
    }

    /// This function runs the main loop of the client, handling packet transmission and reception.
    pub async fn handle_packets(&mut self, comm: Arc<AsyncTaskComm>) -> ah::Result<()> {
        // Initially wait for the user side to start us.
        comm.wait_for_restart_request().await;

        // Main loop.
        loop {
            // Initialize a new session.
            let session_secret = get_session(
                &self.chan_conf,
                &self.base_url,
                &self.user_agent,
                &self.extra_headers,
                &self.key,
            )
            .await?;
            log::debug!("Initialized new session.");

            comm.clear().await;

            let r_task_ready = Arc::new(Notify::new());
            let w_task_ready = Arc::new(Notify::new());

            // Spawn the read task ("/r/").
            let mut r_task = task::spawn({
                let r = Arc::clone(&self.r);
                let ready = Arc::clone(&r_task_ready);
                let comm = Arc::clone(&comm);
                async move {
                    let res = r.run(&ready, &comm, session_secret).await;
                    ready.notify_one();
                    res
                }
            });

            // Spawn the write task ("/w/").
            let mut w_task = task::spawn({
                let w = Arc::clone(&self.w);
                let ready = Arc::clone(&w_task_ready);
                let comm = Arc::clone(&comm);
                async move {
                    let res = w.run(&ready, &comm, session_secret).await;
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
                    comm.set_restart_request();
                    ret.context("httun HTTP-r")??;
                    unreachable!(); // Task never returns Ok.
                }
                ret = &mut w_task => {
                    r_task.abort();
                    let _ = r_task.await;
                    comm.set_restart_request();
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
