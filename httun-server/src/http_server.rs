// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

//! Very simple HTTP server
//!
//! This HTTP server only implements what's necessary to run a httun tunnel.

use crate::comm_backend::CommRxMsg;
use anyhow::{self as ah, Context as _, format_err as err};
use atoi::atoi;
use base64::prelude::*;
use httun_conf::{Config, HttpAuth};
use httun_protocol::Message;
use httun_util::{
    ChannelId,
    errors::DisconnectedError,
    header::HttpHeader,
    net::tcp_send_all,
    query::Query,
    strings::{Direction, parse_path, split_delim},
    timeouts::HTTP_CHANNEL_PIN_TIMEOUT,
};
use memchr::memmem::find;
use std::{
    io::Write as _,
    net::SocketAddr,
    sync::{
        Arc, OnceLock as StdOnceLock,
        atomic::{self, AtomicU32},
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
    task::{self, JoinHandle},
    time::timeout,
};

/// Maximum buffer size for receiving HTTP packets.
const BUF_SIZE: usize = 1024 * (64 + 8);
/// Next connection ID.
static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(0);

/// Receive buffer for HTTP packets.
#[derive(Debug)]
struct RecvBuf {
    /// Received buffer.
    buf: Vec<u8>,
    /// Number of bytes received.
    count: usize,
    /// Length of HTTP header section.
    hdr_len: usize,
    /// Length of HTTP content/body section.
    cont_len: usize,
}

impl RecvBuf {
    /// Get the full length of the HTTP packet (headers + body).
    pub fn full_len(&self) -> ah::Result<usize> {
        self.hdr_len
            .checked_add(self.cont_len)
            .ok_or_else(|| err!("HTTP packet length calculation overflow"))
    }

    /// Interpret the content-length header and set `cont_len`.
    pub fn extract_content_length(&mut self) -> ah::Result<()> {
        debug_assert!(self.hdr_len > 0);
        match find_hdr(&self.buf[..self.hdr_len], b"content-length") {
            Some(len) => {
                let Some(len) = atoi::<usize>(len.trim_ascii()) else {
                    return Err(err!("content-length header number decode error."));
                };
                self.cont_len = len;
            }
            None => {
                self.cont_len = 0;
            }
        };
        Ok(())
    }
}

/// Receive HTTP headers.
async fn recv_headers(stream: &TcpStream) -> ah::Result<RecvBuf> {
    let mut buf = RecvBuf {
        buf: vec![0_u8; BUF_SIZE],
        count: 0,
        hdr_len: 0,
        cont_len: 0,
    };
    loop {
        stream.readable().await?;
        match stream.try_read(&mut buf.buf[buf.count..]) {
            Ok(n) => {
                if n == 0 {
                    return Err(DisconnectedError.into());
                }
                buf.count = buf.count.saturating_add(n);
                debug_assert!(buf.count <= buf.buf.len());

                // End of headers?
                if let Some(p) = find(&buf.buf[..buf.count], b"\r\n\r\n") {
                    buf.hdr_len = p.saturating_add(4);
                    buf.extract_content_length()?;
                    return Ok(buf);
                }

                if buf.count >= buf.buf.len() {
                    return Err(err!(
                        "Received HTTP packet is too large. (>={})",
                        buf.buf.len()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

/// Receive the rest of the HTTP packet, after headers have been received.
async fn recv_rest(stream: &TcpStream, mut buf: RecvBuf) -> ah::Result<RecvBuf> {
    let full_len = buf.full_len()?;
    if full_len > buf.buf.len() {
        return Err(err!(
            "Received HTTP packet is too large. (>{})",
            buf.buf.len()
        ));
    }
    if buf.count < full_len {
        loop {
            stream.readable().await?;
            match stream.try_read(&mut buf.buf[buf.count..full_len]) {
                Ok(n) => {
                    if n == 0 {
                        return Err(DisconnectedError.into());
                    }
                    buf.count = buf.count.saturating_add(n);
                    debug_assert!(buf.count <= full_len);
                    if buf.count >= full_len {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
    buf.buf.truncate(full_len);
    Ok(buf)
}

/// Receive a full HTTP packet, including headers and body.
async fn recv_http(stream: &TcpStream) -> ah::Result<RecvBuf> {
    recv_rest(stream, recv_headers(stream).await?).await
}

/// Send an HTTP reply.
///
/// `stream` is the TCP stream to send the reply on.
/// `payload` is the body of the HTTP reply.
/// `extra_headers` are additional headers to include in the reply.
/// `mime` is the MIME type of the payload (e.g., "application/octet-stream").
/// `status` is the HTTP status line (e.g., "200 Ok").
async fn send_http_reply(
    stream: &TcpStream,
    payload: &[u8],
    extra_headers: &[HttpHeader],
    status: &str,
    mime: &str,
) -> ah::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    write!(&mut buf, "HTTP/1.1 {status}\r\n")?;
    write!(&mut buf, "cache-control: no-store\r\n")?;
    for hdr in extra_headers {
        buf.extend_from_slice(hdr.name());
        write!(&mut buf, ": ")?;
        buf.extend_from_slice(hdr.value());
        write!(&mut buf, "\r\n")?;
    }
    if !payload.is_empty() {
        write!(&mut buf, "content-length: {}\r\n", payload.len())?;
        write!(&mut buf, "content-type: {mime}\r\n")?;
    }
    write!(&mut buf, "\r\n")?;

    buf.extend_from_slice(payload);

    tcp_send_all(stream, &buf).await
}

/// Send an HTTP 200 OK reply.
///
/// `stream` is the TCP stream to send the reply on.
/// `payload` is the body of the HTTP reply.
/// `extra_headers` are additional headers to include in the reply.
async fn send_http_reply_ok(
    stream: &TcpStream,
    payload: &[u8],
    extra_headers: &[HttpHeader],
) -> ah::Result<()> {
    let status = "200 Ok";
    let mime = "application/octet-stream";
    send_http_reply(stream, payload, extra_headers, status, mime).await
}

/// Send an HTTP 408 Request Timeout reply.
///
/// `stream` is the TCP stream to send the reply on.
/// `extra_headers` are additional headers to include in the reply.
async fn send_http_reply_timeout(
    stream: &TcpStream,
    extra_headers: &[HttpHeader],
) -> ah::Result<()> {
    let status = "408 Request Timeout";
    let mime = "text/plain";
    let mut extra_headers = extra_headers.to_vec();
    extra_headers.push(HttpHeader::new(b"connection", b"close"));
    send_http_reply(stream, status.as_bytes(), &extra_headers, status, mime).await
}

/// Send an HTTP 400 Bad Request reply.
///
/// `stream` is the TCP stream to send the reply on.
/// `extra_headers` are additional headers to include in the reply.
async fn send_http_reply_badrequest(
    stream: &TcpStream,
    extra_headers: &[HttpHeader],
) -> ah::Result<()> {
    let status = "400 Bad Request";
    let mime = "text/plain";
    let mut extra_headers = extra_headers.to_vec();
    extra_headers.push(HttpHeader::new(b"connection", b"close"));
    send_http_reply(stream, status.as_bytes(), &extra_headers, status, mime).await
}

/// Get the next HTTP header line from the buffer.
///
/// Returns the header line and the remaining buffer as a tuple.
fn next_hdr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    split_delim(buf, b'\n').map(|(l, r)| {
        if !l.is_empty() && l[l.len() - 1] == b'\r' {
            (&l[..l.len() - 1], r)
        } else {
            (l, r)
        }
    })
}

/// Find a specific HTTP header in the buffer.
///
/// `buf` is the buffer containing HTTP headers.
/// `name` is the name of the header to find.
///
/// Returns the value of the header if found.
fn find_hdr<'a>(buf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut tail = buf;
    while let Some((h, t)) = next_hdr(tail) {
        tail = t;
        if let Some((n, v)) = split_hdr(h)
            && n.eq_ignore_ascii_case(name)
        {
            return Some(v);
        }
    }
    None
}

/// Split an HTTP header line into name and value.
///
/// `h` is the header line.
///
/// Returns the name and value as a tuple.
fn split_hdr(h: &[u8]) -> Option<(&[u8], &[u8])> {
    split_delim(h, b':').map(|(n, v)| (n.trim_ascii(), v))
}

/// Http request method.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpRequest {
    /// HTTP GET method.
    Get,
    /// HTTP POST method.
    Post,
}

/// Parse the HTTP request header line (first line, e.g., "GET /chan_id/r?m=... HTTP/1.1").
///
/// `line` is the HTTP request header line.
///
/// Returns the parts of the request as a tuple.
fn parse_request_header(line: &[u8]) -> ah::Result<(HttpRequest, ChannelId, Direction, Query)> {
    let Some((request, tail)) = split_delim(line, b' ') else {
        return Err(err!("No GET/POST request found."));
    };
    let Some((path_info, _tail)) = split_delim(tail, b' ') else {
        return Err(err!("Did not receive path info."));
    };

    let request = match request {
        b"GET" => HttpRequest::Get,
        b"POST" => HttpRequest::Post,
        _ => {
            return Err(err!("Received neither GET nor POST."));
        }
    };

    let (path, query) = split_delim(path_info, b'?').unwrap_or_else(|| (path_info, b"".as_slice()));

    let (chan_id, direction) = parse_path(path)?;

    let query: Result<Query, _> = query.try_into();
    let query = query.context("Parse query string")?;

    Ok((request, chan_id, direction, query))
}

/// Decode the HTTP Basic Authorization header.
///
/// `value` is the value of the Authorization header.
///
/// Returns the decoded HttpAuth if successful.
fn decode_auth_header(value: &[u8]) -> Option<HttpAuth> {
    let (mode, encoded) = split_delim(value.trim_ascii_start(), b' ')?;
    if !mode.trim_ascii().eq_ignore_ascii_case(b"Basic") {
        return None;
    }
    let cred = BASE64_STANDARD.decode(encoded.trim_ascii()).ok()?;
    let (user, password) = split_delim(&cred, b':')?;
    let user = String::from_utf8(user.to_vec()).ok()?;
    let password = String::from_utf8(password.to_vec()).ok()?;
    let password = if password.is_empty() {
        None
    } else {
        Some(password)
    };
    Some(HttpAuth::new(user, password))
}

/// HTTP request received from the client.
#[derive(Clone, Debug)]
pub struct HttunHttpReq {
    /// HTTP request method.
    request: HttpRequest,
    /// Httun channel ID.
    chan_id: ChannelId,
    /// Httun direction (R/W).
    direction: Direction,
    /// HTTP query parameters.
    query: Query,
    /// HTTP Basic Authorization (if any).
    authorization: Option<HttpAuth>,
    /// HTTP body.
    body: Vec<u8>,
}

impl HttunHttpReq {
    /// Extract the body from the query parameters if necessary.
    pub fn extract_body(&mut self) {
        // In case of a GET request, the httun client puts
        // the body into a b64 encoded query named 'm'.
        if self.request == HttpRequest::Get
            && let Some(qmsg) = self.query.get(b"m")
            && let Ok(qmsg) = Message::decode_b64u(qmsg)
        {
            self.body = qmsg;
        }
    }

    /// Parse an HTTP request from the given buffer.
    ///
    /// `id` is the connection ID.
    /// `buf` is the buffer containing the HTTP request.
    ///
    /// Returns the parsed HTTP request.
    pub async fn parse(id: u32, buf: &[u8]) -> ah::Result<HttunHttpReq> {
        let mut authorization = None;

        // Parse the request header.
        let Some((h, mut tail)) = next_hdr(buf) else {
            return Err(err!("No GET/POST header found"));
        };
        let (request, chan_id, direction, query) = parse_request_header(h)?;

        log::trace!("Conn {id}: {request:?} / id={chan_id} / {direction:?} / {query:?}");

        // Go through all headers.
        let body = loop {
            let Some((h, t)) = next_hdr(tail) else {
                return Err(err!("Header end not found"));
            };
            tail = t;
            if h.is_empty() {
                // The remaining data is the body.
                break tail;
            }

            // Parse authorization header:
            if let Some((n, v)) = split_hdr(h)
                && n.eq_ignore_ascii_case(b"authorization")
            {
                authorization = decode_auth_header(v);
            }
        };

        let mut req = HttunHttpReq {
            request,
            chan_id,
            direction,
            query,
            authorization,
            body: body.to_vec(),
        };
        req.extract_body();

        Ok(req)
    }
}

/// Task to receive HTTP requests from the client.
///
/// `conn` is the HTTP connection state.
/// `rx_r_sender` is the sender for R direction requests.
/// `rx_w_sender` is the sender for W direction requests.
async fn rx_task(
    conn: &Arc<HttpConn>,
    rx_r_sender: &mpsc::Sender<HttunHttpReq>,
    rx_w_sender: &mpsc::Sender<HttunHttpReq>,
) -> ah::Result<()> {
    loop {
        let buf = match recv_http(&conn.stream).await.context("HTTP recv") {
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                conn.set_error(HttpError::PeerDisconnected);
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(b) => b,
        };

        let req = match HttunHttpReq::parse(conn.id, &buf.buf).await {
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                conn.set_error(HttpError::PeerDisconnected);
                return Ok(());
            }
            Err(e) => {
                conn.set_error(HttpError::ProtocolError);
                return Err(e);
            }
            Ok(r) => r,
        };

        if let Err(e) = conn.pin_channel(&req) {
            conn.set_error(HttpError::ProtocolError);
            return Err(e);
        }

        match req.direction {
            Direction::R => rx_r_sender.send(req).await?,
            Direction::W => rx_w_sender.send(req).await?,
        }
    }
}

/// Httun HTTP error state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HttpError {
    /// No error occurred.
    NoError = 0,
    /// Peer disconnected.
    PeerDisconnected,
    /// Protocol error.
    ProtocolError,
    /// The server rx task has been aborted.
    Abort,
}

impl From<HttpError> for u32 {
    /// Convert HttpError to u32.
    fn from(value: HttpError) -> Self {
        value as _
    }
}

impl TryFrom<u32> for HttpError {
    type Error = ah::Error;

    /// Convert u32 to HttpError.
    fn try_from(value: u32) -> ah::Result<Self> {
        const NO_ERROR: u32 = HttpError::NoError as _;
        const PEER_DISCONNECTED: u32 = HttpError::PeerDisconnected as _;
        const PROTOCOL_ERROR: u32 = HttpError::ProtocolError as _;
        const ABORT: u32 = HttpError::Abort as _;

        match value {
            NO_ERROR => Ok(HttpError::NoError),
            PEER_DISCONNECTED => Ok(HttpError::PeerDisconnected),
            PROTOCOL_ERROR => Ok(HttpError::ProtocolError),
            ABORT => Ok(HttpError::Abort),
            _ => Err(err!("Invalid HttpError value: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChanPinState {
    NoChannel,
    HaveChannelId,
    Aborted,
}

/// HTTP connection.
#[derive(Debug)]
pub struct HttpConn {
    /// Connection ID.
    id: u32,
    /// TCP stream.
    stream: Arc<TcpStream>,
    /// Connection error state.
    error: Arc<AtomicU32>,
    /// RX task handle.
    rx_task: StdOnceLock<JoinHandle<()>>,
    /// Receiver for R direction requests.
    rx_r: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    /// Receiver for W direction requests.
    rx_w: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    /// Pinned channel ID and auth. (None if not pinned yet).
    pinned_chan: StdOnceLock<(ChannelId, Option<HttpAuth>)>,
    /// Channel pinning state (receiver).
    pinned_state_rx: Mutex<watch::Receiver<ChanPinState>>,
    /// Channel pinning state (sender).
    pinned_state_tx: watch::Sender<ChanPinState>,
    /// Server configuration.
    conf: Arc<Config>,
    /// Extra HTTP headers to include in replies.
    extra_headers: Arc<[HttpHeader]>,
}

impl HttpConn {
    /// Wrap a new TCP stream into an HttpConn.
    ///
    /// `stream` is the TCP stream.
    /// `conf` is the server configuration.
    /// `extra_headers` are additional headers to include in replies.
    async fn new(
        stream: TcpStream,
        conf: Arc<Config>,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Arc<Self>> {
        stream.set_nodelay(true)?;
        stream.set_ttl(255)?;

        let id = NEXT_CONN_ID.fetch_add(1, atomic::Ordering::Relaxed);
        log::debug!("New connection: {id}");

        let (pinned_state_tx, pinned_state_rx) = watch::channel(ChanPinState::NoChannel);

        Ok(Arc::new(Self {
            id,
            stream: Arc::new(stream),
            error: Arc::new(AtomicU32::new(HttpError::NoError.into())),
            rx_task: StdOnceLock::new(),
            rx_r: Mutex::new(None),
            rx_w: Mutex::new(None),
            pinned_chan: StdOnceLock::new(),
            pinned_state_rx: Mutex::new(pinned_state_rx),
            pinned_state_tx,
            conf,
            extra_headers,
        }))
    }

    /// Spawn the RX task for this connection.
    pub async fn spawn_rx_task(self: &Arc<Self>) {
        let (rx_r_sender, rx_r_receiver) = mpsc::channel(2);
        let (rx_w_sender, rx_w_receiver) = mpsc::channel(4);

        let rx_task = task::spawn({
            let this = Arc::clone(self);
            async move {
                while this.get_error() == HttpError::NoError {
                    if let Err(e) = rx_task(&this, &rx_r_sender, &rx_w_sender).await {
                        log::info!("Connection {} receive: {e:?}", this.id);
                    }
                }
                // senders are dropped -> channels are closed.
            }
        });

        self.rx_task
            .set(rx_task)
            .expect("spawn_rx_task was called twice");
        *self.rx_r.lock().await = Some(rx_r_receiver);
        *self.rx_w.lock().await = Some(rx_w_receiver);
    }

    /// Get the pinned channel ID (if any).
    pub fn chan_id(&self) -> Option<ChannelId> {
        self.pinned_chan.get().map(|c| &c.0).cloned()
    }

    /// Set the current error code.
    fn set_error(&self, error: HttpError) {
        self.error.store(error.into(), atomic::Ordering::Relaxed);
        if let Err(e) = self.pinned_state_tx.send(ChanPinState::Aborted) {
            log::warn!("Failed to abort pin state: {e:?}");
        }
    }

    /// Get the current error code.
    fn get_error(&self) -> HttpError {
        self.error
            .load(atomic::Ordering::Relaxed)
            .try_into()
            .expect("Invalid HttpError code.")
    }

    /// Check HTTP Basic Authorization.
    ///
    /// `req` is the HTTP request.
    /// `conf_auth` is the configured HttpAuth for the channel.
    ///
    /// Returns Ok(()) if authorization is successful, Err otherwise.
    fn check_auth(&self, req: &HttunHttpReq, conf_auth: &Option<HttpAuth>) -> ah::Result<()> {
        if let Some(conf_auth) = conf_auth {
            if req.authorization.as_ref() != Some(conf_auth) {
                return Err(err!(
                    "HTTP basic authorization failed. Received wrong user/key."
                ));
            }
        } else if req.authorization.is_some() {
            log::warn!(
                "The client sent an HTTP authorization header, \
                but the server did not check it, \
                because http basic auth is not configured."
            );
        }
        Ok(())
    }

    /// Pin the connection to a specific channel.
    ///
    /// `req` is the HTTP request.
    ///
    /// Returns Ok(()) if pinning is successful, Err otherwise.
    fn pin_channel(&self, req: &HttunHttpReq) -> ah::Result<()> {
        if let Some(pinned_chan) = self.pinned_chan.get() {
            if pinned_chan.0 == req.chan_id {
                self.check_auth(req, &pinned_chan.1)?;
                return Ok(());
            } else {
                return Err(err!(
                    "Http connection is already pinned to a different channel."
                ));
            }
        }

        let chan = self
            .conf
            .channel_by_id(req.chan_id)
            .context("Get channel from configuration")?;
        self.check_auth(req, chan.http().basic_auth())?;

        let pinned_chan = self
            .pinned_chan
            .get_or_init(|| (req.chan_id, chan.http().basic_auth().clone()));

        self.pinned_state_tx
            .send(ChanPinState::HaveChannelId)
            .context("Notify channel ID pinning")?;

        if pinned_chan.0 != req.chan_id {
            Err(err!(
                "Http connection is already pinned to a different channel."
            ))
        } else {
            Ok(())
        }
    }

    /// Wait until the channel is pinned.
    pub async fn wait_pinned(&self) -> ah::Result<bool> {
        let mut pinned_state_rx = self.pinned_state_rx.lock().await;

        let state = timeout(
            HTTP_CHANNEL_PIN_TIMEOUT,
            pinned_state_rx.wait_for(|p| *p != ChanPinState::NoChannel),
        )
        .await
        .context("Timeout waiting for channel ID")?
        .context("Wait for channel ID")?;

        Ok(*state == ChanPinState::HaveChannelId)
    }

    /// Receive a message from the httun client.
    ///
    /// Returns the received message.
    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        let mut rx_r = self.rx_r.lock().await;
        let mut rx_w = self.rx_w.lock().await;
        let error;

        let ret = tokio::select! {
            req = rx_r.as_mut().context("RX thread not running")?.recv() => {
                error = self.get_error();
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    Ok(CommRxMsg::ReqFromSrv(req.body))
                } else {
                    Err(err!("RX channel closed"))
                }
            }
            req = rx_w.as_mut().context("RX thread not running")?.recv() => {
                error = self.get_error();
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    self.send_reply_ok(&[]).await.context("Send POST reply")?;
                    Ok(CommRxMsg::ToSrv(req.body))
                } else {
                    Err(err!("RX channel closed"))
                }
            }
        };

        match error {
            HttpError::NoError => ret,
            HttpError::PeerDisconnected => Err(DisconnectedError.into()),
            HttpError::ProtocolError => Err(err!("Fatal http protocol error")),
            HttpError::Abort => Err(err!("Http connection aborted")),
        }
    }

    /// Abort the RX task.
    fn abort_rx_task(&self) {
        self.set_error(HttpError::Abort);
        if let Some(rx_task) = self.rx_task.get() {
            rx_task.abort();
        }
    }

    /// Close the HTTP connection.
    pub async fn close(&self) -> ah::Result<()> {
        let mut rx_r = self.rx_r.lock().await;
        let mut rx_w = self.rx_w.lock().await;
        self.abort_rx_task();
        if let Some(rx_r) = rx_r.as_mut() {
            rx_r.close();
        }
        if let Some(rx_w) = rx_w.as_mut() {
            rx_w.close();
        }
        Ok(())
    }

    /// Send an HTTP 200 OK reply with the given payload.
    ///
    /// `payload` is the body of the HTTP reply.
    pub async fn send_reply_ok(&self, payload: &[u8]) -> ah::Result<()> {
        send_http_reply_ok(&self.stream, payload, &self.extra_headers).await
    }

    /// Send an HTTP 408 Request Timeout reply.
    pub async fn send_reply_timeout(&self) -> ah::Result<()> {
        send_http_reply_timeout(&self.stream, &self.extra_headers).await
    }

    /// Send an HTTP 400 Bad Request reply.
    pub async fn send_reply_badrequest(&self) -> ah::Result<()> {
        send_http_reply_badrequest(&self.stream, &self.extra_headers).await
    }
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        // Abort the RX task on drop.
        self.abort_rx_task();
    }
}

/// Simple HTTP server for use with httun.
#[derive(Debug)]
pub struct HttpServer {
    /// TCP listener.
    listener: TcpListener,
    /// Server configuration.
    conf: Arc<Config>,
    /// Extra HTTP headers to include in replies.
    extra_headers: Arc<[HttpHeader]>,
}

impl HttpServer {
    /// Create a new HTTP server.
    ///
    /// `addr` is the socket address to bind to.
    /// `conf` is the server configuration.
    /// `extra_headers` are additional headers to include in replies.
    pub async fn new(
        addr: SocketAddr,
        conf: Arc<Config>,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context("HTTP server listener")?;
        Ok(Self {
            listener,
            conf,
            extra_headers,
        })
    }

    /// Accept a new HTTP connection.
    ///
    /// Returns the accepted HttpConn.
    pub async fn accept(&self) -> ah::Result<Arc<HttpConn>> {
        let (stream, _addr) = self.listener.accept().await.context("HTTP accept")?;
        HttpConn::new(
            stream,
            Arc::clone(&self.conf),
            Arc::clone(&self.extra_headers),
        )
        .await
    }
}

// vim: ts=4 sw=4 expandtab
