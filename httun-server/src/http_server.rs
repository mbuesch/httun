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
    errors::DisconnectedError,
    net::tcp_send_all,
    query::Query,
    strings::{Direction, parse_path},
};
use memchr::{memchr, memmem::find};
use std::{
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        Arc, OnceLock as StdOnceLock,
        atomic::{self, AtomicBool, AtomicU32},
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    task::{self, JoinHandle},
};

const BUF_SIZE: usize = 1024 * (64 + 8);
static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
struct RecvBuf {
    buf: Vec<u8>,
    count: usize,
    hdr_len: usize,
    cont_len: usize,
}

impl RecvBuf {
    pub fn full_len(&self) -> ah::Result<usize> {
        self.hdr_len
            .checked_add(self.cont_len)
            .ok_or_else(|| err!("HTTP packet length calculation overflow"))
    }
}

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
                    buf.hdr_len = p + 4;
                    buf.cont_len = match find_hdr(&buf.buf[..buf.hdr_len], b"Content-Length") {
                        Some(cont_len) => {
                            let Some(cont_len) = atoi::<usize>(cont_len.trim_ascii()) else {
                                return Err(err!("Content-Length header number decode error."));
                            };
                            cont_len
                        }
                        None => 0,
                    };
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

async fn recv_http(stream: &TcpStream) -> ah::Result<RecvBuf> {
    recv_rest(stream, recv_headers(stream).await?).await
}

async fn send_http_reply(
    stream: &TcpStream,
    payload: &[u8],
    extra_headers: &[(&str, &str)],
    status: &str,
    mime: &str,
) -> ah::Result<()> {
    let mut headers = String::with_capacity(BUF_SIZE);
    write!(&mut headers, "HTTP/1.1 {status}\r\n")?;
    write!(&mut headers, "Cache-Control: no-store\r\n")?;
    for (name, value) in extra_headers {
        write!(&mut headers, "{name}: {value}\r\n")?;
    }
    if !payload.is_empty() {
        write!(&mut headers, "Content-Length: {}\r\n", payload.len())?;
        write!(&mut headers, "Content-Type: {mime}\r\n")?;
    }
    write!(&mut headers, "\r\n")?;

    let mut buf = headers.into_bytes();
    buf.extend_from_slice(payload);

    tcp_send_all(stream, &buf).await
}

async fn send_http_reply_ok(stream: &TcpStream, payload: &[u8]) -> ah::Result<()> {
    let status = "200 Ok";
    let mime = "application/octet-stream";
    send_http_reply(stream, payload, &[], status, mime).await
}

async fn send_http_reply_timeout(stream: &TcpStream) -> ah::Result<()> {
    let status = "408 Request Timeout";
    let mime = "text/plain";
    send_http_reply(
        stream,
        status.as_bytes(),
        &[("Connection", "close")],
        status,
        mime,
    )
    .await
}

async fn send_http_reply_badrequest(stream: &TcpStream) -> ah::Result<()> {
    let status = "400 Bad Request";
    let mime = "text/plain";
    send_http_reply(
        stream,
        status.as_bytes(),
        &[("Connection", "close")],
        status,
        mime,
    )
    .await
}

fn next_hdr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    split_delim(buf, b'\n').map(|(l, r)| {
        if !l.is_empty() && l[l.len() - 1] == b'\r' {
            (&l[..l.len() - 1], r)
        } else {
            (l, r)
        }
    })
}

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

fn split_hdr(h: &[u8]) -> Option<(&[u8], &[u8])> {
    split_delim(h, b':').map(|(n, v)| (n.trim_ascii(), v))
}

fn split_delim(buf: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    memchr(delim, buf).map(|pos| (&buf[..pos], &buf[pos + 1..]))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpRequest {
    Get,
    Post,
}

fn parse_request_header(line: &[u8]) -> ah::Result<(HttpRequest, String, Direction, Query)> {
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

    let (chan_name, direction) = parse_path(path)?;

    let query = String::from_utf8(query.to_vec())
        .context("Convert query to string")?
        .parse::<Query>()
        .context("Parse query string")?;

    Ok((request, chan_name, direction, query))
}

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

#[derive(Clone, Debug)]
pub struct HttunHttpReq {
    request: HttpRequest,
    chan_name: String,
    direction: Direction,
    query: Query,
    authorization: Option<HttpAuth>,
    body: Vec<u8>,
}

impl HttunHttpReq {
    pub fn extract_body(&mut self) {
        // In case of a GET request, the httun client puts
        // the body into a b64 encoded query named 'm'.
        if self.request == HttpRequest::Get
            && let Some(qmsg) = self.query.get("m")
            && let Ok(qmsg) = Message::decode_b64u(qmsg)
        {
            self.body = qmsg;
        }
    }

    pub async fn parse(id: u32, buf: &[u8]) -> ah::Result<HttunHttpReq> {
        let mut authorization = None;

        // Parse the request header.
        let Some((h, mut tail)) = next_hdr(buf) else {
            return Err(err!("No GET/POST header found"));
        };
        let (request, chan_name, direction, query) = parse_request_header(h)?;

        log::trace!("Conn {id}: {request:?} / {chan_name} / {direction:?} / {query:?}");

        // Go through all headers.
        let body = loop {
            let Some((h, t)) = next_hdr(tail) else {
                return Err(err!("Header end not found"));
            };
            tail = t;
            if h.is_empty() {
                break tail;
            }

            // Parse authorization header:
            if let Some((n, v)) = split_hdr(h)
                && n.eq_ignore_ascii_case(b"Authorization")
            {
                authorization = decode_auth_header(v);
            }
        }
        .to_vec();

        let mut req = HttunHttpReq {
            request,
            chan_name,
            direction,
            query,
            authorization,
            body,
        };
        req.extract_body();

        Ok(req)
    }
}

async fn rx_task(
    id: u32,
    stream: &TcpStream,
    rx_r_sender: &mpsc::Sender<HttunHttpReq>,
    rx_w_sender: &mpsc::Sender<HttunHttpReq>,
    closed: &AtomicBool,
) -> ah::Result<()> {
    loop {
        let buf = match recv_http(stream).await.context("HTTP recv") {
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                closed.store(true, atomic::Ordering::Relaxed);
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(b) => b,
        };

        let req = match HttunHttpReq::parse(id, &buf.buf).await {
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                closed.store(true, atomic::Ordering::Relaxed);
                return Ok(());
            }
            Err(e) => {
                let _ = send_http_reply_badrequest(stream).await;
                return Err(e);
            }
            Ok(r) => r,
        };

        match req.direction {
            Direction::R => rx_r_sender.send(req).await?,
            Direction::W => rx_w_sender.send(req).await?,
        }
    }
}

#[derive(Debug)]
pub struct HttpConn {
    id: u32,
    stream: Arc<TcpStream>,
    closed: Arc<AtomicBool>,
    rx_task: StdOnceLock<JoinHandle<()>>,
    rx_r: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    rx_w: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    pinned_chan: StdOnceLock<(String, Option<HttpAuth>)>,
    conf: Arc<Config>,
}

impl HttpConn {
    async fn new(stream: TcpStream, conf: Arc<Config>) -> ah::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_linger(None)?;
        stream.set_ttl(255)?;

        let id = NEXT_CONN_ID.fetch_add(1, atomic::Ordering::Relaxed);
        log::debug!("New connection: {id}");

        Ok(Self {
            id,
            stream: Arc::new(stream),
            closed: Arc::new(AtomicBool::new(false)),
            rx_task: StdOnceLock::new(),
            rx_r: Mutex::new(None),
            rx_w: Mutex::new(None),
            pinned_chan: StdOnceLock::new(),
            conf,
        })
    }

    pub async fn spawn_rx_task(&self) {
        let (rx_r_sender, rx_r_receiver) = mpsc::channel(2);
        let (rx_w_sender, rx_w_receiver) = mpsc::channel(4);

        let rx_task = task::spawn({
            let stream = Arc::clone(&self.stream);
            let closed = Arc::clone(&self.closed);
            let id = self.id;
            async move {
                while !closed.load(atomic::Ordering::Relaxed) {
                    if let Err(e) = rx_task(id, &stream, &rx_r_sender, &rx_w_sender, &closed).await
                    {
                        log::info!("Connection {id} receive: {e:?}");
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

    pub fn chan_name(&self) -> Option<String> {
        self.pinned_chan.get().map(|c| &c.0).cloned()
    }

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

    fn pin_channel(&self, req: &HttunHttpReq) -> ah::Result<()> {
        if let Some(pinned_chan) = self.pinned_chan.get() {
            if pinned_chan.0 == req.chan_name {
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
            .channel(&req.chan_name)
            .context("Get channel from configuration")?;
        self.check_auth(req, chan.http_basic_auth())?;

        let pinned_chan = self
            .pinned_chan
            .get_or_init(|| (req.chan_name.to_string(), chan.http_basic_auth().clone()));

        if pinned_chan.0 != req.chan_name {
            Err(err!(
                "Http connection is already pinned to a different channel."
            ))
        } else {
            Ok(())
        }
    }

    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        let mut rx_r = self.rx_r.lock().await;
        let mut rx_w = self.rx_w.lock().await;
        let closed;

        let ret = tokio::select! {
            req = rx_r.as_mut().context("RX thread not running")?.recv() => {
                closed = self.closed.load(atomic::Ordering::Relaxed);
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    self.pin_channel(&req)?;
                    Ok(CommRxMsg::ReqFromSrv(req.body))
                } else {
                    Err(err!("RX channel closed"))
                }
            }
            req = rx_w.as_mut().context("RX thread not running")?.recv() => {
                closed = self.closed.load(atomic::Ordering::Relaxed);
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    self.pin_channel(&req)?;
                    self.send_reply_ok(&[]).await.context("Send POST reply")?;
                    Ok(CommRxMsg::ToSrv(req.body))
                } else {
                    Err(err!("RX channel closed"))
                }
            }
        };

        if closed {
            return Err(DisconnectedError.into());
        }

        ret
    }

    fn abort_rx_task(&self) {
        self.closed.store(true, atomic::Ordering::Relaxed);
        if let Some(rx_task) = self.rx_task.get() {
            rx_task.abort();
        }
    }

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

    pub async fn send_reply_ok(&self, payload: &[u8]) -> ah::Result<()> {
        send_http_reply_ok(&self.stream, payload).await
    }

    pub async fn send_reply_timeout(&self) -> ah::Result<()> {
        send_http_reply_timeout(&self.stream).await
    }

    pub async fn send_reply_badrequest(&self) -> ah::Result<()> {
        send_http_reply_badrequest(&self.stream).await
    }
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        self.abort_rx_task();
    }
}

#[derive(Debug)]
pub struct HttpServer {
    listener: TcpListener,
    conf: Arc<Config>,
}

impl HttpServer {
    pub async fn new(addr: SocketAddr, conf: Arc<Config>) -> ah::Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context("HTTP server listener")?;
        Ok(Self { listener, conf })
    }

    pub async fn accept(&self) -> ah::Result<HttpConn> {
        let (stream, _addr) = self.listener.accept().await.context("HTTP accept")?;
        HttpConn::new(stream, Arc::clone(&self.conf)).await
    }
}

// vim: ts=4 sw=4 expandtab
