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
use httun_util::{DisconnectedError, Query};
use memchr::{memchr, memmem::find};
use std::{
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{self, AtomicBool, AtomicU32},
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    task::{self, JoinHandle},
};

const RX_BUF_SIZE: usize = 1024 * (64 + 8);
static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(0);

struct RecvBuf {
    buf: Vec<u8>,
    count: usize,
    hdr_len: usize,
    cont_len: usize,
}

async fn recv_headers(stream: &TcpStream) -> ah::Result<RecvBuf> {
    let mut buf = RecvBuf {
        buf: vec![0_u8; RX_BUF_SIZE],
        count: 0,
        hdr_len: 0,
        cont_len: 0,
    };
    loop {
        stream.readable().await?;
        match stream.try_read(&mut buf.buf[buf.count..RX_BUF_SIZE - buf.count]) {
            Ok(n) => {
                if n == 0 {
                    return Err(DisconnectedError.into());
                }
                buf.count = buf.count.saturating_add(n);
                if buf.count > buf.buf.len() {
                    return Err(err!("Received too many bytes. (>{})", buf.buf.len()));
                }
                if let Some(p) = find(&buf.buf[..buf.count], b"\r\n\r\n") {
                    buf.hdr_len = p + 4;
                    buf.cont_len = match find_hdr(&buf.buf[..buf.count], b"Content-Length") {
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
    let full_len = buf
        .hdr_len
        .checked_add(buf.cont_len)
        .ok_or_else(|| err!("HTTP packet length calculation overflow"))?;
    if full_len > buf.buf.len() {
        return Err(err!(
            "Received HTTP packet is too large. (>{})",
            buf.buf.len()
        ));
    }
    if buf.count < full_len {
        loop {
            stream.readable().await?;
            match stream.try_read(&mut buf.buf[buf.count..full_len - buf.count]) {
                Ok(n) => {
                    if n == 0 {
                        return Err(DisconnectedError.into());
                    }
                    buf.count = buf.count.saturating_add(n);
                    debug_assert!(buf.count <= full_len);
                    if buf.count == full_len {
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

async fn send_all(stream: &TcpStream, data: &[u8]) -> ah::Result<()> {
    let mut count = 0;
    loop {
        stream.writable().await?;
        match stream.try_write(&data[count..]) {
            Ok(n) => {
                count += n;
                assert!(count <= data.len());
                if count == data.len() {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

fn next_hdr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(pos) = buf.iter().position(|b| *b == b'\n') {
        let (mut l, mut r) = buf.split_at(pos);
        if !l.is_empty() && l[l.len() - 1] == b'\r' {
            l = &l[..l.len() - 1];
        }
        r = &r[1..];
        Some((l, r))
    } else {
        None
    }
}

fn find_hdr<'a>(buf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut tail = buf;
    while let Some((h, t)) = next_hdr(tail) {
        tail = t;
        if let Some(p) = memchr(b':', h) {
            if h[..p].trim_ascii().eq_ignore_ascii_case(name) {
                return Some(&h[p + 1..]);
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpRequest {
    Get,
    Post,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    R,
    W,
}

fn parse_path(path: &[u8]) -> ah::Result<(String, Direction)> {
    let mut path = path.split(|c| *c == b'/');

    let Some(comp) = path.next() else {
        return Err(err!("1st path component is missing."));
    };
    if !comp.is_empty() {
        return Err(err!("1st path component is not empty."));
    }

    //TODO ignore all empty path components

    let Some(comp) = path.next() else {
        return Err(err!("2nd path component is missing."));
    };
    let chan_name = String::from_utf8(comp.to_vec()).context("Convert chan_name to string")?;

    let Some(direction) = path.next() else {
        return Err(err!("3rd path component is missing."));
    };
    let direction = match direction {
        b"r" => Direction::R,
        b"w" => Direction::W,
        _ => {
            return Err(err!("Unknown direction in path."));
        }
    };

    let Some(_serial) = path.next() else {
        return Err(err!("4th path component is missing."));
    };

    if path.next().is_some() {
        return Err(err!("Got trailing garbage in path."));
    }

    Ok((chan_name, direction))
}

fn parse_request_header(h: &[u8]) -> ah::Result<(HttpRequest, String, Direction, Query)> {
    let mut h = h.split(|c| *c == b' ');

    let Some(request) = h.next() else {
        return Err(err!("No GET/POST request found."));
    };
    let request = match request {
        b"GET" => HttpRequest::Get,
        b"POST" => HttpRequest::Post,
        _ => {
            return Err(err!("Received neither GET nor POST."));
        }
    };

    let Some(path_info) = h.next() else {
        return Err(err!("Did not receive path info."));
    };
    let path;
    let query;
    if let Some(qpos) = path_info.iter().position(|c| *c == b'?') {
        let (p, q) = path_info.split_at(qpos);
        path = p;
        query = &q[1..];
    } else {
        path = path_info;
        query = b"";
    }

    let (chan_name, direction) = parse_path(path)?;

    let query = String::from_utf8(query.to_vec())
        .context("Convert query to string")?
        .parse::<Query>()
        .context("Parse query string")?;

    Ok((request, chan_name, direction, query))
}

#[derive(Clone, Debug)]
pub struct HttunHttpReq {
    request: HttpRequest,
    chan_name: String,
    direction: Direction,
    query: Query,
    body: Vec<u8>,
}

impl HttunHttpReq {
    pub fn extract_body(&mut self) {
        if self.request == HttpRequest::Get {
            if let Some(qmsg) = self.query.get("m") {
                if let Ok(qmsg) = &BASE64_URL_SAFE_NO_PAD.decode(qmsg.as_bytes()) {
                    self.body = qmsg.to_vec();
                }
            }
        }
    }
}

async fn recv_httun_request(id: u32, stream: &TcpStream) -> ah::Result<HttunHttpReq> {
    let buf = recv_http(stream).await.context("HTTP recv")?;
    let buf = buf.buf;

    // Parse the request header.
    let Some((h, mut tail)) = next_hdr(&buf) else {
        return Err(err!("No GET/POST header found"));
    };
    let (request, chan_name, direction, query) = parse_request_header(h)?;

    log::trace!("Conn {id}: {request:?} / {chan_name} / {direction:?} / {query:?}");

    //TODO add support for "authorization" header?

    // Ignore all other headers.
    let body = loop {
        let Some((h, t)) = next_hdr(tail) else {
            return Err(err!("Header end not found"));
        };
        tail = t;
        if h.is_empty() {
            break tail;
        }
    }
    .to_vec();

    let mut req = HttunHttpReq {
        request,
        chan_name,
        direction,
        query,
        body,
    };
    req.extract_body();

    Ok(req)
}

async fn rx_task(
    id: u32,
    stream: &TcpStream,
    rx_r_sender: &mpsc::Sender<HttunHttpReq>,
    rx_w_sender: &mpsc::Sender<HttunHttpReq>,
    closed: &AtomicBool,
) -> ah::Result<()> {
    loop {
        let req = match recv_httun_request(id, stream).await {
            Err(e) if e.downcast_ref::<DisconnectedError>().is_some() => {
                closed.store(true, atomic::Ordering::Relaxed);
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(req) => req,
        };

        match req.direction {
            Direction::R => rx_r_sender.send(req).await?,
            Direction::W => rx_w_sender.send(req).await?,
        }
    }
}

//TODO: The connection could be re-used for a different channel.
// This is not supported, yet.
// But this should only happen, if a http proxy routes two different httun
// connections at the same time and it reuses the server side connection.

pub struct HttpConn {
    id: u32,
    stream: Arc<TcpStream>,
    closed: Arc<AtomicBool>,
    rx_task: StdMutex<Option<JoinHandle<()>>>,
    rx_r: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    rx_w: Mutex<Option<mpsc::Receiver<HttunHttpReq>>>,
    pinned_chan: StdMutex<Option<String>>,
}

impl HttpConn {
    async fn new(stream: TcpStream) -> ah::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_linger(None)?;
        stream.set_ttl(255)?;

        let id = NEXT_CONN_ID.fetch_add(1, atomic::Ordering::Relaxed);
        log::debug!("New connection: {id}");

        Ok(Self {
            id,
            stream: Arc::new(stream),
            closed: Arc::new(AtomicBool::new(false)),
            rx_task: StdMutex::new(None),
            rx_r: Mutex::new(None),
            rx_w: Mutex::new(None),
            pinned_chan: StdMutex::new(None),
        })
    }

    pub async fn spawn_rx_task(&self) {
        let (rx_r_sender, rx_r_receiver) = mpsc::channel(1);
        let (rx_w_sender, rx_w_receiver) = mpsc::channel(8);

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

        *self.rx_task.lock().expect("Mutex poisoned") = Some(rx_task);
        *self.rx_r.lock().await = Some(rx_r_receiver);
        *self.rx_w.lock().await = Some(rx_w_receiver);
    }

    pub fn chan_name(&self) -> Option<String> {
        self.pinned_chan.lock().expect("Mutex poisoned").clone()
    }

    fn pin_channel(&self, chan_name: &str) -> ah::Result<()> {
        let mut pinned_chan = self.pinned_chan.lock().expect("Mutex poisoned");
        if let Some(pinned_chan) = pinned_chan.as_ref() {
            if pinned_chan != chan_name {
                Err(err!(
                    "Http connection is already pinned to a different channel."
                ))
            } else {
                Ok(())
            }
        } else {
            *pinned_chan = Some(chan_name.to_string());
            Ok(())
        }
    }

    async fn send_reply(&self, payload: Vec<u8>, status: &str) -> ah::Result<()> {
        let mut headers = String::with_capacity(256);
        write!(&mut headers, "HTTP/1.1 {status}\r\n")?;
        write!(&mut headers, "Cache-Control: no-store\r\n")?;
        if !payload.is_empty() {
            write!(&mut headers, "Content-Length: {}\r\n", payload.len())?;
            write!(&mut headers, "Content-Type: application/octet-stream\r\n")?;
        }
        write!(&mut headers, "\r\n")?;
        send_all(&self.stream, headers.as_bytes()).await?;
        if !payload.is_empty() {
            send_all(&self.stream, &payload).await?;
        }
        Ok(())
    }

    pub async fn send_reply_ok(&self, payload: Vec<u8>) -> ah::Result<()> {
        self.send_reply(payload, "200 Ok").await
    }

    pub async fn send_reply_timeout(&self) -> ah::Result<()> {
        self.send_reply(vec![], "408 Request Timeout").await
    }

    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        let mut rx_r = self.rx_r.lock().await;
        let mut rx_w = self.rx_w.lock().await;
        let closed;

        let ret = tokio::select! {
            req = rx_r.as_mut().expect("RX thread not running").recv() => {
                closed = self.closed.load(atomic::Ordering::Relaxed);
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    self.pin_channel(&req.chan_name)?;
                    Ok(CommRxMsg::ReqFromSrv(req.body))
                } else {
                    Err(err!("RX channel closed"))
                }
            }
            req = rx_w.as_mut().expect("RX thread not running").recv() => {
                closed = self.closed.load(atomic::Ordering::Relaxed);
                drop((rx_r, rx_w)); // drop locks

                if let Some(req) = req {
                    self.pin_channel(&req.chan_name)?;
                    self.send_reply_ok(vec![]).await.context("Send POST reply")?;
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

    pub async fn close(&self) -> ah::Result<()> {
        let mut rx_r = self.rx_r.lock().await;
        let mut rx_w = self.rx_w.lock().await;
        self.closed.store(true, atomic::Ordering::Relaxed);
        if let Some(rx_r) = rx_r.as_mut() {
            rx_r.close();
        }
        if let Some(rx_w) = rx_w.as_mut() {
            rx_w.close();
        }
        Ok(())
    }
}

pub struct HttpServer {
    listener: TcpListener,
}

impl HttpServer {
    pub async fn new(addr: SocketAddr) -> ah::Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context("HTTP server listener")?;
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> ah::Result<HttpConn> {
        let (stream, _addr) = self.listener.accept().await.context("HTTP accept")?;
        HttpConn::new(stream).await
    }
}

// vim: ts=4 sw=4 expandtab
