// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    fcgi::{FcgiRequest, FcgiRequestResult, FcgiRole},
    server_conn::ServerUnixConn,
};
use anyhow::{self as ah, format_err as err};
use httun_protocol::Message;
use httun_unix_protocol::UNIX_SOCK;
use httun_util::{
    ChannelId,
    header::HttpHeader,
    query::Query,
    strings::{Direction, parse_path},
    timeouts::{CHAN_R_TIMEOUT, UNIX_TIMEOUT},
};
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    path::Path,
    sync::Arc,
    sync::OnceLock,
    time::Instant,
};
use tokio::{
    sync::{Mutex, MutexGuard},
    time::timeout,
};

/// Represents an active connection to the `httun-server`.
#[derive(Debug, Clone)]
struct Connection {
    /// Connection to the `httun-server`.
    conn: Arc<ServerUnixConn>,
    /// Last activity time.
    last_activity: Instant,
}

impl Connection {
    /// Create a new connection to the `httun-server`.
    fn new(conn: Arc<ServerUnixConn>) -> Self {
        Self {
            conn,
            last_activity: Instant::now(),
        }
    }

    /// Log activity.
    fn log_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if the connection is timed out.
    fn is_timed_out(&self, now: Instant) -> bool {
        self.last_activity.duration_since(now) >= UNIX_TIMEOUT
    }
}

/// Key for the global connections map.
type ConnectionsKey = (ChannelId, bool);
/// Global connections map.
/// This map stores active connections to the `httun-server`.
static CONNECTIONS: OnceLock<Mutex<HashMap<ConnectionsKey, Connection>>> = OnceLock::new();

/// Get the global connections map.
async fn get_connections<'a>() -> MutexGuard<'a, HashMap<ConnectionsKey, Connection>> {
    CONNECTIONS
        .get()
        .expect("CONNECTIONS object is not initialized")
        .lock()
        .await
}

/// Get a connection for the given channel ID and direction.
async fn get_connection(chan_id: ChannelId, send: bool) -> ah::Result<Arc<ServerUnixConn>> {
    let key = (chan_id, send);
    let mut connections = get_connections().await;
    if let Some(conn) = connections.get_mut(&key) {
        conn.log_activity();
        Ok(Arc::clone(&conn.conn))
    } else {
        let conn = Arc::new(ServerUnixConn::new(Path::new(UNIX_SOCK), chan_id, send).await?);
        connections.insert(key, Connection::new(Arc::clone(&conn)));
        Ok(conn)
    }
}

/// Remove a connection.
///
/// This removes both the send and receive connections.
async fn remove_connection(chan_id: ChannelId) {
    let mut connections = get_connections().await;
    connections.remove(&(chan_id, false));
    connections.remove(&(chan_id, true));
}

/// Check for and remove timed out connections.
pub async fn check_connection_timeouts() {
    let mut connections = get_connections().await;
    let now = Instant::now();
    connections.retain(|_, conn| !conn.is_timed_out(now));
}

/// Return value of request from httun-server.
struct FromHttunRet {
    /// Payload from httun-server.
    payload: Vec<u8>,
    /// Extra HTTP headers from httun-server.
    extra_headers: Vec<HttpHeader>,
}

/// Send a payload to httun-server and receive a payload from httun-server.
async fn recv_from_httun_server(
    chan_id: ChannelId,
    req_payload: Vec<u8>,
) -> ah::Result<FromHttunRet> {
    let conn = get_connection(chan_id, false).await?;
    match conn.recv(req_payload).await {
        Ok(payload) => Ok(FromHttunRet {
            payload,
            extra_headers: conn.extra_headers().to_vec(),
        }),
        Err(e) => {
            remove_connection(chan_id).await;
            Err(e)
        }
    }
}

/// Return value of request sent to httun-server.
struct ToHttunRet {
    /// Extra HTTP headers from httun-server.
    extra_headers: Vec<HttpHeader>,
}

/// Send a payload to httun-server.
async fn send_to_httun_server(chan_id: ChannelId, req_payload: Vec<u8>) -> ah::Result<ToHttunRet> {
    let conn = get_connection(chan_id, true).await?;
    if let Err(e) = conn.send(req_payload).await {
        remove_connection(chan_id).await;
        Err(e)
    } else {
        Ok(ToHttunRet {
            extra_headers: conn.extra_headers().to_vec(),
        })
    }
}

/// Send keepalive to httun-server.
async fn send_keepalive_to_httun_server(chan_id: ChannelId) -> ah::Result<()> {
    get_connection(chan_id, true).await?.send_keepalive().await
}

/// Send `FastCGI` response.
async fn fcgi_response(
    req: &FcgiRequest<'_>,
    status: &str,
    extra_headers: &[HttpHeader],
    body: Option<(&[u8], &str)>,
) -> FcgiRequestResult {
    // Create HTTP response headers.
    let mut hdrs: Vec<u8> = Vec::with_capacity(4096);
    writeln!(&mut hdrs, "cache-control: no-store").expect("hdrs write");
    for hdr in extra_headers {
        hdrs.extend_from_slice(hdr.name());
        write!(&mut hdrs, ": ").expect("hdrs write");
        hdrs.extend_from_slice(hdr.value());
        writeln!(&mut hdrs).expect("hdrs write");
    }
    if let Some((_, mime)) = body {
        writeln!(&mut hdrs, "content-type: {mime}").expect("hdrs write");
    }
    writeln!(&mut hdrs, "status: {status}").expect("hdrs write");
    writeln!(&mut hdrs).expect("hdrs write");

    // Get stdout for communication with the FastCGI.
    let mut f = req.get_stdout();

    // Write HTTP response headers to stdout.
    match f.write(&hdrs).await {
        Ok(count) if count == hdrs.len() => (),
        _ => {
            eprintln!("FCGI: Failed to write to fcgi socket.");
            return FcgiRequestResult::Complete(1);
        }
    }

    // Write HTTP response body to stdout.
    if let Some((body, _)) = body {
        match f.write(body).await {
            Ok(count) if count == body.len() => (),
            _ => {
                eprintln!("FCGI: Failed to write to fcgi socket.");
                return FcgiRequestResult::Complete(1);
            }
        }
    }

    // Flush stdout.
    if f.flush().await.is_err() {
        eprintln!("FCGI: Failed to flush fcgi socket.");
        return FcgiRequestResult::Complete(1);
    }

    FcgiRequestResult::Complete(0)
}

/// Send `FastCGI` error response.
async fn fcgi_response_error(
    req: &FcgiRequest<'_>,
    status: &str,
    extra_headers: &[HttpHeader],
    message: &str,
) -> FcgiRequestResult {
    fcgi_response(
        req,
        status,
        extra_headers,
        Some((message.as_bytes(), "text/plain")),
    )
    .await
}

/// Handle `FastCGI` requests.
///
/// This is the main entry point for the FCGI application.
pub async fn fcgi_handler(req: FcgiRequest<'_>) -> FcgiRequestResult {
    if req.role != FcgiRole::Responder {
        eprintln!("FCGI: Only Responder role is supported.");
        return FcgiRequestResult::UnknownRole;
    }

    let Some(method) = req.get_param("request_method") else {
        return fcgi_response_error(&req, "400 Bad Request", &[], "FCGI: No request_method.").await;
    };
    let Some(query) = req.get_param("query_string") else {
        return fcgi_response_error(&req, "400 Bad Request", &[], "FCGI: No query_string.").await;
    };
    let Some(path_info) = req.get_param("path_info") else {
        return fcgi_response_error(&req, "400 Bad Request", &[], "FCGI: No path_info.").await;
    };

    let (chan_id, direction) = match parse_path(path_info) {
        Err(e) => {
            return fcgi_response_error(
                &req,
                "400 Bad Request",
                &[],
                &format!("FCGI: path_info: {e}"),
            )
            .await;
        }
        Ok(p) => p,
    };

    let query: Result<Query, _> = query.as_slice().try_into();
    let Ok(query) = query else {
        return fcgi_response_error(&req, "400 Bad Request", &[], "FCGI: Invalid query string.")
            .await;
    };

    let req_payload = match &method[..] {
        b"GET" => {
            if let Some(msg) = query.get(b"m") {
                let Ok(msg) = Message::decode_b64u(msg) else {
                    return fcgi_response_error(
                        &req,
                        "400 Bad Request",
                        &[],
                        "FCGI: Invalid query m= value.",
                    )
                    .await;
                };
                msg
            } else {
                vec![]
            }
        }
        b"POST" => {
            let mut buf = vec![];
            let Ok(count) = req.get_stdin().read_to_end(&mut buf) else {
                return fcgi_response_error(
                    &req,
                    "400 Bad Request",
                    &[],
                    "FCGI: Failed to read POST body.",
                )
                .await;
            };
            buf.truncate(count);
            buf
        }
        _ => {
            return fcgi_response_error(
                &req,
                "400 Bad Request",
                &[],
                "FCGI: request_method is not GET or POST.",
            )
            .await;
        }
    };

    match direction {
        Direction::R => {
            let result =
                timeout(CHAN_R_TIMEOUT, recv_from_httun_server(chan_id, req_payload)).await;

            match result {
                Err(_) => {
                    if let Err(e) = send_keepalive_to_httun_server(chan_id).await {
                        eprintln!("FCGI: HTTP-r: keepalive to server failed: {e:?}");
                    }
                    fcgi_response(&req, "408 Request Timeout", &[], None).await
                }
                Ok(Err(e)) => {
                    eprintln!("FCGI: HTTP-r: recv from server failed: {e:?}");
                    fcgi_response_error(
                        &req,
                        "503 Service Unavailable",
                        &[],
                        "FCGI: HTTP-r: recv from server failed.",
                    )
                    .await
                }
                Ok(Ok(ret)) => {
                    fcgi_response(
                        &req,
                        "200 Ok",
                        &ret.extra_headers,
                        Some((&ret.payload, "application/octet-stream")),
                    )
                    .await
                }
            }
        }
        Direction::W => {
            let result = send_to_httun_server(chan_id, req_payload).await;

            match result {
                Ok(ret) => fcgi_response(&req, "200 Ok", &ret.extra_headers, None).await,
                Err(e) => {
                    eprintln!("FCGI: HTTP-w: send to server failed: {e:?}");
                    fcgi_response_error(
                        &req,
                        "503 Service Unavailable",
                        &[],
                        "FCGI: HTTP-w: send to server failed.",
                    )
                    .await
                }
            }
        }
    }
}

/// Initialize the `FastCGI` handler.
pub fn init_fcgi_handler() -> ah::Result<()> {
    CONNECTIONS
        .set(Mutex::new(HashMap::new()))
        .map_err(|_| err!("Initialization of CONNECTIONS object failed"))
}

// vim: ts=4 sw=4 expandtab
