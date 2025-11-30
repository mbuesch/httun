// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod fcgi;
mod server_conn;

use crate::{
    fcgi::{Fcgi, FcgiRequest, FcgiRequestResult, FcgiRole},
    server_conn::ServerUnixConn,
};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_protocol::Message;
use httun_unix_protocol::UNIX_SOCK;
use httun_util::{
    header::HttpHeader,
    query::Query,
    strings::{Direction, parse_path},
    timeouts::{CHAN_R_TIMEOUT, UNIX_TIMEOUT},
};
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    os::fd::AsRawFd as _,
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync::{self, Mutex, MutexGuard, Semaphore},
    task,
    time::timeout,
};

const MAX_NUM_CONNECTIONS: u8 = 64;

#[derive(Debug, Clone)]
struct Connection {
    conn: Arc<ServerUnixConn>,
    last_activity: Instant,
}

impl Connection {
    fn new(conn: Arc<ServerUnixConn>) -> Self {
        Self {
            conn,
            last_activity: Instant::now(),
        }
    }

    fn log_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_timed_out(&self, now: Instant) -> bool {
        self.last_activity.duration_since(now) >= UNIX_TIMEOUT
    }
}

type ConnectionsKey = (String, bool);
static CONNECTIONS: OnceLock<Mutex<HashMap<ConnectionsKey, Connection>>> = OnceLock::new();

async fn get_connections<'a>() -> MutexGuard<'a, HashMap<ConnectionsKey, Connection>> {
    CONNECTIONS
        .get()
        .expect("CONNECTIONS object is not initialized")
        .lock()
        .await
}

async fn get_connection(name: &str, send: bool) -> ah::Result<Arc<ServerUnixConn>> {
    let key = (name.to_string(), send);
    let mut connections = get_connections().await;
    if let Some(conn) = connections.get_mut(&key) {
        conn.log_activity();
        Ok(Arc::clone(&conn.conn))
    } else {
        let conn = Arc::new(ServerUnixConn::new(Path::new(UNIX_SOCK), name).await?);
        connections.insert(key, Connection::new(Arc::clone(&conn)));
        Ok(conn)
    }
}

async fn remove_connection(name: &str) {
    let mut connections = get_connections().await;
    connections.remove(&(name.to_string(), false));
    connections.remove(&(name.to_string(), true));
}

async fn check_connection_timeouts() {
    let mut connections = get_connections().await;
    let now = Instant::now();
    connections.retain(|_, conn| !conn.is_timed_out(now));
}

struct FromHttunRet {
    payload: Vec<u8>,
    extra_headers: Vec<HttpHeader>,
}

async fn recv_from_httun_server(name: &str, req_payload: Vec<u8>) -> ah::Result<FromHttunRet> {
    let conn = get_connection(name, false).await?;
    match conn.recv(req_payload).await {
        Ok(payload) => Ok(FromHttunRet {
            payload,
            extra_headers: conn.extra_headers().to_vec(),
        }),
        Err(e) => {
            remove_connection(name).await;
            Err(e)
        }
    }
}

struct ToHttunRet {
    extra_headers: Vec<HttpHeader>,
}

async fn send_to_httun_server(name: &str, req_payload: Vec<u8>) -> ah::Result<ToHttunRet> {
    let conn = get_connection(name, true).await?;
    if let Err(e) = conn.send(req_payload).await {
        remove_connection(name).await;
        Err(e)
    } else {
        Ok(ToHttunRet {
            extra_headers: conn.extra_headers().to_vec(),
        })
    }
}

async fn send_keepalive_to_httun_server(name: &str) -> ah::Result<()> {
    get_connection(name, true).await?.send_keepalive().await
}

async fn fcgi_response(
    req: &FcgiRequest<'_>,
    status: &str,
    extra_headers: &[HttpHeader],
    body: Option<(&[u8], &str)>,
) -> FcgiRequestResult {
    let mut hdrs: Vec<u8> = Vec::with_capacity(4096);
    writeln!(&mut hdrs, "Cache-Control: no-store").expect("hdrs write");
    for hdr in extra_headers {
        hdrs.extend_from_slice(hdr.name());
        write!(&mut hdrs, ": ").expect("hdrs write");
        hdrs.extend_from_slice(hdr.value());
        writeln!(&mut hdrs).expect("hdrs write");
    }
    if let Some((_, mime)) = body {
        writeln!(&mut hdrs, "Content-type: {mime}").expect("hdrs write");
    }
    writeln!(&mut hdrs, "Status: {status}").expect("hdrs write");
    writeln!(&mut hdrs).expect("hdrs write");

    let mut f = req.get_stdout();

    match f.write(&hdrs).await {
        Ok(count) if count == hdrs.len() => (),
        _ => {
            eprintln!("FCGI: Failed to write to fcgi socket.");
            return FcgiRequestResult::Complete(1);
        }
    }

    if let Some((body, _)) = body {
        match f.write(body).await {
            Ok(count) if count == body.len() => (),
            _ => {
                eprintln!("FCGI: Failed to write to fcgi socket.");
                return FcgiRequestResult::Complete(1);
            }
        }
    }

    if f.flush().await.is_err() {
        eprintln!("FCGI: Failed to flush fcgi socket.");
        return FcgiRequestResult::Complete(1);
    }

    FcgiRequestResult::Complete(0)
}

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

async fn fcgi_handler(req: FcgiRequest<'_>) -> FcgiRequestResult {
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

    let (chan_name, direction) = match parse_path(path_info) {
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
            let result = timeout(
                CHAN_R_TIMEOUT,
                recv_from_httun_server(&chan_name, req_payload),
            )
            .await;

            match result {
                Err(_) => {
                    if let Err(e) = send_keepalive_to_httun_server(&chan_name).await {
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
            let result = send_to_httun_server(&chan_name, req_payload).await;

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

async fn async_main() -> ah::Result<()> {
    println!("Spawning new httun-fcgi: {}", std::process::id());

    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;

    CONNECTIONS
        .set(Mutex::new(HashMap::new()))
        .map_err(|_| err!("Initialization of CONNECTIONS object failed"))?;

    let fcgi = Fcgi::new(std::io::stdin().as_raw_fd()).context("Create FCGI")?;

    // Spawn task: Periodic task.
    task::spawn({
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                check_connection_timeouts().await;
            }
        }
    });

    // Spawn task: Socket handler.
    task::spawn(async move {
        let conn_semaphore = Arc::new(Semaphore::new(MAX_NUM_CONNECTIONS.into()));
        loop {
            let conn_semaphore = Arc::clone(&conn_semaphore);
            match fcgi.accept().await {
                Ok(mut conn) => {
                    if let Ok(permit) = conn_semaphore.acquire_owned().await {
                        task::spawn(async move {
                            if let Err(e) = conn.handle(fcgi_handler).await {
                                eprintln!("FCGI conn error: {e:?}");
                            }
                            drop(permit);
                        });
                    }
                }
                Err(e) => {
                    let _ = exit_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Task: Main loop.
    let exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
                println!("SIGHUP: Ignoring.");
            }
            code = exit_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }
    exitcode
}

fn main() -> ah::Result<()> {
    const WORKER_THREADS: usize = 6;
    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(WORKER_THREADS * 4)
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main())
}

// vim: ts=4 sw=4 expandtab
