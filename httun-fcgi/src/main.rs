// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod fcgi;
mod query;
mod server_conn;

use crate::{
    fcgi::{Fcgi, FcgiRequest, FcgiRequestResult, FcgiRole},
    query::Query,
    server_conn::ServerUnixConn,
};
use anyhow::{self as ah, Context as _, format_err as err};
use base64::prelude::*;
use std::{
    collections::HashMap,
    fmt::Write as _,
    io::Read as _,
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

const MAX_NUM_CONNECTIONS: usize = 16;
const SERVER_SOCK: &str = "/run/httun-server/httun-server.sock";

const CHAN_R_TIMEOUT: Duration = Duration::from_secs(5);
const UNIX_TIMEOUT: Duration = Duration::from_secs(15);

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
        .expect("CONNECTIONS obj not init")
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
        let conn = Arc::new(ServerUnixConn::new(Path::new(SERVER_SOCK), name).await?);
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

fn path_element_is_valid(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || ['-', '_'].contains(&c))
}

//TODO try again is server disconnected (Broken Pipe, os error 32)

async fn recv_from_httun_server(name: &str, req_payload: Vec<u8>) -> ah::Result<Vec<u8>> {
    let conn = get_connection(name, false).await?;
    match conn.recv(req_payload).await {
        Ok(buf) => Ok(buf),
        Err(e) => {
            remove_connection(name).await;
            Err(e)
        }
    }
}

async fn send_to_httun_server(name: &str, req_payload: Vec<u8>) -> ah::Result<()> {
    let conn = get_connection(name, true).await?;
    if let Err(e) = conn.send(req_payload).await {
        remove_connection(name).await;
        Err(e)
    } else {
        Ok(())
    }
}

async fn fcgi_response(
    req: &FcgiRequest<'_>,
    status: &str,
    body: Option<(&[u8], &str)>,
) -> FcgiRequestResult {
    let mut hdrs = String::with_capacity(4096);
    if let Some((_, mime)) = body {
        writeln!(&mut hdrs, "Content-type: {mime}").unwrap();
    }
    writeln!(&mut hdrs, "Cache-Control: no-store").unwrap();
    writeln!(&mut hdrs, "Status: {status}").unwrap();
    writeln!(&mut hdrs).unwrap();

    let mut f = req.get_stdout();

    match f.write(hdrs.as_bytes()).await {
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

    FcgiRequestResult::Complete(0)
}

async fn fcgi_response_error(
    req: &FcgiRequest<'_>,
    status: &str,
    message: &str,
) -> FcgiRequestResult {
    fcgi_response(req, status, Some((message.as_bytes(), "text/plain"))).await
}

async fn fcgi_handler(req: FcgiRequest<'_>) -> FcgiRequestResult {
    if req.role != FcgiRole::Responder {
        eprintln!("FCGI: Only Responder role is supported.");
        return FcgiRequestResult::UnknownRole;
    }

    let Some(_remote_addr) = req.get_str_param("remote_addr") else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: No remote_addr.").await;
    };
    let Some(_remote_port) = req.get_str_param("remote_port") else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: No remote_port.").await;
    };
    let Some(method) = req.get_str_param("request_method") else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: No request_method.").await;
    };
    let Some(query) = req.get_str_param("query_string") else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: No query_string.").await;
    };
    let Some(path_info) = req.get_str_param("path_info") else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: No path_info.").await;
    };

    let mut path = path_info.split('/');
    let Some(first) = path.next() else {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Missing first entry.",
        )
        .await;
    };
    let Some(name) = path.next() else {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Missing tunnel name.",
        )
        .await;
    };
    let Some(direction) = path.next() else {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Missing direction (r/w).",
        )
        .await;
    };
    let Some(_serial) = path.next() else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: path_info: Missing serial.")
            .await;
    };
    if path.next().is_some() {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Got trailing garbage.",
        )
        .await;
    }

    if !first.is_empty() {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: First entry is not empty.",
        )
        .await;
    }
    if !path_element_is_valid(name) {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Invalid tunnel name.",
        )
        .await;
    }
    if !path_element_is_valid(direction) {
        return fcgi_response_error(
            &req,
            "400 Bad Request",
            "FCGI: path_info: Invalid direction (r/w).",
        )
        .await;
    }

    let Ok(query) = query.parse::<Query>() else {
        return fcgi_response_error(&req, "400 Bad Request", "FCGI: Invalid query string.").await;
    };

    let req_payload = match method {
        "GET" => {
            if let Some(msg) = query.get("m") {
                let Ok(msg) = &BASE64_URL_SAFE_NO_PAD.decode(msg.as_bytes()) else {
                    return fcgi_response_error(
                        &req,
                        "400 Bad Request",
                        "FCGI: Invalid query m= value.",
                    )
                    .await;
                };
                msg.to_vec()
            } else {
                vec![]
            }
        }
        "POST" => {
            let mut buf = vec![];
            let Ok(count) = req.get_stdin().read_to_end(&mut buf) else {
                return fcgi_response_error(
                    &req,
                    "400 Bad Request",
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
                "FCGI: request_method is not GET or POST.",
            )
            .await;
        }
    };

    match direction {
        "r" => match timeout(CHAN_R_TIMEOUT, recv_from_httun_server(name, req_payload)).await {
            Err(_) => fcgi_response(&req, "408 Request Timeout", None).await,
            Ok(Err(e)) => {
                eprintln!("FCGI: HTTP-r: recv from server failed: {e}");
                fcgi_response_error(
                    &req,
                    "503 Service Unavailable",
                    "FCGI: HTTP-r: recv from server failed.",
                )
                .await
            }
            Ok(Ok(data)) => {
                fcgi_response(&req, "200 Ok", Some((&data, "application/octet-stream"))).await
            }
        },
        "w" => {
            if let Err(e) = send_to_httun_server(name, req_payload).await {
                eprintln!("FCGI: HTTP-w: send to server failed: {e}");
                fcgi_response_error(
                    &req,
                    "503 Service Unavailable",
                    "FCGI: HTTP-w: send to server failed.",
                )
                .await
            } else {
                fcgi_response(&req, "200 Ok", None).await
            }
        }
        _ => fcgi_response_error(&req, "400 Bad Request", "FCGI: Unknown direction.").await,
    }
}

async fn async_main() -> ah::Result<()> {
    println!("Spawning new httun-fcgi: {}", std::process::id());

    // Create async IPC channels.
    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);
    let exit_sock_tx = Arc::new(exit_sock_tx);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    CONNECTIONS.set(Mutex::new(HashMap::new())).unwrap();

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
        let conn_semaphore = Semaphore::new(MAX_NUM_CONNECTIONS);
        loop {
            match fcgi.accept().await {
                Ok(mut conn) => {
                    if let Ok(_permit) = conn_semaphore.acquire().await {
                        task::spawn(async move {
                            if let Err(e) = conn.handle(fcgi_handler).await {
                                eprintln!("FCGI conn error: {e}");
                            }
                        });
                    }
                }
                Err(e) => {
                    let _ = exit_sock_tx.send(Err(e)).await;
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
            code = exit_sock_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }
    exitcode
}

fn main() -> ah::Result<()> {
    runtime::Builder::new_current_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main())
}

// vim: ts=4 sw=4 expandtab
