// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::http_server::HttpConn;
use anyhow as ah;
use httun_util::timeouts::CHAN_R_TIMEOUT;
use std::time::Duration;

#[cfg(target_family = "unix")]
use crate::unix_sock::UnixConn;

#[cfg(target_family = "unix")]
use anyhow::{Context as _, format_err as err};

#[cfg(target_family = "unix")]
use httun_unix_protocol::{UnMessage, UnOperation};

/// Message received from communication backend.
#[derive(Debug)]
pub enum CommRxMsg {
    /// Data to server.
    ToSrv(Vec<u8>),
    /// Request for data from server.
    ReqFromSrv(Vec<u8>),
    /// Keepalive message.
    #[allow(dead_code)]
    Keepalive,
}

/// Communication backend over Unix socket connections.
#[cfg(target_family = "unix")]
#[derive(Debug)]
pub struct CommBackendUnix {
    conn: UnixConn,
}

/// Communication backend over HTTP connections.
#[derive(Debug)]
pub struct CommBackendHttp {
    conn: HttpConn,
}

/// Communication backend abstraction over Unix socket and HTTP connections.
#[derive(Debug)]
pub enum CommBackend {
    #[cfg(target_family = "unix")]
    Unix(Box<CommBackendUnix>),
    Http(Box<CommBackendHttp>),
}

impl CommBackend {
    /// Create a new Unix socket communication backend.
    #[cfg(target_family = "unix")]
    pub fn new_unix(conn: UnixConn) -> Self {
        Self::Unix(Box::new(CommBackendUnix { conn }))
    }

    /// Create a new HTTP communication backend.
    pub fn new_http(conn: HttpConn) -> Self {
        Self::Http(Box::new(CommBackendHttp { conn }))
    }

    /// Get the channel name, if known.
    pub fn chan_name(&self) -> Option<String> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(b) => Some(b.conn.chan_name().to_string()),
            Self::Http(b) => b.conn.chan_name(),
        }
    }

    /// Receive a message from the communication backend.
    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(b) => {
                let umsg = b.conn.recv().await.context("Unix socket receive")?;
                match umsg.op() {
                    UnOperation::ToSrv => Ok(CommRxMsg::ToSrv(umsg.into_payload())),
                    UnOperation::ReqFromSrv => Ok(CommRxMsg::ReqFromSrv(umsg.into_payload())),
                    UnOperation::Keepalive => Ok(CommRxMsg::Keepalive),
                    UnOperation::ToSrvInit
                    | UnOperation::FromSrvInit
                    | UnOperation::FromSrv
                    | UnOperation::Close => {
                        Err(err!("Received invalid operation: {:?}", umsg.op()))
                    }
                }
            }
            Self::Http(b) => match b.conn.recv().await {
                Ok(msg) => Ok(msg),
                Err(e) => {
                    let _ = b.conn.send_reply_badrequest().await;
                    Err(e)
                }
            },
        }
    }

    /// Send a reply to the communication backend.
    pub async fn send_reply(&self, payload: Vec<u8>) -> ah::Result<()> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(b) => {
                let chan_name = self
                    .chan_name()
                    .ok_or_else(|| err!("Channel name is not known, yet"))?;
                let umsg = UnMessage::new_from_srv(chan_name.to_string(), payload);
                b.conn.send(&umsg).await.context("Unix socket send")
            }
            Self::Http(b) => b.conn.send_reply_ok(&payload).await,
        }
    }

    /// Send a reply timeout notification to the communication backend.
    pub async fn send_reply_timeout(&self) -> ah::Result<()> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(_) => {
                // Timeouts are handled at the FastCGI/Webserver level.
                Ok(())
            }
            Self::Http(b) => b.conn.send_reply_timeout().await,
        }
    }

    /// Get the reply timeout duration for the communication backend.
    pub fn get_reply_timeout_duration(&self) -> Option<Duration> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(_) => {
                // Timeouts are handled at the FastCGI/Webserver level.
                None
            }
            Self::Http(_) => Some(CHAN_R_TIMEOUT),
        }
    }

    /// Close the communication backend.
    pub async fn close(&self) -> ah::Result<()> {
        match self {
            #[cfg(target_family = "unix")]
            Self::Unix(b) => {
                let chan_name = self
                    .chan_name()
                    .ok_or_else(|| err!("Channel name is not known, yet"))?;
                let umsg = UnMessage::new_close(chan_name.to_string());
                b.conn.send(&umsg).await.context("Unix socket send")
            }
            Self::Http(b) => b.conn.close().await,
        }
    }
}

// vim: ts=4 sw=4 expandtab
