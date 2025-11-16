// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{http_server::HttpConn, unix_sock::UnixConn};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_unix_protocol::{UnMessage, UnOperation};
use httun_util::timeouts::CHAN_R_TIMEOUT;
use std::time::Duration;

#[derive(Debug)]
pub enum CommRxMsg {
    ToSrv(Vec<u8>),
    ReqFromSrv(Vec<u8>),
    Keepalive,
}

#[derive(Debug)]
pub enum CommBackend {
    Unix(Box<UnixConn>),
    Http(Box<HttpConn>),
}

impl CommBackend {
    pub fn new_unix(conn: UnixConn) -> Self {
        Self::Unix(Box::new(conn))
    }

    pub fn new_http(conn: HttpConn) -> Self {
        Self::Http(Box::new(conn))
    }

    pub fn chan_name(&self) -> Option<String> {
        match self {
            Self::Unix(conn) => Some(conn.chan_name().to_string()),
            Self::Http(conn) => conn.chan_name(),
        }
    }

    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        match self {
            Self::Unix(conn) => {
                let umsg = conn.recv().await.context("Unix socket receive")?;
                match umsg.op() {
                    UnOperation::ToSrv => Ok(CommRxMsg::ToSrv(umsg.into_payload())),
                    UnOperation::ReqFromSrv => Ok(CommRxMsg::ReqFromSrv(umsg.into_payload())),
                    UnOperation::Keepalive => Ok(CommRxMsg::Keepalive),
                    UnOperation::Init | UnOperation::FromSrv | UnOperation::Close => {
                        Err(err!("Received invalid operation: {:?}", umsg.op()))
                    }
                }
            }
            Self::Http(conn) => match conn.recv().await {
                Ok(msg) => Ok(msg),
                Err(e) => {
                    let _ = conn.send_reply_badrequest().await;
                    Err(e)
                }
            },
        }
    }

    pub async fn send_reply(&self, payload: Vec<u8>) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => {
                let chan_name = self
                    .chan_name()
                    .ok_or_else(|| err!("Channel name is not known, yet"))?;
                let umsg = UnMessage::new_from_srv(chan_name.to_string(), payload);
                conn.send(&umsg).await.context("Unix socket send")
            }
            Self::Http(conn) => conn.send_reply_ok(&payload).await,
        }
    }

    pub async fn send_reply_timeout(&self) -> ah::Result<()> {
        match self {
            Self::Unix(_) => Ok(()),
            Self::Http(conn) => conn.send_reply_timeout().await,
        }
    }

    pub fn get_reply_timeout_duration(&self) -> Option<Duration> {
        match self {
            Self::Unix(_) => None,
            Self::Http(_) => Some(CHAN_R_TIMEOUT),
        }
    }

    pub async fn close(&self) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => {
                let chan_name = self
                    .chan_name()
                    .ok_or_else(|| err!("Channel name is not known, yet"))?;
                let umsg = UnMessage::new_close(chan_name.to_string());
                conn.send(&umsg).await.context("Unix socket send")
            }
            Self::Http(conn) => conn.close().await,
        }
    }
}

// vim: ts=4 sw=4 expandtab
