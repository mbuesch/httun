// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{http_server::HttpConn, unix_sock::UnixConn};
use anyhow::{self as ah, Context as _, format_err as err};
use httun_unix_protocol::{UnMessage, UnOperation};

pub enum CommRxMsg {
    ToSrv(Vec<u8>),
    ReqFromSrv(Vec<u8>),
}

pub enum CommBackend {
    Unix(UnixConn),
    Http(HttpConn),
}

impl CommBackend {
    pub fn new_unix(conn: UnixConn) -> Self {
        Self::Unix(conn)
    }

    pub fn new_http(conn: HttpConn) -> Self {
        Self::Http(conn)
    }

    pub fn chan_name(&self) -> Option<String> {
        match self {
            Self::Unix(conn) => Some(conn.chan_name().to_string()),
            Self::Http(conn) => conn.chan_name(),
        }
    }

    async fn recv_unix(&self, conn: &UnixConn) -> ah::Result<CommRxMsg> {
        let Some(umsg) = conn.recv().await.context("Unix socket receive")? else {
            return Err(err!("Disconnected."));
        };

        match umsg.op() {
            UnOperation::ToSrv => Ok(CommRxMsg::ToSrv(umsg.into_payload())),
            UnOperation::ReqFromSrv => Ok(CommRxMsg::ReqFromSrv(umsg.into_payload())),
            UnOperation::Init | UnOperation::FromSrv | UnOperation::Close => {
                Err(err!("Received invalid operation: {:?}", umsg.op()))
            }
        }
    }

    async fn recv_http(&self, conn: &HttpConn) -> ah::Result<CommRxMsg> {
        conn.recv().await
    }

    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        match self {
            Self::Unix(conn) => self.recv_unix(conn).await,
            Self::Http(conn) => self.recv_http(conn).await,
        }
    }

    async fn send_unix(&self, conn: &UnixConn, payload: Vec<u8>) -> ah::Result<()> {
        let chan_name = self
            .chan_name()
            .ok_or_else(|| err!("Channel name is not known, yet"))?;
        let umsg = UnMessage::new_from_srv(chan_name.to_string(), payload);
        conn.send(&umsg).await.context("Unix socket send")
    }

    async fn send_http(&self, conn: &HttpConn, payload: Vec<u8>) -> ah::Result<()> {
        conn.send_reply(payload, "200 Ok").await
    }

    pub async fn send(&self, payload: Vec<u8>) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => self.send_unix(conn, payload).await,
            Self::Http(conn) => self.send_http(conn, payload).await,
        }
    }

    async fn send_close_unix(&self, conn: &UnixConn) -> ah::Result<()> {
        let chan_name = self
            .chan_name()
            .ok_or_else(|| err!("Channel name is not known, yet"))?;
        let umsg = UnMessage::new_close(chan_name.to_string());
        conn.send(&umsg).await.context("Unix socket send")
    }

    async fn send_close_http(&self, _conn: &HttpConn) -> ah::Result<()> {
        // Nothing to do.
        Ok(())
    }

    pub async fn send_close(&self) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => self.send_close_unix(conn).await,
            Self::Http(conn) => self.send_close_http(conn).await,
        }
    }
}

// vim: ts=4 sw=4 expandtab
