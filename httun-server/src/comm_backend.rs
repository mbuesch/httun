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

    async fn recv_unix(conn: &UnixConn) -> ah::Result<CommRxMsg> {
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

    async fn recv_http(conn: &HttpConn) -> ah::Result<CommRxMsg> {
        todo!()
    }

    pub async fn recv(&self) -> ah::Result<CommRxMsg> {
        match self {
            Self::Unix(conn) => Self::recv_unix(conn).await,
            Self::Http(conn) => Self::recv_http(conn).await,
        }
    }

    async fn send_unix(conn: &UnixConn, chan_name: &str, payload: Vec<u8>) -> ah::Result<()> {
        let umsg = UnMessage::new_from_srv(chan_name.to_string(), payload);
        conn.send(&umsg).await.context("Unix socket send")
    }

    async fn send_http(conn: &HttpConn, chan_name: &str, payload: Vec<u8>) -> ah::Result<()> {
        todo!()
    }

    pub async fn send(&self, chan_name: &str, payload: Vec<u8>) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => Self::send_unix(conn, chan_name, payload).await,
            Self::Http(conn) => Self::send_http(conn, chan_name, payload).await,
        }
    }

    async fn send_close_unix(conn: &UnixConn, chan_name: &str) -> ah::Result<()> {
        let umsg = UnMessage::new_close(chan_name.to_string());
        conn.send(&umsg).await.context("Unix socket send")
    }

    async fn send_close_http(conn: &HttpConn, chan_name: &str) -> ah::Result<()> {
        todo!()
    }

    pub async fn send_close(&self, chan_name: &str) -> ah::Result<()> {
        match self {
            Self::Unix(conn) => Self::send_close_unix(conn, chan_name).await,
            Self::Http(conn) => Self::send_close_http(conn, chan_name).await,
        }
    }
}

// vim: ts=4 sw=4 expandtab
