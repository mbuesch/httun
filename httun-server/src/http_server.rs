// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow as ah;
use std::net::SocketAddr;

pub struct HttpConn {}

impl HttpConn {
    pub fn chan_name(&self) -> &str {
        todo!()
    }
}

pub struct HttpServer {}

impl HttpServer {
    pub async fn new(addr: SocketAddr) -> ah::Result<Self> {
        Ok(Self {})
    }

    pub async fn accept(&self) -> ah::Result<HttpConn> {
        todo!()
    }
}

// vim: ts=4 sw=4 expandtab
