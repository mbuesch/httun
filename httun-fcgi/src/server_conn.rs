// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _};
use httun_util::{ChannelId, strings::Direction};
use std::path::Path;
use tokio::{
    io::{ReadHalf, WriteHalf, split},
    net::UnixStream,
};

/// IPC connection between this FCGI process and httun-server.
pub type IpcClientConn =
    httun_unix_protocol::IpcClientConn<ReadHalf<UnixStream>, WriteHalf<UnixStream>>;

pub async fn connect(
    socket_path: &Path,
    chan_id: ChannelId,
    dir_to_server: bool,
) -> ah::Result<IpcClientConn> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("Connect to Unix socket")?;
    let (reader, writer) = split(stream);
    let dir = if dir_to_server {
        Direction::W
    } else {
        Direction::R
    };
    IpcClientConn::new(reader, writer, chan_id, dir).await
}
