// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, Context as _};
use httun_util::{ChannelId, strings::Direction};
use std::path::Path;

#[cfg(target_family = "unix")]
use tokio::{
    io::{ReadHalf, WriteHalf, split},
    net::UnixStream,
};
#[cfg(target_family = "windows")]
use tokio::{
    io::{ReadHalf, WriteHalf, split},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
};

/// Local IPC connection between this HTTP server process and httun-server.
#[cfg(target_family = "unix")]
pub type IpcClientConn =
    httun_unix_protocol::IpcClientConn<ReadHalf<UnixStream>, WriteHalf<UnixStream>>;
/// Local IPC connection between this HTTP server process and httun-server.
#[cfg(target_family = "windows")]
pub type IpcClientConn =
    httun_unix_protocol::IpcClientConn<ReadHalf<NamedPipeClient>, WriteHalf<NamedPipeClient>>;

pub async fn connect(
    socket_path: &Path,
    chan_id: ChannelId,
    dir_to_server: bool,
) -> ah::Result<IpcClientConn> {
    let dir = if dir_to_server {
        Direction::W
    } else {
        Direction::R
    };

    #[cfg(target_family = "unix")]
    {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("Connect to Unix socket")?;
        let (reader, writer) = split(stream);
        IpcClientConn::new(reader, writer, chan_id, dir).await
    }

    #[cfg(target_family = "windows")]
    {
        let stream = ClientOptions::new()
            .open(socket_path.as_os_str())
            .context("Connect to Windows named pipe")?;
        let (reader, writer) = split(stream);
        IpcClientConn::new(reader, writer, chan_id, dir).await
    }
}
