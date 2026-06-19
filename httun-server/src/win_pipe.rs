// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use httun_conf::Config;
use httun_util::header::HttpHeader;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{ReadHalf, WriteHalf, split},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};

/// IPC connection carried by a Windows named pipe.
pub type IpcServerConn =
    httun_unix_protocol::IpcServerConn<ReadHalf<NamedPipeServer>, WriteHalf<NamedPipeServer>>;

/// Windows named-pipe listener used by httun-httpserver.
#[derive(Debug)]
pub struct WinPipe {
    pipe_name: PathBuf,
    conf: Arc<Config>,
    extra_headers: Arc<[HttpHeader]>,
    first_instance: AtomicBool,
}

impl WinPipe {
    pub fn new(
        conf: Arc<Config>,
        pipe_name: &Path,
        extra_headers: Arc<[HttpHeader]>,
    ) -> ah::Result<Self> {
        if pipe_name.as_os_str().is_empty() {
            return Err(err!("Windows named pipe name must not be empty."));
        }
        Ok(Self {
            pipe_name: pipe_name.to_path_buf(),
            conf,
            extra_headers,
            first_instance: AtomicBool::new(true),
        })
    }

    pub async fn accept(&self) -> ah::Result<IpcServerConn> {
        let first_instance = self.first_instance.load(Ordering::Acquire);
        let stream = ServerOptions::new()
            .first_pipe_instance(first_instance)
            .create(&self.pipe_name)
            .context("Create Windows named pipe instance")?;
        if first_instance {
            self.first_instance.store(false, Ordering::Release);
        }
        stream
            .connect()
            .await
            .context("Accept Windows named pipe connection")?;
        let (reader, writer) = split(stream);
        IpcServerConn::new(reader, writer, &self.conf, &self.extra_headers).await
    }
}
