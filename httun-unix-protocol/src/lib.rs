// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

#![forbid(unsafe_code)]

pub use crate::{
    ipc::{IPC_HANDSHAKE_TIMEOUT, IpcClientConn, IpcRxMessage, IpcServerConn},
    message::{IpcMessage, IpcMessageHeader, IpcOperation},
};

mod ipc;
mod message;

/// Path to the Unix domain socket used by httun-server.
pub const UNIX_SOCK: &str = "/run/httun-server/httun-server.sock";
/// Name of the Windows named pipe used by httun-server.
pub const WINDOWS_PIPE: &str = r"\\.\pipe\httun-server";

// vim: ts=4 sw=4 expandtab
