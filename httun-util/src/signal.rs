// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(target_family = "unix")]
#[macro_export]
macro_rules! register_signal {
    ($kind:ident) => {
        signal(SignalKind::$kind())
    };
}

#[cfg(not(target_family = "unix"))]
#[macro_export]
macro_rules! register_signal {
    ($kind:ident) => {{
        let result: ah::Result<u32> = Ok(0_u32);
        result
    }};
}

#[cfg(target_family = "unix")]
#[macro_export]
macro_rules! recv_signal {
    ($sig:ident) => {
        $sig.recv()
    };
}

#[cfg(not(target_family = "unix"))]
#[doc(hidden)]
pub async fn signal_dummy<T>(_: &mut T) {
    loop {
        tokio::time::sleep(std::time::Duration::MAX).await;
    }
}

#[cfg(not(target_family = "unix"))]
#[macro_export]
macro_rules! recv_signal {
    ($sig:ident) => {
        $crate::signal::signal_dummy(&mut $sig)
    };
}

pub use recv_signal;
pub use register_signal;

// vim: ts=4 sw=4 expandtab
