// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::time::{now, tdiff};
use anyhow::{self as ah, Context as _};
use httun_conf::Config;
use httun_protocol::{
    Key, L7Container, Message, SequenceGenerator, SequenceType, SequenceValidator, SessionSecret,
    secure_random,
};
use httun_tun::TunHandler;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{self, AtomicU64},
    },
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, Notify},
};

const ACTIVITY_TIMEOUT_S: i64 = 30;
const L7_TIMEOUT_S: i64 = 30;

#[derive(Debug)]
struct L7State {
    pub remote: SocketAddr,
    pub stream: TcpStream,
    pub last_activity: u64,
}

impl L7State {
    pub fn new(remote: SocketAddr, stream: TcpStream) -> Self {
        Self { remote, stream, last_activity: now() }
    }
}

#[derive(Debug)]
struct PingState {
    pub notify: Notify,
    pub buf: Mutex<Vec<u8>>,
}

impl PingState {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            buf: Mutex::new(vec![]),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Session {
    pub secret: Option<SessionSecret>,
    pub sequence: u64,
}

#[derive(Debug)]
struct SessionState {
    session: Session,
    tx_sequence_a: SequenceGenerator,
    rx_validator_b: SequenceValidator,
    rx_validator_c: SequenceValidator,
}

#[derive(Debug)]
pub struct Channel {
    name: String,
    tun: TunHandler,
    key: Key,
    test_enabled: bool,
    l7state: Mutex<Option<L7State>>,
    ping: PingState,
    session: StdMutex<SessionState>,
    last_activity: AtomicU64,
}

impl Channel {
    fn new(conf: &Config, name: &str, tun: TunHandler, key: Key, test_enabled: bool) -> Self {
        let window_length = conf.parameters().receive().window_length();
        let session = SessionState {
            session: Default::default(),
            tx_sequence_a: SequenceGenerator::new(SequenceType::A),
            rx_validator_b: SequenceValidator::new(SequenceType::B, window_length),
            rx_validator_c: SequenceValidator::new(SequenceType::C, window_length),
        };
        Self {
            name: name.to_string(),
            tun,
            key,
            test_enabled,
            l7state: Mutex::new(None),
            ping: PingState::new(),
            session: StdMutex::new(session),
            last_activity: AtomicU64::new(now()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn test_enabled(&self) -> bool {
        self.test_enabled
    }

    pub fn session(&self) -> Session {
        let mut s = self.session.lock().expect("Mutex poisoned");
        s.session.sequence = s.tx_sequence_a.next();
        s.session.clone()
    }

    pub fn create_new_session(&self) -> SessionSecret {
        let session_secret: SessionSecret = secure_random();

        {
            let mut s = self.session.lock().expect("Mutex poisoned");

            s.session.sequence = u64::MAX;
            s.session.secret = Some(session_secret);
            s.tx_sequence_a.reset();
            s.rx_validator_b.reset();
            s.rx_validator_c.reset();
        }

        session_secret
    }

    pub async fn check_rx_sequence(
        &self,
        msg: &Message,
        sequence_type: SequenceType,
    ) -> ah::Result<()> {
        let mut s = self.session.lock().expect("Mutex poisoned");
        let validator = match sequence_type {
            SequenceType::B => &mut s.rx_validator_b,
            SequenceType::C => &mut s.rx_validator_c,
            t => panic!("Invalid {t:?}"),
        };
        validator
            .check_recv_seq(msg)
            .context("Message sequence validation")
    }

    pub fn log_activity(&self) {
        self.last_activity.store(now(), atomic::Ordering::Relaxed);
    }

    pub fn activity_timed_out(&self) -> bool {
        tdiff(now(), self.last_activity.load(atomic::Ordering::Relaxed)) > ACTIVITY_TIMEOUT_S
    }

    pub async fn put_ping(&self, payload: Vec<u8>) {
        *self.ping.buf.lock().await = payload;
        self.ping.notify.notify_one();
    }

    pub async fn get_pong(&self) -> Vec<u8> {
        loop {
            self.ping.notify.notified().await;

            let mut ping_buf = self.ping.buf.lock().await;
            if !ping_buf.is_empty() {
                let mut payload: Vec<u8> = "Reply to: ".to_string().into();
                payload.append(&mut *ping_buf);
                return payload;
            }
        }
    }

    pub async fn l4send(&self, data: &[u8]) -> ah::Result<()> {
        self.tun.send(data).await.context("TUN send")
    }

    pub async fn l4recv(&self) -> ah::Result<Vec<u8>> {
        self.tun.recv().await.context("TUN receive")
    }

    pub async fn l7send(&self, data: &[u8]) -> ah::Result<()> {
        let cont = L7Container::deserialize(data).context("Unpack L7 control data")?;

        let mut l7state = self.l7state.lock().await;

        fn disconnect(l7state: &mut Option<L7State>) {
            if let Some(l7state) = l7state.as_ref() {
                log::trace!("L7 disconnect from {}", l7state.remote);
            }
            *l7state = None;
        }

        if cont.payload().is_empty() {
            // Disconnect.
            disconnect(&mut l7state);
        } else {
            let mut connect = l7state.is_none();
            if let Some(l7state) = l7state.as_ref() {
                if l7state.remote != *cont.addr() {
                    connect = true;
                }
            }
            if connect {
                disconnect(&mut l7state);
                *l7state = Some(L7State::new(
                    *cont.addr(),
                    self.tun
                        .bind_and_connect_socket(cont.addr())
                        .await
                        .context("Connect L7 socket")?,
                ));
            }

            if let Some(l7state) = l7state.as_mut() {
                let _ = &l7state.stream; //TODO

                l7state.last_activity = now();
            }
        }

        Ok(())
    }

    pub async fn l7recv(&self) -> ah::Result<Vec<u8>> {
        //TODO

        //l7state.last_activity = now();
        todo!()
    }

    async fn check_l7_timeout(&self) {
        let mut timeout = false;
        let mut l7state = self.l7state.lock().await;
        if let Some(l7state) = l7state.as_mut() {
            timeout = tdiff(now(), l7state.last_activity) > L7_TIMEOUT_S;
        }
        if timeout {
            log::debug!("L7 socket timeout");
            *l7state = None;
        }
    }

    pub async fn periodic_work(&self) {
        self.check_l7_timeout().await;
    }
}

#[derive(Debug)]
pub struct Channels {
    channels: StdMutex<HashMap<String, Arc<Channel>>>,
}

impl Channels {
    pub async fn new(conf: Arc<Config>) -> ah::Result<Self> {
        let mut channels = HashMap::new();

        for chan in conf.channels_iter() {
            log::info!("Active channel: {}", chan.name());
            let tun = TunHandler::new(chan.tun().unwrap_or("httun"))
                .await
                .context("Tun interface init")?;
            let key = chan.shared_secret();
            let test_enabled = chan.enable_test();
            channels.insert(
                chan.name().to_string(),
                Arc::new(Channel::new(&conf, chan.name(), tun, key, test_enabled)),
            );
        }
        if channels.is_empty() {
            log::warn!("There are no [[channels]] configured in the configuration file!");
        }

        Ok(Self {
            channels: StdMutex::new(channels),
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<Channel>> {
        self.channels
            .lock()
            .expect("Lock poison")
            .get(name)
            .map(Arc::clone)
    }
}

// vim: ts=4 sw=4 expandtab
