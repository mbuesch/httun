// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use crate::Message;
use anyhow::{self as ah, format_err as err};
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::atomic::{self, AtomicU64},
};

#[derive(Debug)]
pub struct SequenceValidator {
    win_len: NonZeroUsize,
    rx_seq: BTreeSet<u64>,
    expected_flags: u64,
}

impl SequenceValidator {
    pub fn new(ty: SequenceType, win_len: NonZeroUsize) -> Self {
        Self {
            win_len,
            rx_seq: BTreeSet::new(),
            expected_flags: ty.to_flags(),
        }
    }

    pub fn reset(&mut self) {
        self.rx_seq.clear();
    }

    pub fn check_recv_seq(&mut self, msg: &Message) -> ah::Result<()> {
        let sequence = msg.sequence();

        if sequence & SequenceGenerator::SEQ_FLAGS_MASK != self.expected_flags {
            return Err(err!("Unexpected message sequence flags."));
        }
        let sequence = sequence & SequenceGenerator::SEQ_MASK;

        let oldest_seq = self.rx_seq.first().copied();

        if let Some(oldest_seq) = oldest_seq {
            if sequence <= oldest_seq {
                return Err(err!("Message is too old: {sequence} <= {oldest_seq}."));
            }
        }
        if self.rx_seq.contains(&sequence) {
            return Err(err!("Message has already been received."));
        }

        self.rx_seq.insert(sequence);

        if let Some(oldest_seq) = oldest_seq {
            if self.rx_seq.len() > self.win_len.into() {
                self.rx_seq.remove(&oldest_seq);
            }
        }
        debug_assert!(self.rx_seq.len() <= self.win_len.into());

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceType {
    A,
    B,
    C,
    D,
}

impl SequenceType {
    pub fn to_flags(&self) -> u64 {
        match self {
            SequenceType::A => 0,
            SequenceType::B => SequenceGenerator::SEQ_FLAG0,
            SequenceType::C => SequenceGenerator::SEQ_FLAG1,
            SequenceType::D => SequenceGenerator::SEQ_FLAG1 | SequenceGenerator::SEQ_FLAG0,
        }
    }
}

#[derive(Debug)]
pub struct SequenceGenerator {
    seq: AtomicU64,
}

impl SequenceGenerator {
    const SEQ_FLAG0: u64 = 1 << 62;
    const SEQ_FLAG1: u64 = 1 << 63;
    const SEQ_FLAGS_MASK: u64 = Self::SEQ_FLAG0 | Self::SEQ_FLAG1;
    const SEQ_MASK: u64 = !Self::SEQ_FLAGS_MASK;

    pub fn new(ty: SequenceType) -> Self {
        Self {
            seq: AtomicU64::new(ty.to_flags()),
        }
    }

    pub fn reset(&self) {
        let _ = self
            .seq
            .fetch_and(Self::SEQ_FLAGS_MASK, atomic::Ordering::Relaxed);
    }

    pub fn next(&self) -> u64 {
        let seq = self.seq.fetch_add(1, atomic::Ordering::Relaxed);

        // Abort the program if we reached the maximum and clobbered the flags.
        // In practice this is not reachable.
        // The sequence starts from zero, so we have 2^62 packets until this assertion hits.
        assert_ne!(seq & Self::SEQ_MASK, Self::SEQ_MASK);

        seq
    }
}

// vim: ts=4 sw=4 expandtab
