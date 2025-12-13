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

/// Validate received message sequence numbers.
///
/// Keeps track of a sliding window of received sequence numbers to detect
/// duplicates, old messages or replayed messages.
#[derive(Debug)]
pub struct SequenceValidator {
    /// The length of the sliding window.
    win_len: NonZeroUsize,
    /// The set of received sequence numbers within the sliding window.
    rx_seq: BTreeSet<u64>,
    /// The expected sequence number flags.
    /// Corresponds to the sequence type.
    expected_flags: u64,
}

impl SequenceValidator {
    /// Create a new sequence validator for the given sequence type and window length.
    pub fn new(ty: SequenceType, win_len: NonZeroUsize) -> Self {
        Self {
            win_len,
            rx_seq: BTreeSet::new(),
            expected_flags: ty.to_flags(),
        }
    }

    /// Reset the sequence validator.
    pub fn reset(&mut self) {
        self.rx_seq.clear();
    }

    /// Check the sequence number of a received message.
    ///
    /// Returns an error if the message is invalid.
    pub fn check_recv_seq(&mut self, msg: &Message) -> ah::Result<()> {
        let sequence = msg.sequence();

        // Check the sequence flags.
        // They must match the expected flags for this sequence type.
        if sequence & SequenceGenerator::SEQ_FLAGS_MASK != self.expected_flags {
            return Err(err!("Unexpected message sequence flags."));
        }
        let sequence = sequence & SequenceGenerator::SEQ_MASK;

        // Get the oldest sequence number in the window.
        let oldest_seq = self.rx_seq.first().copied();

        // Check if the message is older than the oldest sequence in the window.
        if let Some(oldest_seq) = oldest_seq
            && sequence <= oldest_seq
        {
            return Err(err!("Message is too old: {sequence} <= {oldest_seq}."));
        }

        // Check for duplicate/replayed messages.
        if self.rx_seq.contains(&sequence) {
            return Err(err!("Message has already been received."));
        }

        // Insert the sequence number into the sliding window.
        self.rx_seq.insert(sequence);

        // Remove the oldest sequence number if the window is full.
        if let Some(oldest_seq) = oldest_seq
            && self.rx_seq.len() > self.win_len.into()
        {
            self.rx_seq.remove(&oldest_seq);
        }
        assert!(self.rx_seq.len() <= self.win_len.into());

        Ok(())
    }
}

/// The sequence type.
/// Different sequence types are guaranteed to always generate different sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceType {
    A,
    B,
    C,
    D,
}

impl SequenceType {
    /// Convert the sequence type to the corresponding sequence number flags.
    pub fn to_flags(&self) -> u64 {
        match self {
            SequenceType::A => 0,
            SequenceType::B => SequenceGenerator::SEQ_FLAG0,
            SequenceType::C => SequenceGenerator::SEQ_FLAG1,
            SequenceType::D => SequenceGenerator::SEQ_FLAG1 | SequenceGenerator::SEQ_FLAG0,
        }
    }
}

/// Generate httun message sequence numbers with embedded sequence type flags.
#[derive(Debug)]
pub struct SequenceGenerator {
    /// The current sequence number.
    seq: AtomicU64,
}

impl SequenceGenerator {
    const SEQ_FLAG0: u64 = 1 << 62;
    const SEQ_FLAG1: u64 = 1 << 63;
    const SEQ_FLAGS_MASK: u64 = Self::SEQ_FLAG0 | Self::SEQ_FLAG1;
    const SEQ_MASK: u64 = !Self::SEQ_FLAGS_MASK;

    /// Create a new sequence generator for the given sequence type.
    pub fn new(ty: SequenceType) -> Self {
        Self {
            seq: AtomicU64::new(ty.to_flags()),
        }
    }

    /// Reset the sequence number to zero.
    pub fn reset(&self) {
        let _ = self
            .seq
            .fetch_and(Self::SEQ_FLAGS_MASK, atomic::Ordering::Relaxed);
    }

    /// Get the next sequence number.
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
