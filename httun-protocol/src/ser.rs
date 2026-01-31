// -*- coding: utf-8 -*-
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2025 Michael Büsch <m@bues.ch>

use anyhow::{self as ah, format_err as err};
use std::ops::Range;

/// Simple serializer helper.
pub struct Ser {
    buf: Vec<u8>,
    size: usize,
}

impl Ser {
    #[inline]
    pub fn new_fixed_size(size: usize) -> Self {
        Self {
            buf: Vec::with_capacity(size),
            size,
        }
    }

    #[inline]
    pub fn push(&mut self, data: &[u8]) -> ah::Result<()> {
        self.buf
            .len()
            .checked_add(data.len())
            .filter(|newlen| *newlen <= self.size)
            .ok_or_else(|| err!("Ser: Overflow"))?;
        self.buf.extend(data);
        Ok(())
    }

    #[inline]
    pub fn push_u8(&mut self, data: u8) -> ah::Result<()> {
        self.push(&data.to_be_bytes())
    }

    #[inline]
    pub fn push_u16(&mut self, data: u16) -> ah::Result<()> {
        self.push(&data.to_be_bytes())
    }

    #[inline]
    pub fn push_u64(&mut self, data: u64) -> ah::Result<()> {
        self.push(&data.to_be_bytes())
    }

    #[inline]
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    #[inline]
    pub fn into_vec(self) -> ah::Result<Vec<u8>> {
        if self.buf.len() == self.size {
            Ok(self.buf)
        } else {
            Err(err!("Ser: Buffer was not completely filled up."))
        }
    }
}

/// Simple deserializer helper.
pub struct De<'a> {
    buf: &'a [u8],
    range: Range<usize>,
}

impl<'a> De<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            range: 0..buf.len(),
        }
    }

    #[inline]
    pub fn new_min_max(buf: &'a [u8], min_len: usize, max_len: usize) -> ah::Result<Self> {
        if buf.len() < min_len {
            return Err(err!("De: Input data size is too small."));
        }
        if buf.len() > max_len {
            return Err(err!("De: Input data size is too large."));
        }
        Ok(Self::new(buf))
    }

    #[inline]
    pub fn new_fixed_size(buf: &'a [u8], expected_len: usize) -> ah::Result<Self> {
        Self::new_min_max(buf, expected_len, expected_len)
    }

    #[inline]
    pub fn pop(&mut self, len: usize) -> ah::Result<&'a [u8]> {
        let end = self
            .range
            .start
            .checked_add(len)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| err!("De: Overflow."))?;

        let slice = &self.buf[self.range.start..end];
        self.range.start = end;

        Ok(slice)
    }

    #[inline]
    pub fn pop_array<const SIZE: usize>(&mut self) -> ah::Result<[u8; SIZE]> {
        self.pop(SIZE).and_then(|v| Ok(v.try_into()?))
    }

    #[inline]
    pub fn pop_u8(&mut self) -> ah::Result<u8> {
        self.pop(u8::BITS as usize / 8)
            .and_then(|v| Ok(u8::from_be_bytes(v.try_into()?)))
    }

    #[inline]
    pub fn pop_u16(&mut self) -> ah::Result<u16> {
        self.pop(u16::BITS as usize / 8)
            .and_then(|v| Ok(u16::from_be_bytes(v.try_into()?)))
    }

    #[inline]
    pub fn pop_u64(&mut self) -> ah::Result<u64> {
        self.pop(u64::BITS as usize / 8)
            .and_then(|v| Ok(u64::from_be_bytes(v.try_into()?)))
    }

    #[inline]
    pub fn pop_back(&mut self, len: usize) -> ah::Result<&[u8]> {
        let begin = self
            .range
            .end
            .checked_sub(len)
            .filter(|begin| *begin >= self.range.start)
            .ok_or_else(|| err!("De: Underflow."))?;

        let slice = &self.buf[begin..self.range.end];
        self.range.end = begin;

        Ok(slice)
    }

    #[inline]
    pub fn pop_back_array<const SIZE: usize>(&mut self) -> ah::Result<[u8; SIZE]> {
        self.pop_back(SIZE).and_then(|v| Ok(v.try_into()?))
    }

    #[inline]
    pub fn into_remaining_range(self) -> Range<usize> {
        self.range
    }

    #[inline]
    pub fn suspend(self) -> DeSuspended {
        DeSuspended {
            range: self.into_remaining_range(),
        }
    }
}

pub struct DeSuspended {
    range: Range<usize>,
}

impl DeSuspended {
    #[inline]
    pub fn resume(self, buf: &[u8]) -> De<'_> {
        De {
            buf,
            range: self.range,
        }
    }
}

// vim: ts=4 sw=4 expandtab
