// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use memchr::memchr;
use std::fmt::Write as _;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    R,
    W,
}

fn path_is_valid(path: &[u8]) -> bool {
    path.iter()
        .all(|c| c.is_ascii_alphanumeric() || [b'-', b'_', b'/'].contains(c))
}

pub fn next_path_comp(mut path: &[u8]) -> Option<(&[u8], &[u8])> {
    loop {
        if path.is_empty() {
            break None;
        }
        if let Some(p) = memchr(b'/', path) {
            let (l, r) = path.split_at(p);
            path = &r[1..];
            if !l.is_empty() {
                break Some((l, path));
            }
        } else {
            break Some((path, &path[path.len()..path.len()]));
        }
    }
}

pub fn parse_path(path: &[u8]) -> ah::Result<(String, Direction)> {
    if !path_is_valid(path) {
        return Err(err!("Invalid characters in path."));
    }

    let Some((chan_name, tail)) = next_path_comp(path) else {
        return Err(err!("1st path component is missing."));
    };
    let Some((direction, tail)) = next_path_comp(tail) else {
        return Err(err!("2nd path component is missing."));
    };
    let Some((_serial, tail)) = next_path_comp(tail) else {
        return Err(err!("3rd path component is missing."));
    };
    if next_path_comp(tail).is_some() {
        return Err(err!("Got trailing garbage in path."));
    }

    let chan_name = String::from_utf8(chan_name.to_vec())?;
    let direction = match direction {
        b"r" => Direction::R,
        b"w" => Direction::W,
        _ => {
            return Err(err!("Unknown direction in path."));
        }
    };

    Ok((chan_name, direction))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02X}").expect("write! on String failed");
    }
    s
}

// vim: ts=4 sw=4 expandtab
