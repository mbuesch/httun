// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::strings::split_delim;
use anyhow::{self as ah, format_err as err};
use std::collections::HashMap;

/// Maximum number of components in a query string.
const MAX_NR_COMP: usize = 8;

/// A query string.
#[derive(Debug, Clone)]
pub struct Query {
    comps: HashMap<Vec<u8>, Vec<u8>>,
}

impl Query {
    /// Returns the value of a query component, by name.
    /// Returns `None` if the component does not exist.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.comps.get(name).map(|v| &**v)
    }
}

impl TryFrom<&[u8]> for Query {
    type Error = ah::Error;

    /// Parses a query string.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut comps = HashMap::with_capacity(MAX_NR_COMP);
        let data = split_delim(data, b'#').unwrap_or((data, &[])).0;
        let mut tail = data.trim_ascii();
        while !tail.is_empty() {
            let (comp, t) = split_delim(tail, b'&').unwrap_or((tail, &[]));
            tail = t;
            if !comp.is_empty() {
                let Some((name, value)) = split_delim(comp, b'=') else {
                    return Err(err!("Invalid query string: No name/value separator."));
                };
                let name = name.trim_ascii();
                let value = value.trim_ascii();
                if name.is_empty() {
                    return Err(err!("Invalid query string: No name."));
                }
                if comps.len() >= MAX_NR_COMP {
                    return Err(err!("Invalid query string: Too many components."));
                }
                comps.insert(name.to_vec(), value.to_vec());
            }
        }
        Ok(Self { comps })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_query() {
        let a = b" ";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert!(b.comps.is_empty());

        let a = b"m=foo";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert_eq!(b.get(b"m").unwrap(), b"foo");

        let a = b"m=x&b=c";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert_eq!(b.get(b"m").unwrap(), b"x");
        assert_eq!(b.get(b"b").unwrap(), b"c");

        let a = b" m=x&b=c ";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert_eq!(b.get(b"m").unwrap(), b"x");
        assert_eq!(b.get(b"b").unwrap(), b"c");

        let a = b" m = x & b = c ";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert_eq!(b.get(b"m").unwrap(), b"x");
        assert_eq!(b.get(b"b").unwrap(), b"c");

        let a = b"m&b=c";
        let b: Result<Query, _> = a.as_slice().try_into();
        assert!(b.is_err());

        let a = b"=x&b=c";
        let b: Result<Query, _> = a.as_slice().try_into();
        assert!(b.is_err());

        let a = b"m=x#b=c";
        let b: Result<Query, _> = a.as_slice().try_into();
        let b = b.unwrap();
        assert_eq!(b.get(b"m").unwrap(), b"x");
        assert!(b.get(b"b").is_none());
    }
}

// vim: ts=4 sw=4 expandtab
