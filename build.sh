#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"

cd "$basedir" || die "cd basedir failed."
export HTTUN_CONF_PREFIX="/opt/httun"
cargo build || die "Cargo build (debug) failed."
cargo test || die "Cargo test failed."
if which cargo-auditable >/dev/null 2>&1; then
    cargo auditable build --release || die "Cargo build (release) failed."
    cargo audit --deny warnings bin \
        target/release/httun-client \
        target/release/httun-fcgi \
        target/release/httun-server \
        || die "Cargo audit failed."
else
    cargo build --release || die "Cargo build (release) failed."
fi

# vim: ts=4 sw=4 expandtab
