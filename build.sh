#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"
. "$basedir/scripts/lib.sh"

release="both"
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            release="debug"
            ;;
        --release|-r)
            release="release"
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done

cd "$basedir" || die "cd basedir failed."
export HTTUN_CONF_PREFIX="/opt/httun"

# Debug build and test
if [ "$release" = "debug" -o "$release" = "both" ]; then
    cargo build || die "Cargo build (debug) failed."
    cargo test || die "Cargo test failed."
fi

# Release build
if [ "$release" = "release" -o "$release" = "both" ]; then
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
fi

# vim: ts=4 sw=4 expandtab
