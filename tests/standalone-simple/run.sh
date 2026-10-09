#!/bin/sh
# -*- coding: utf-8 -*-
set -e
basedir="$(dirname "$(realpath "$0")")"
. "$basedir/../testlib.sh"

skip_if_root

info "Starting servers..."

rm -f "$basedir/httun-server.sock"

"$target_dir/httun-httpserver" \
    --config "$basedir/httun.conf" \
    --unix-socket "$basedir/httun-server.sock" \
    --listen localhost:8090 \
    &
httpserver_pid=$!

"$target_dir/httun-server" \
    --config "$basedir/httun.conf" \
    --unix-socket "$basedir/httun-server.sock" \
    --no-drop-root \
    --no-webserver-cred-check \
    &
server_pid=$!

sleep 1

info "Running the test..."

"$target_dir/httun-client" \
    --config "$basedir/httun.conf" \
    --alias local \
    http://localhost:8090 \
    test \
    --duration 3.0

info "Exiting..."
cleanup
wait
rm -f "$basedir/httun-server.sock"

# vim: ts=4 sw=4 expandtab
