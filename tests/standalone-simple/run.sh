#!/bin/sh
# -*- coding: utf-8 -*-
set -e
basedir="$(realpath "$0" | xargs dirname)"

#export HTTUN_LOG=debug

httpserver_pid=
server_pid=

cleanup()
{
    if [ -n "$httpserver_pid" ]; then
        kill "$httpserver_pid"
        httpserver_pid=
    fi
    if [ -n "$server_pid" ]; then
        kill "$server_pid"
        server_pid=
    fi
}

cleanup_and_exit()
{
    cleanup
    exit 1
}

trap cleanup_and_exit INT TERM
trap cleanup EXIT

release="debug"
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            release="debug"
            ;;
        --release|-r)
            release="release"
            ;;
        --full)
            ;;
        --minimal)
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done
target="$basedir/../../target/$release"

echo "Starting servers..."

rm -f "$basedir/httun-server.sock"

"$target/httun-httpserver" \
    --config "$basedir/httun.conf" \
    --unix-socket "$basedir/httun-server.sock" \
    --listen localhost:8090 \
    &
httpserver_pid=$!

"$target/httun-server" \
    --config "$basedir/httun.conf" \
    --unix-socket "$basedir/httun-server.sock" \
    --no-drop-root \
    --no-webserver-cred-check \
    &
server_pid=$!

sleep 1

echo "Running the test..."

"$target/httun-client" \
    --config "$basedir/httun.conf" \
    --alias local \
    http://localhost:8090 \
    test \
    --duration 3.0

echo "Exiting..."
cleanup
wait
rm -f "$basedir/httun-server.sock"

# vim: ts=4 sw=4 expandtab
