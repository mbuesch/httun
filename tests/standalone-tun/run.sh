#!/bin/sh
# -*- coding: utf-8 -*-
set -e

is_inner=0
if [ "${1:-}" = "--inside-userns" ]; then
    is_inner=1
    shift
fi

basedir="$(dirname "$(realpath "$0")")"

# shellcheck source=tests/testlib.sh
. "$basedir/../testlib.sh"

if [ "$is_inner" -eq 0 ]; then
    skip_if_root
    skip_if_minimal

    for command in unshare nsenter ip ping; do
        command -v "$command" >/dev/null 2>&1 ||
            die "Required command not found: $command"
    done
    [ -c /dev/net/tun ] || die "/dev/net/tun is not available"

    if ! unshare --user --map-root-user --net true; then
        die "Rootless user and network namespaces are not available"
    fi

    exec unshare --user --map-root-user --net \
        "$basedir/run.sh" --inside-userns "--$opt_release"
fi

server_ns_pid=
client_ns_pid=
client_pid=
socket="$basedir/httun-server.sock"

cleanup()
{
    if [ -n "$client_pid" ]; then
        kill "$client_pid" 2>/dev/null || true
        client_pid=
    fi
    if [ -n "$httpserver_pid" ]; then
        kill "$httpserver_pid" 2>/dev/null || true
        httpserver_pid=
    fi
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        server_pid=
    fi
    if [ -n "$server_ns_pid" ]; then
        kill "$server_ns_pid" 2>/dev/null || true
        server_ns_pid=
    fi
    if [ -n "$client_ns_pid" ]; then
        kill "$client_ns_pid" 2>/dev/null || true
        client_ns_pid=
    fi
    rm -f "$socket"
}

wait_for_namespace()
{
    pid=$1
    count=0
    while ! nsenter -t "$pid" -n true 2>/dev/null; do
        count=$((count + 1))
        [ "$count" -lt 100 ] || die "Network namespace for PID $pid did not start"
        sleep 0.05
    done
}

wait_for_link()
{
    pid=$1
    interface=$2
    owner_pid=$3
    count=0
    while ! nsenter -t "$pid" -n ip link show "$interface" >/dev/null 2>&1; do
        kill -0 "$owner_pid" 2>/dev/null || die "Process $owner_pid exited before creating $interface"
        count=$((count + 1))
        [ "$count" -lt 200 ] || die "TUN interface $interface was not created"
        sleep 0.05
    done
}

info "Creating private network namespaces..."

unshare --net sleep 300 &
server_ns_pid=$!
unshare --net sleep 300 &
client_ns_pid=$!

wait_for_namespace "$server_ns_pid"
wait_for_namespace "$client_ns_pid"

ip link add httun-test-s type veth peer name httun-test-c
ip link set httun-test-s netns "$server_ns_pid"
ip link set httun-test-c netns "$client_ns_pid"

nsenter -t "$server_ns_pid" -n sh -euc '
    ip link set lo up
    ip addr add 172.31.0.1/30 dev httun-test-s
    ip link set httun-test-s up
'
nsenter -t "$client_ns_pid" -n sh -euc '
    ip link set lo up
    ip addr add 172.31.0.2/30 dev httun-test-c
    ip link set httun-test-c up
'

info "Starting standalone servers..."

rm -f "$socket"

nsenter -t "$server_ns_pid" -n \
    "$target_dir/httun-httpserver" \
    --config "$basedir/httun.conf" \
    --unix-socket "$socket" \
    --listen 172.31.0.1:8090 \
    &
httpserver_pid=$!

nsenter -t "$server_ns_pid" -n \
    "$target_dir/httun-server" \
    --config "$basedir/httun.conf" \
    --unix-socket "$socket" \
    --no-drop-root \
    --no-webserver-cred-check \
    &
server_pid=$!

wait_for_link "$server_ns_pid" httun-s-0 "$server_pid"
nsenter -t "$server_ns_pid" -n \
    ip addr add 10.99.99.1/30 dev httun-s-0

info "Starting the TUN client..."

nsenter -t "$client_ns_pid" -n \
    "$target_dir/httun-client" \
    --config "$basedir/httun.conf" \
    --alias local \
    http://172.31.0.1:8090 \
    tun --tun httun-c-0 \
    &
client_pid=$!

wait_for_link "$client_ns_pid" httun-c-0 "$client_pid"
nsenter -t "$client_ns_pid" -n \
    ip addr add 10.99.99.2/30 dev httun-c-0

info "Testing the TUN channel..."

nsenter -t "$client_ns_pid" -n \
    ping -i 0.1 -c 15 -W 3 10.99.99.1

info "Exiting..."
cleanup
wait

# vim: ts=4 sw=4 expandtab
