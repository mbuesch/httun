#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ -d "$target" ] || die "httun is not built! Run ./build.sh"
    [ "$(id -u)" = "0" ] || die "Must be root to install httun."
}

install_dirs()
{
    do_install \
        -o root -g root -m 0755 \
        -d /opt/httun/bin

    do_install \
        -o root -g root -m 0755 \
        -d /opt/httun/etc

    do_install \
        -o root -g root -m 0755 \
        -d /opt/httun/lib/fcgi-bin
}

install_httun_server()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-server" \
        /opt/httun/bin/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/httun-server/httun-server.service" \
        /etc/systemd/system/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/httun-server/httun-server.socket" \
        /etc/systemd/system/

    do_systemctl enable httun-server.socket
    #do_systemctl enable httun-server.service
}

install_httun_client()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-client" \
        /opt/httun/bin/
}

install_httun_fcgi()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-fcgi" \
        /opt/httun/lib/fcgi-bin/

    do_systemctl restart apache2.service
}

release="release"
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
target="$basedir/target/$release"

entry_checks
stop_services
install_dirs
install_httun_server
install_httun_client
install_httun_fcgi
start_services

# vim: ts=4 sw=4 expandtab
