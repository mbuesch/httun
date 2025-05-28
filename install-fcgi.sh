#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

install_httun_fcgi()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-fcgi" \
        /opt/httun/lib/fcgi-bin/

    try_systemctl restart apache2.service
    try_systemctl restart lighttpd.service
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

install_entry_checks
stop_services fcgi
install_dirs
install_httun_server fcgi
install_httun_client
install_httun_fcgi
start_services fcgi

# vim: ts=4 sw=4 expandtab
