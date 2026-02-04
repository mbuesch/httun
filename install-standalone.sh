#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

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

install_entry_checks server
stop_services
disable_services
install_dirs
install_httun_server
do_systemctl daemon-reload
enable_services_standalone
start_services_standalone

# vim: ts=4 sw=4 expandtab
