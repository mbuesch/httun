#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ "$(id -u)" = "0" ] || die "Must be root to create users."
}

sys_groupadd()
{
    local args="--system"
    info "groupadd $args $*"
    groupadd $args "$@" || die "Failed groupadd"
}

sys_useradd()
{
    local args="--system -s /usr/sbin/nologin -d /nonexistent -M -N"
    info "useradd $args $*"
    useradd $args "$@" || die "Failed useradd"
}

do_usermod()
{
    info "usermod $*"
    usermod "$@" || die "Failed usermod"
}

stop_daemons()
{
    systemctl stop httun-server.socket >/dev/null 2>&1
    systemctl stop httun-server.service >/dev/null 2>&1
}

remove_users()
{
    # Delete all existing users and groups, if any.
    userdel httun >/dev/null 2>&1
    groupdel httun >/dev/null 2>&1
}

add_users()
{
    sys_groupadd httun
    sys_useradd -g httun httun
}

entry_checks
stop_daemons
remove_users
add_users

# vim: ts=4 sw=4 expandtab
