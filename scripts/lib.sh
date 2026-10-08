# shellcheck shell=sh

info()
{
    echo "--- $*"
}

error()
{
    echo "=== ERROR: $*" >&2
}

warning()
{
    echo "=== WARNING: $*" >&2
}

die()
{
    error "$*"
    exit 1
}

do_install()
{
    info "install $*"
    install "$@" || die "Failed install $*"
}

do_systemctl()
{
    info "systemctl $*"
    systemctl "$@" || die "Failed to systemctl $*"
}

do_chown()
{
    info "chown $*"
    chown "$@" || die "Failed to chown $*"
}

do_chmod()
{
    info "chmod $*"
    chmod "$@" || die "Failed to chmod $*"
}

try_systemctl()
{
    info "systemctl $*"
    systemctl "$@" 2>/dev/null
}

stop_services()
{
    try_systemctl stop httun-server.socket
    try_systemctl stop httun-server.service
    try_systemctl stop httun-httpserver.service
}

disable_services()
{
    try_systemctl disable httun-server.service
    try_systemctl disable httun-server.socket
    try_systemctl disable httun-httpserver.service
}

enable_services_fcgi()
{
    do_systemctl enable httun-server.socket
}

enable_services_standalone()
{
    do_systemctl enable httun-server.socket
    do_systemctl enable httun-httpserver.service
}

start_services_fcgi()
{
    try_systemctl restart apache2.service
    try_systemctl restart lighttpd.service
    do_systemctl start httun-server.socket
    do_systemctl start httun-server.service
}

start_services_standalone()
{
    do_systemctl start httun-server.socket
    do_systemctl start httun-server.service
    do_systemctl start httun-httpserver.service
}

install_entry_checks()
{
    local mode="$1"

    [ -d "$target" ] || die "httun is not built! Run ./build.sh"
    [ "$(id -u)" = "0" ] || die "Must be root to install httun."

    if [ "$mode" = "server" ]; then
        if ! grep -qe '^httun:' /etc/passwd; then
            die "The system user 'httun' does not exist in /etc/passwd. Please run ./create-user.sh"
        fi
        if ! grep -qe '^httun:' /etc/group; then
            die "The system group 'httun' does not exist in /etc/group. Please run ./create-user.sh"
        fi
    fi
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
        -d /opt/httun/etc/httun

    do_install \
        -o root -g root -m 0755 \
        -d /opt/httun/lib/fcgi-bin
}

install_httun_server()
{
    # server.conf
    if [ -e /opt/httun/etc/httun/server.conf ]; then
        do_chown root:root /opt/httun/etc/httun/server.conf
        do_chmod 0640 /opt/httun/etc/httun/server.conf
    else
        do_install \
            -o root -g root -m 0640 \
            "$basedir/httun-server/server.conf" \
            /opt/httun/etc/httun/server.conf

        info "Re-generate the UUID"
        local new_uuid="$("$target/httun-client" gen-uuid)"
        [ -n "$new_uuid" ] || die "httun-client gen-uuid failed"
        sed -i "s|^uuid = .*|$new_uuid|" \
            /opt/httun/etc/httun/server.conf \
            || die "Failed to replace uuid in server.conf"
    fi

    # server-start-pre.sh
    if [ -e /opt/httun/etc/httun/server-start-pre.sh ]; then
        do_chown root:root /opt/httun/etc/httun/server-start-pre.sh
        do_chmod 0750 /opt/httun/etc/httun/server-start-pre.sh
    else
        do_install \
            -o root -g root -m 0750 \
            "$basedir/httun-server/server-start-pre.sh" \
            /opt/httun/etc/httun/server-start-pre.sh
    fi

    # server-start-post.sh
    if [ -e /opt/httun/etc/httun/server-start-post.sh ]; then
        do_chown root:root /opt/httun/etc/httun/server-start-post.sh
        do_chmod 0750 /opt/httun/etc/httun/server-start-post.sh
    else
        do_install \
            -o root -g root -m 0750 \
            "$basedir/httun-server/server-start-post.sh" \
            /opt/httun/etc/httun/server-start-post.sh
    fi

    # http-server-start-pre.sh
    if [ -e /opt/httun/etc/httun/http-server-start-pre.sh ]; then
        do_chown root:root /opt/httun/etc/httun/http-server-start-pre.sh
        do_chmod 0750 /opt/httun/etc/httun/http-server-start-pre.sh
    else
        do_install \
            -o root -g root -m 0750 \
            "$basedir/httun-httpserver/http-server-start-pre.sh" \
            /opt/httun/etc/httun/http-server-start-pre.sh
    fi

    # http-server-start-post.sh
    if [ -e /opt/httun/etc/httun/http-server-start-post.sh ]; then
        do_chown root:root /opt/httun/etc/httun/http-server-start-post.sh
        do_chmod 0750 /opt/httun/etc/httun/http-server-start-post.sh
    else
        do_install \
            -o root -g root -m 0750 \
            "$basedir/httun-httpserver/http-server-start-post.sh" \
            /opt/httun/etc/httun/http-server-start-post.sh
    fi

    # httun-server binary
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-server" \
        /opt/httun/bin/

    # httun-httpserver binary
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-httpserver" \
        /opt/httun/bin/

    # httun-fcgi binary
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-fcgi" \
        /opt/httun/lib/fcgi-bin/

    # httun-server.service
    do_install \
        -o root -g root -m 0644 \
        "$basedir/httun-server/httun-server.service" \
        /etc/systemd/system/

    # httun-server.socket
    do_install \
        -o root -g root -m 0644 \
        "$basedir/httun-server/httun-server.socket" \
        /etc/systemd/system/

    # httun-httpserver.service
    do_install \
        -o root -g root -m 0644 \
        "$basedir/httun-httpserver/httun-httpserver.service" \
        /etc/systemd/system/
}

install_httun_client()
{
    # client.conf
    if [ -e /opt/httun/etc/httun/client.conf ]; then
        do_chown root:root /opt/httun/etc/httun/client.conf
        do_chmod 0644 /opt/httun/etc/httun/client.conf
    else
        do_install \
            -o root -g root -m 0644 \
            "$basedir/httun-client/client.conf" \
            /opt/httun/etc/httun/client.conf
    fi

    # httun-client binary
    do_install \
        -o root -g root -m 0755 \
        "$target/httun-client" \
        /opt/httun/bin/
}

# vim: ts=4 sw=4 expandtab
