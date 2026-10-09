# -*- coding: utf-8 -*-
set -e
basedir="$(dirname "$(realpath "$0")")"

#export HTTUN_LOG=debug

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

opt_release="debug"
opt_minimal=0
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            opt_release="debug"
            ;;
        --release|-r)
            opt_release="release"
            ;;
        --minimal)
            opt_minimal=1
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done

target_dir="$basedir/../../target/$opt_release"

if [ "$(id -u)" = "0" ]; then
    is_root=1
else
    is_root=0
fi

skip_if_root()
{
    if [ "$is_root" -ne 0 ]; then
        info "Skipping the test because it is running as root."
        exit 0
    fi
}

skip_if_not_root()
{
    if [ "$is_root" -eq 0 ]; then
        info "Skipping the test because it is not running as root."
        exit 0
    fi
}

skip_if_minimal()
{
    if [ "$opt_minimal" -ne 0 ]; then
        info "Skipping the test because it is running in minimal mode."
        exit 0
    fi
}

# vim: ts=4 sw=4 expandtab
