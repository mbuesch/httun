#!/bin/sh
# -*- coding: utf-8 -*-

srcdir="$(dirname "$(realpath "$0")")"
srcdir="$srcdir/.."

# Import the makerelease.lib
# https://bues.ch/cgit/misc.git/tree/makerelease.lib
die() { echo "$*"; exit 1; }
for path in $(echo "$PATH" | tr ':' ' '); do
    [ -f "$MAKERELEASE_LIB" ] && break
    MAKERELEASE_LIB="$path/makerelease.lib"
done
[ -f "$MAKERELEASE_LIB" ] && . "$MAKERELEASE_LIB" || die "makerelease.lib not found."

hook_get_version()
{
    version="$(cargo_local_pkg_version httun-server)"
}

hook_regression_tests()
{
    default_hook_regression_tests "$@"

    sh "$1"/tests/run.sh
}

project=httun
conf_noupload=1
makerelease "$@"

# vim: ts=4 sw=4 expandtab
