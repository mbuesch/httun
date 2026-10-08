#!/bin/sh
# -*- coding: utf-8 -*-
set -e

export HTTUN_CONF_PREFIX="/opt/httun"
export CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift
if [ $# -ge 1 ]; then
    exec cargo +nightly "$@" -Zcodegen-backend
else
    exec cargo +nightly build -Zcodegen-backend
fi

# vim: ts=4 sw=4 expandtab
