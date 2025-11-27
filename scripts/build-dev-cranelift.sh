#!/bin/sh
export HTTUN_CONF_PREFIX="/opt/httun"
export CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift
exec cargo +nightly build -Zcodegen-backend
