#!/bin/sh
export CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift
exec cargo +nightly build -Zcodegen-backend
