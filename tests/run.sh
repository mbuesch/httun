#!/bin/sh
# -*- coding: utf-8 -*-
set -e
basedir="$(realpath "$0" | xargs dirname)"

for d in "$basedir"/*; do
    if [ -d "$d" ] && [ -x "$d/run.sh" ]; then
        echo "Testcase: $(basename "$d")"
        "$d/run.sh" "$@" || exit 1
        echo ""
    fi
done

# vim: ts=4 sw=4 expandtab
