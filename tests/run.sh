#!/bin/sh
# -*- coding: utf-8 -*-
set -e
basedir="$(dirname "$(realpath "$0")")"

for d in "$basedir"/*; do
    if [ -d "$d" ] && [ -x "$d/run.sh" ]; then
        echo "Testcase: $(basename "$d")"
        if ! "$d/run.sh" "$@" ; then
            echo "Testcase FAILED: $(basename "$d")" >&2
            exit 1
        fi
        echo ""
    fi
done

# vim: ts=4 sw=4 expandtab
