#!/bin/sh
# gfopentls.library for tools that build a directory with its own
# build-amiga.sh (AmiCradle's Cradle stove_build, target "tls"): the
# top-level build-amiga-tls.sh, with the same STOVE, CPU and OUT.
# MIT licensed and free. Copyright (c) 2026 AmiCradle Team.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$HERE/../build-amiga-tls.sh" "$@"
