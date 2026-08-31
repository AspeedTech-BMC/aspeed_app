#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -e

MBEDTLS_DIR="$1"
USER_CFG="$2"
OUTDIR="$3"
CC="$4"
AR="$5"

# CC/AR are passed in from meson so mbedtls is built with the same (possibly
# cross) toolchain as the rest of the project -- without them, make falls
# back to the build machine's native cc/ar and produces libs in the wrong
# ELF format for the target.
#
# mbedtls's own Makefile only tracks .c -> .o mtimes, so it won't notice
# CC/AR changed between runs (e.g. after a prior native-toolchain attempt,
# or when switching cptra-platform). Force a clean so every invocation
# actually reflects the CC/AR passed in, not stale objects from a previous
# toolchain.
make -C "$MBEDTLS_DIR" clean

# Pass the CFLAGS directly to make. We need the compiler to see
# -DMBEDTLS_USER_CONFIG_FILE="path/to/config.h".
# To survive the shell used by make, we need to pass \"path/to/config.h\".
make -C "$MBEDTLS_DIR" lib CC="$CC" AR="$AR" CFLAGS="-DMBEDTLS_USER_CONFIG_FILE='\"$USER_CFG\"'"

cp "$MBEDTLS_DIR"/library/*.a "$OUTDIR"/
