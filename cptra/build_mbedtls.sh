#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -e

MBEDTLS_DIR="$1"
USER_CFG="$2"
OUTDIR="$3"

# Pass the CFLAGS directly to make. We need the compiler to see
# -DMBEDTLS_USER_CONFIG_FILE="path/to/config.h".
# To survive the shell used by make, we need to pass \"path/to/config.h\".
make -C "$MBEDTLS_DIR" lib CFLAGS="-DMBEDTLS_USER_CONFIG_FILE='\"$USER_CFG\"'"

cp "$MBEDTLS_DIR"/library/*.a "$OUTDIR"/
