/* SPDX-License-Identifier: GPL-2.0 */
//
// mctp-echo: MCTP echo server, for testing.
//
// Copyright (c) 2021 Code Construct
// Copyright (c) 2021 Google

#include <stdint.h>
#include <stdlib.h>
#include "mctp.h"

void mctp_hexdump(const void *b, int len, const char *indent);
void print_hex_addr(const u8 *data, size_t len);
int write_hex_addr(const u8 *data, size_t len, char *dest, size_t dest_len);
int parse_hex_addr(const char *in, u8 *out, size_t *out_len);
int parse_uint32(const char *str, u32 *out);
int parse_int32(const char *str, s32 *out);
/* Returns a malloced pointer */
char *bytes_to_uuid(const u8 u[16]);
