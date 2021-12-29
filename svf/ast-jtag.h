/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "stdint.h"
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef unsigned long long __u64;

#include "jtag.h"

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_PER_BYTE 8
/******************************************************************************************************************/
int ast_jtag_open(char *dev);
void ast_jtag_close(void);
int ast_set_jtag_mode(uint8_t sw_mode);
unsigned int ast_get_jtag_freq(void);
int ast_set_jtag_freq(unsigned int freq);
int ast_jtag_run_test_idle(unsigned char end, unsigned int tck);
int ast_jtag_xfer(unsigned char endsts, unsigned int len, unsigned int *out, unsigned int *in, enum jtag_xfer_type type);