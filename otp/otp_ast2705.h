/* SPDX-License-Identifier: GPL-2.0 */

#ifndef OTP_AST2705_H
#define OTP_AST2705_H

#include <stdint.h>
#include "utils.h"

/*
 * AST2705 OTP memory map (unit: Double Word 32-bits)
 *
 * Region    Start    End      Size(DW)
 * OTPROM    0x000    0x8FF    2304
 * OTPRBP    0x900    0x90F    16
 * OTPCFG    0x910    0x94F    64
 * OTPUSR    0x950    0xF4F    1536
 * OTPSEC    0xF50    0xFDF    144
 * OTPSTRAP  0xFE0    0xFEF    16
 * OTPCTRL   0xFF0    0xFFF    16
 */

#define ROM_REGION_START		0x000
#define ROM_REGION_END			0x900
#define RBP_REGION_START		0x900
#define RBP_REGION_END			0x910
#define CFG_REGION_START		0x910
#define CFG_REGION_END			0x950
#define USR_REGION_START		0x950
#define USR_REGION_END			0xF50
#define SEC_REGION_START		0xF50
#define SEC_REGION_END			0xFE0
#define STRAP_REGION_START		0xFE0
#define STRAP_REGION_END		0xFF0
#define CTRL_REGION_START		0xFF0
#define CTRL_REGION_END			0x1000

#define OTP_ROM_SIZE			(ROM_REGION_END - ROM_REGION_START)
#define OTP_RBP_SIZE			(RBP_REGION_END - RBP_REGION_START)
#define OTP_CFG_SIZE			(CFG_REGION_END - CFG_REGION_START)
#define OTP_USR_SIZE			(USR_REGION_END - USR_REGION_START)
#define OTP_SEC_SIZE			(SEC_REGION_END - SEC_REGION_START)
#define OTP_STRAP_SIZE			(STRAP_REGION_END - STRAP_REGION_START)
#define OTP_CTRL_SIZE			(CTRL_REGION_END - CTRL_REGION_START)

enum otp2705_region {
	OTP2705_REGION_ROM,
	OTP2705_REGION_RBP,
	OTP2705_REGION_CFG,
	OTP2705_REGION_USR,
	OTP2705_REGION_SEC,
	OTP2705_REGION_STRAP,
	OTP2705_REGION_CTRL,
};

enum otp2705_status {
	OTP2705_FAILURE   = -2,
	OTP2705_USAGE     = -1,
	OTP2705_SUCCESS   = 0,
	OTP2705_PROG_SKIP = 1,
};

/*
 * OTPSTRAP layout (16 DW total):
 *   DW0       : write protection bits [31:0]
 *   DW1       : write protection bits [63:32]
 *   DW2~DW13  : 6 options × 2 DWs each
 *               option i: DW[2+i*2] = bits[31:0], DW[2+i*2+1] = bits[63:32]
 *   DW14~DW15 : reserved
 */
#define OTP_STRAP_NUM_BITS    64
#define OTP_STRAP_NUM_OPTIONS 6

struct otpstrap_status {
	int value;
	int option_value[OTP_STRAP_NUM_OPTIONS];
	int remain_times;
	int writeable_option;
	int protected;
};

enum cmd_ret {
	CMD_RET_SUCCESS,
	CMD_RET_FAILURE,
	CMD_RET_USAGE = -1,
};

struct otp2705_read {
	unsigned int offset;	/* DW offset in OTP address space */
	unsigned int len;	/* number of DWs to read */
	uint8_t *data;
};

struct otp2705_prog {
	unsigned int w_offset;	/* DW offset in OTP address space */
	unsigned int len;	/* number of DWs to write */
	uint8_t *data;
};

struct otp2705_revid {
	uint32_t revid0;
	uint32_t revid1;
};

#define OTPIOC_BASE			'O'
#define ASPEED_OTP2705_READ_DATA	_IOR(OTPIOC_BASE, 0, struct otp2705_read)
#define ASPEED_OTP2705_PROG_DATA	_IOW(OTPIOC_BASE, 2, struct otp2705_prog)
#define ASPEED_OTP2705_GET_REVID	_IOR(OTPIOC_BASE, 9, struct otp2705_revid)

#endif /* OTP_AST2705_H */
