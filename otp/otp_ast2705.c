// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2026 Aspeed Technology Inc.
 *
 * AST2705 OTP utility - supports read and pb (program bit) commands.
 * R/W granularity: 32-bit double-word.
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "otp_ast2705.h"

static int otp_fd = -1;

/* ------------------------------------------------------------------ */
/* Low-level read / write                                               */
/* ------------------------------------------------------------------ */

static int otp_read_dw(uint32_t abs_dw_offset, uint32_t *data)
{
	struct otp2705_read rdata;

	rdata.offset = abs_dw_offset;
	rdata.len    = 1;
	rdata.data   = (uint8_t *)data;

	return ioctl(otp_fd, ASPEED_OTP2705_READ_DATA, &rdata);
}

static int otp_prog_dw(uint32_t abs_dw_offset, uint32_t data)
{
	struct otp2705_prog pdata;

	pdata.w_offset = abs_dw_offset;
	pdata.len      = 1;
	pdata.data     = (uint8_t *)&data;

	return ioctl(otp_fd, ASPEED_OTP2705_PROG_DATA, &pdata);
}

/* ------------------------------------------------------------------ */
/* Region helpers                                                       */
/* ------------------------------------------------------------------ */

struct region_info {
	const char *name;
	uint32_t   start;
	uint32_t   size;
};

static const struct region_info regions[] = {
	[OTP2705_REGION_ROM]   = { "rom",   ROM_REGION_START,   OTP_ROM_SIZE   },
	[OTP2705_REGION_RBP]   = { "rbp",   RBP_REGION_START,   OTP_RBP_SIZE   },
	[OTP2705_REGION_CFG]   = { "cfg",   CFG_REGION_START,   OTP_CFG_SIZE   },
	[OTP2705_REGION_USR]   = { "usr",   USR_REGION_START,   OTP_USR_SIZE   },
	[OTP2705_REGION_SEC]   = { "sec",   SEC_REGION_START,   OTP_SEC_SIZE   },
	[OTP2705_REGION_STRAP] = { "strap", STRAP_REGION_START, OTP_STRAP_SIZE },
	[OTP2705_REGION_CTRL]  = { "ctrl",  CTRL_REGION_START,  OTP_CTRL_SIZE  },
};

static int region_by_name(const char *name)
{
	for (int i = 0; i < (int)ARRAY_SIZE(regions); i++) {
		if (!strcmp(name, regions[i].name))
			return i;
	}
	return -1;
}

/* ------------------------------------------------------------------ */
/* read command                                                          */
/* ------------------------------------------------------------------ */

static int do_otpread(int argc, char *const argv[])
{
	uint32_t offset, count;
	uint32_t data;
	int reg_id;
	int rc;

	/* read <region> <dw_offset> [count] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	reg_id = region_by_name(argv[1]);
	if (reg_id < 0)
		return CMD_RET_USAGE;

	offset = (uint32_t)strtoul(argv[2], NULL, 16);
	count  = (argc == 4) ? (uint32_t)strtoul(argv[3], NULL, 16) : 1;

	if ((uint64_t)offset + count > regions[reg_id].size) {
		printf("offset+count 0x%x exceeds region size 0x%x\n",
		       offset + count, regions[reg_id].size);
		return CMD_RET_USAGE;
	}

	printf("%s region (DW 0x%X ~ 0x%X):\n",
	       regions[reg_id].name, offset, offset + count - 1);

	for (uint32_t i = 0; i < count; i++) {
		uint32_t abs = regions[reg_id].start + offset + i;

		rc = otp_read_dw(abs, &data);
		if (rc) {
			printf("Failed to read DW 0x%X, ret=%d errno=%d\n",
			       abs, rc, errno);
			return CMD_RET_FAILURE;
		}

		if (i % 4 == 0)
			printf("\n%04X:", (offset + i) * 4);
		printf(" %08X", data);
	}
	printf("\n");

	return CMD_RET_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Strap helpers                                                        */
/* ------------------------------------------------------------------ */

static void otp_strap_status(struct otpstrap_status *otpstrap)
{
	uint32_t dw0, dw1;
	int i, j;

	for (i = 0; i < OTP_STRAP_NUM_BITS; i++) {
		otpstrap[i].value            = 0;
		otpstrap[i].remain_times     = OTP_STRAP_NUM_OPTIONS;
		otpstrap[i].writeable_option = -1;
		otpstrap[i].protected        = 0;
	}

	/* DW2..DW13: 6 options, each option = 2 DWs covering bits [63:0] */
	for (i = 0; i < OTP_STRAP_NUM_OPTIONS; i++) {
		uint32_t abs0 = STRAP_REGION_START + 2 + i * 2;
		int r0, r1;

		r0 = otp_read_dw(abs0,     &dw0);	/* strap bits [31:0]  */
		r1 = otp_read_dw(abs0 + 1, &dw1);	/* strap bits [63:32] */
		if (r0 || r1)
			printf("OTP read strap option %d failed, ret=%d/%d\n", i, r0, r1);

		for (j = 0; j < 32; j++) {
			int bv = (dw0 >> j) & 0x1;

			if (!bv && otpstrap[j].writeable_option == -1)
				otpstrap[j].writeable_option = i;
			if (bv)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bv;
			otpstrap[j].option_value[i] = bv;
		}

		for (j = 32; j < 64; j++) {
			int bv = (dw1 >> (j - 32)) & 0x1;

			if (!bv && otpstrap[j].writeable_option == -1)
				otpstrap[j].writeable_option = i;
			if (bv)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bv;
			otpstrap[j].option_value[i] = bv;
		}
	}

	/* DW0, DW1: write protection for bits [31:0] and [63:32] */
	if (otp_read_dw(STRAP_REGION_START + 0, &dw0) |
	    otp_read_dw(STRAP_REGION_START + 1, &dw1))
		printf("OTP read strap protection failed\n");

	for (j = 0; j < 32; j++) {
		if ((dw0 >> j) & 0x1)
			otpstrap[j].protected = 1;
	}
	for (j = 32; j < 64; j++) {
		if ((dw1 >> (j - 32)) & 0x1)
			otpstrap[j].protected = 1;
	}
}

static int otp_strap_bit_confirm(struct otpstrap_status *otpstrap, int bit_offset, int value)
{
	printf("OTPSTRAP[0x%X]:\n", bit_offset);

	if (value == otpstrap->value) {
		printf("\tThe value is same as before, skip it.\n");
		return OTP2705_PROG_SKIP;
	}

	if (otpstrap->protected) {
		printf("\tThis bit is protected and is not writable\n");
		return OTP2705_FAILURE;
	}

	if (otpstrap->remain_times == 0) {
		printf("\tThis bit has no remaining chance to write.\n");
		return OTP2705_FAILURE;
	}

	printf("\tWrite 1 to OTPSTRAP[0x%X] OPTION[0x%X], value becomes from 0x%X to 0x%X.\n",
	       bit_offset, otpstrap->writeable_option, otpstrap->value, otpstrap->value ^ 1);

	return OTP2705_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* pb (program bit) command                                             */
/* ------------------------------------------------------------------ */

static int confirm_yesno(void)
{
	char str_input[8];
	int i = 0;

	while (i < (int)sizeof(str_input) - 1) {
		str_input[i] = getc(stdin);
		if (str_input[i] == '\n')
			break;
		i++;
	}
	str_input[i] = '\0';

	return (!strcmp(str_input, "y") || !strcmp(str_input, "Y") ||
		!strcmp(str_input, "yes") || !strcmp(str_input, "YES"));
}

static int do_otppb(int argc, char *const argv[])
{
	uint32_t dw_offset, bit_offset, value;
	uint32_t abs_offset, cur_val, new_val;
	int reg_id, nconfirm = 0;
	int pos, rc;

	/*
	 * strap:  pb strap [o] <bit_offset> <value(0|1)>
	 *           bit_offset : global bit position, 0 ~ (OTP_STRAP_NUM_BITS-1)
	 *           value      : 0 or 1
	 *
	 * others: pb <region> [o] <dw_offset> <bit_offset> <value>
	 *           dw_offset  : DW offset within region (hex)
	 *           bit_offset : shift amount within DW, 0-31
	 *           value      : any 32-bit value, programmed as (value << bit_offset);
	 *                        must fit in 32 bits after shifting
	 */
	if (argc < 4 || argc > 6)
		return CMD_RET_USAGE;

	reg_id = region_by_name(argv[1]);
	if (reg_id < 0)
		return CMD_RET_USAGE;

	pos = 2;
	if (!strcmp(argv[pos], "o")) {
		nconfirm = 1;
		pos++;
	}

	if (reg_id == OTP2705_REGION_STRAP) {
		struct otpstrap_status otpstrap[OTP_STRAP_NUM_BITS];
		uint32_t opt, dw_in_region, bit_in_dw;
		int ret;

		/* pb strap [o] <bit_offset> <value> */
		if (pos + 2 > argc)
			return CMD_RET_USAGE;

		bit_offset = (uint32_t)strtoul(argv[pos],     NULL, 16);
		value      = (uint32_t)strtoul(argv[pos + 1], NULL, 16);

		if (bit_offset >= OTP_STRAP_NUM_BITS) {
			printf("bit_offset must be 0-%u\n", OTP_STRAP_NUM_BITS - 1);
			return CMD_RET_USAGE;
		}
		if (value != 0 && value != 1) {
			printf("strap value must be 0 or 1\n");
			return CMD_RET_USAGE;
		}

		otp_strap_status(otpstrap);

		ret = otp_strap_bit_confirm(&otpstrap[bit_offset], bit_offset, value);
		if (ret == OTP2705_PROG_SKIP)
			return CMD_RET_SUCCESS;
		if (ret != OTP2705_SUCCESS)
			return CMD_RET_FAILURE;

		if (!nconfirm) {
			printf("type \"YES\" (no quotes) to continue:\n");
			if (!confirm_yesno()) {
				printf("Aborting\n");
				return CMD_RET_FAILURE;
			}
		}

		opt          = otpstrap[bit_offset].writeable_option;
		dw_in_region = 2 + opt * 2 + (bit_offset / 32);
		bit_in_dw    = bit_offset % 32;

		rc = otp_prog_dw(STRAP_REGION_START + dw_in_region, BIT(bit_in_dw));
		if (rc) {
			printf("OTP program failed, ret=%d errno=%d\n", rc, errno);
			return CMD_RET_FAILURE;
		}

		printf("SUCCESS\n");
		return CMD_RET_SUCCESS;
	}

	/* pb <region> [o] <dw_offset> <bit_offset> <value> */
	if (pos + 3 > argc)
		return CMD_RET_USAGE;

	dw_offset  = (uint32_t)strtoul(argv[pos],     NULL, 16);
	bit_offset = (uint32_t)strtoul(argv[pos + 1], NULL, 16);
	value      = (uint32_t)strtoul(argv[pos + 2], NULL, 16);

	if (dw_offset >= regions[reg_id].size) {
		printf("dw_offset 0x%X >= region size 0x%X\n",
		       dw_offset, regions[reg_id].size);
		return CMD_RET_USAGE;
	}
	if (bit_offset >= 32) {
		printf("bit_offset must be 0-31\n");
		return CMD_RET_USAGE;
	}
	if (((uint64_t)value << bit_offset) > 0xFFFFFFFFU) {
		printf("value 0x%X overflows 32 bits when shifted by bit_offset %u\n",
		       value, bit_offset);
		return CMD_RET_USAGE;
	}

	abs_offset = regions[reg_id].start + dw_offset;

	rc = otp_read_dw(abs_offset, &cur_val);
	if (rc) {
		printf("Failed to read DW 0x%X, ret=%d errno=%d\n",
		       abs_offset, rc, errno);
		return CMD_RET_FAILURE;
	}

	new_val = cur_val | (value << bit_offset);

	printf("OTP[%s] DW 0x%X: current=0x%08X, will program=0x%08X\n",
	       regions[reg_id].name, dw_offset, cur_val, new_val);

	if (new_val == cur_val) {
		printf("No change needed, skip.\n");
		return CMD_RET_SUCCESS;
	}

	if (!nconfirm) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf("Aborting\n");
			return CMD_RET_FAILURE;
		}
	}

	rc = otp_prog_dw(abs_offset, new_val);
	if (rc) {
		printf("OTP program failed, ret=%d errno=%d\n", rc, errno);
		return CMD_RET_FAILURE;
	}

	printf("SUCCESS\n");
	return CMD_RET_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Command dispatch                                                     */
/* ------------------------------------------------------------------ */

struct cmd_tbl {
	const char *name;
	int maxargs;
	int (*cmd)(int argc, char *const argv[]);
};

static const struct cmd_tbl cmd_otp[] = {
	{ "read", 4, do_otpread },
	{ "pb",   6, do_otppb   },
};

static const struct cmd_tbl *find_cmd(const char *name)
{
	for (int i = 0; i < (int)ARRAY_SIZE(cmd_otp); i++) {
		if (!strcmp(name, cmd_otp[i].name))
			return &cmd_otp[i];
	}
	return NULL;
}

static void usage(void)
{
	printf("ASPEED AST2705 OTP utility\n"
	       "\n"
	       "Usage:\n"
	       "  otp-ast2705 read  <region> <dw_offset> [count]\n"
	       "  otp-ast2705 pb    strap [o] <bit_offset> <value(0|1)>\n"
	       "  otp-ast2705 pb    <region> [o] <dw_offset> <bit_offset> <value>\n"
	       "\n"
	       "Regions: rom | rbp | cfg | usr | sec | strap | ctrl\n"
	       "\n"
	       "Notes:\n"
	       "  strap pb: bit_offset is global bit position (0-63);\n"
	       "            value must be 0 or 1; option slot selected automatically.\n"
	       "  other pb: value is any 32-bit value, programmed as (value << bit_offset);\n"
	       "            value must not overflow 32 bits after shifting.\n"
	       "  'o' flag skips confirmation prompt. All offsets in hex.\n"
	       "\n"
	       "Region map (DW offsets, 32-bit granularity):\n"
	       "  rom    0x000 - 0x8FF  (2304 DW)\n"
	       "  rbp    0x900 - 0x90F  (16 DW)\n"
	       "  cfg    0x910 - 0x94F  (64 DW)\n"
	       "  usr    0x950 - 0xF4F  (1536 DW)\n"
	       "  sec    0xF50 - 0xFDF  (144 DW)\n"
	       "  strap  0xFE0 - 0xFEF  (16 DW, 2 prot DW + 6 options)\n"
	       "  ctrl   0xFF0 - 0xFFF  (16 DW)\n");
}

int main(int argc, char *argv[])
{
	const struct cmd_tbl *cp;
	int ret;

	if (argc < 3) {
		usage();
		return EXIT_FAILURE;
	}

	otp_fd = open("/dev/aspeed-otp", O_RDWR);
	if (otp_fd == -1) {
		printf("Can't open /dev/aspeed-otp, please install driver!\n");
		return EXIT_FAILURE;
	}

	/* argv[1] is the subcommand; skip program name */
	argc--;
	argv++;

	cp = find_cmd(argv[0]);
	if (!cp) {
		printf("Unknown command: %s\n", argv[0]);
		usage();
		ret = CMD_RET_USAGE;
		goto out;
	}

	if (argc > cp->maxargs) {
		printf("Too many arguments for '%s'\n", cp->name);
		ret = CMD_RET_USAGE;
		goto out;
	}

	ret = cp->cmd(argc, argv);

out:
	close(otp_fd);

	if (ret == CMD_RET_USAGE) {
		usage();
		return EXIT_FAILURE;
	}
	return (ret == CMD_RET_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
