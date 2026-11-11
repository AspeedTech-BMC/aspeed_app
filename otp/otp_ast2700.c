// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Aspeed Technology Inc.
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>
#include <termios.h>
#include <ctype.h>
#include <endian.h>
#include "otp_ast2700.h"
#include "otp_info_ast2700.h"
#include "otp_ipc.h"

#define ANSI_COLOR_RESET		"\e[0m"
#define ANSI_COLOR_RED			"\e[31m"
#define ANSI_COLOR_BRIGHT_RED		"\e[91m"
#define ANSI_COLOR_GREEN		"\e[32m"
#define ANSI_COLOR_YELLOW		"\e[33m"
#define ANSI_COLOR_CYAN			"\e[36m"
#define ANSI_COLOR_BOLD			"\e[1m"

/* Error/usage diagnostics in bright red, to stand out from normal command output. */
#define otp_err(fmt, ...) \
	printf(ANSI_COLOR_BRIGHT_RED fmt ANSI_COLOR_RESET "\n", ##__VA_ARGS__)

/*
 * ASPEED_OTP_READ_DATA/ASPEED_OTP_PROG_DATA report the OTP_CMD_ERR_* codes
 * (200~204) as errno on failure. strerror() doesn't know these, so translate
 * them here before falling back to strerror() for regular errno values.
 */
static const char *otp_cmd_errno_str(int err)
{
	switch (err) {
	case OTP_CMD_ERR_FAIL:
		return "prog fail or soak limit exceeded";
	case OTP_CMD_ERR_CMP_FAIL:
		return "compare mismatch";
	case OTP_CMD_ERR_REGION_FAIL:
		return "region write/read protected";
	case OTP_CMD_ERR_MASTER_FAIL:
		return "master protection error";
	default:
		return strerror(err);
	}
}

static int otp_print_rom(uint32_t offset, int w_count)
{
	int range = OTP_ROM_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	printf("ROM_REGION: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_rom(i, &ret[0]);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret[0]);
		else
			printf("%04X ", ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_rbp(uint32_t offset, int w_count)
{
	int range = OTP_RBP_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_rbp(i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPRBP0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_conf(uint32_t offset, int w_count)
{
	int range = OTP_CONF_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_conf(i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPCFG0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_strap(uint32_t offset, int w_count)
{
	int range = 12;	/* 32-bit * 6 / 16 (per word) */
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_strap(2 + i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPSTRAP0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_strap_pro(uint32_t offset, int w_count)
{
	int range = 2;	/* 32-bit / 16 (per word) */
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_strap(i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPSTRAP_PRO0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_strap_ext(uint32_t offset, int w_count)
{
	int range = (OTP_STRAP_EXT_REGION_SIZE) / 2;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_strap_ext(i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPSTRAPEXT0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_strap_ext_valid(uint32_t offset, int w_count)
{
	int range = (OTP_STRAP_EXT_REGION_SIZE) / 2;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_strap_ext_vld(i, ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		printf("OTPSTRAPEXT_VLD0x%X: 0x%04X\n", i, ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_user_data(uint32_t offset, int w_count)
{
	int range = OTP_USER_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	printf("User Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_udata(i, &ret[0]);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret[0]);
		else
			printf("%04X ", ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_sec_data(uint32_t offset, int w_count)
{
	int range = OTP_SEC_REGION_SIZE;
	uint16_t ret;
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	printf("Secure Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_sdata(i, &ret);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret);
		else
			printf("%04X ", ret);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_cptra(uint32_t offset, int w_count)
{
	int range = OTP_CAL_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	printf("Caliptra Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_cptra(i, &ret[0]);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret[0]);
		else
			printf("%04X ", ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_puf(uint32_t offset, int w_count)
{
	int range = OTP_PUF_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (w_count < 0)
		w_count = range - offset;

	if (offset + w_count > range) {
		otp_err("offset+count 0x%x exceeds region size 0x%x", offset + w_count, range);
		return OTP_USAGE;
	}

	printf("PUF: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read_swpuf(i, &ret[0]);
		if (rc) {
			otp_err("OTP read failed at word offset 0x%x, ret=%d", i, rc);
			return rc;
		}

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret[0]);
		else
			printf("%04X ", ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_print_rbp_info(void)
{
	const struct otprbp_info *rbp_info = info_cb.rbp_info;
	uint16_t OTPRBP[OTP_RBP_REGION_SIZE];
	uint32_t w_offset;
	uint32_t length;
	int ret;

	for (int i = 0; i < OTP_RBP_REGION_SIZE; i++) {
		ret = otp_read_rbp(i, &OTPRBP[i]);
		if (ret) {
			printf("Failed to read OTPRBP at offset 0x%x, ret = %d, errno = %d (%s)\n",
				   i, ret, errno, otp_cmd_errno_str(errno));
			return CMD_RET_FAILURE;
		}
	}

	printf("W     bit-length Description                               Value\n");
	printf("__________________________________________________________________________\n");
	for (int i = 0; i < info_cb.rbp_info_len; i++) {
		w_offset = rbp_info[i].w_offset;
		length = rbp_info[i].length;

		printf("0x%-4X", w_offset);
		printf("0x%-9X", length);
		printf("%-40s: ", rbp_info[i].information);

		for (int j = 0; j < (length + 15) / 16; j++)
			printf("0x%04x ", OTPRBP[w_offset + j]);
		printf("\n");
	}

	return OTP_SUCCESS;
}

static int otp_print_conf_info(void)
{
	const struct otpconf_info *conf_info = info_cb.conf_info;
	uint16_t OTPCFG[32];
	uint32_t mask;
	uint32_t w_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	int ret;
	int global_status;
	uint32_t region_ecc_en = 0, region_ecc_supported = 0;
	bool conf_ecc_active;

	for (int i = 0; i < 32; i++) {
		ret = otp_read_conf(i, &OTPCFG[i]);
		if (ret) {
			printf("Failed to read OTPCFG at offset 0x%x, ret = %d, errno = %d (%s)\n",
				   i, ret, errno, otp_cmd_errno_str(errno));
			return CMD_RET_FAILURE;
		}
	}

	/*
	 * OTPCFG's ECC enable is a single per-region switch (not per-word);
	 * once it's active, re-programming a word that already has any bit
	 * set risks corrupting its ECC parity, so flag that case per word
	 * below instead of waiting for a program attempt to fail.
	 */
	ret = otp_ecc_get_status(&global_status);
	if (ret) {
		printf("Failed to get global ECC status, ret=%d\n", ret);
		return ret;
	}

	ret = otp_get_ecc_policy(OTP_REGION_ID_CFG, &region_ecc_en, &region_ecc_supported);
	if (ret) {
		printf("Failed to get OTPCFG ECC policy, ret=%d\n", ret);
		return ret;
	}

	conf_ecc_active = region_ecc_supported &&
			   (global_status != OTP_ECC_GLOBAL_DISABLED || region_ecc_en);

	printf("OTPCFG ECC: %s%s" ANSI_COLOR_RESET "\n",
	       conf_ecc_active ? ANSI_COLOR_CYAN : ANSI_COLOR_GREEN,
	       conf_ecc_active ? "active" : "inactive");
	printf("W     BIT        Value       Description                                                              Program Status\n");
	printf("______________________________________________________________________________________________________________________________\n");
	for (int i = 0; i < info_cb.conf_info_len; i++) {
		char desc[80];
		bool must_not_prog;

		w_offset = conf_info[i].w_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[w_offset] >> bit_offset) & mask;
		must_not_prog = conf_ecc_active && OTPCFG[w_offset] != 0;

		if (otp_value != conf_info[i].value &&
		    conf_info[i].value != OTP_REG_RESERVED &&
		    conf_info[i].value != OTP_REG_VALUE)
			continue;
		printf("0x%-4X", w_offset);

		if (conf_info[i].length == 1) {
			printf("0x%-9X", conf_info[i].bit_offset);
		} else {
			printf("0x%-2X:0x%-4X",
			       conf_info[i].bit_offset + conf_info[i].length - 1,
			       conf_info[i].bit_offset);
		}
		if (otp_value)
			printf(ANSI_COLOR_BOLD "0x%-10x" ANSI_COLOR_RESET, otp_value);
		else
			printf("0x%-10x", otp_value);

		if (conf_info[i].value == OTP_REG_RESERVED)
			snprintf(desc, sizeof(desc), "Reserved");
		else if (conf_info[i].value == OTP_REG_VALUE)
			snprintf(desc, sizeof(desc), conf_info[i].information, otp_value);
		else
			snprintf(desc, sizeof(desc), "%s", conf_info[i].information);
		printf("%-73s", desc);

		if (must_not_prog)
			printf(ANSI_COLOR_RED "DO NOT PROGRAM" ANSI_COLOR_RESET "\n");
		else
			printf(ANSI_COLOR_GREEN "OK" ANSI_COLOR_RESET "\n");
	}

	return OTP_SUCCESS;
}

static void otp_print_strap_info(void)
{
	const struct otpstrap_info *strap_info = info_cb.strap_info;
	struct otpstrap_status strap_status[32];
	uint32_t bit_offset;
	uint32_t length;
	uint32_t otp_value;
	uint32_t otp_protect;

	otp_strap_status(strap_status);

	printf("BIT(hex) Value  Remains  Protect  Description\n");
	printf("___________________________________________________________________________________________________\n");

	for (int i = 0; i < info_cb.strap_info_len; i++) {
		otp_value = 0;
		otp_protect = 0;
		bit_offset = strap_info[i].bit_offset;
		length = strap_info[i].length;
		for (int j = 0; j < length; j++) {
			otp_value |= strap_status[bit_offset + j].value << j;
			otp_protect |= strap_status[bit_offset + j].protected << j;
		}

		if (otp_value != strap_info[i].value &&
		    strap_info[i].value != OTP_REG_RESERVED)
			continue;

		for (int j = 0; j < length; j++) {
			uint32_t bit_value = strap_status[bit_offset + j].value;
			uint32_t bit_protected = strap_status[bit_offset + j].protected;
			int bit_remain = strap_status[bit_offset + j].remain_times;

			printf("0x%-7X", strap_info[i].bit_offset + j);
			if (bit_value)
				printf(ANSI_COLOR_BOLD "0x%-5X" ANSI_COLOR_RESET, bit_value);
			else
				printf("0x%-5X", bit_value);
			if (bit_remain != 6)
				printf(ANSI_COLOR_BOLD "%-9d" ANSI_COLOR_RESET, bit_remain);
			else
				printf("%-9d", bit_remain);
			if (bit_protected)
				printf(ANSI_COLOR_BOLD "0x%-7X" ANSI_COLOR_RESET, bit_protected);
			else
				printf("0x%-7X", bit_protected);
			if (strap_info[i].value == OTP_REG_RESERVED) {
				printf(" Reserved\n");
				continue;
			}

			if (length == 1) {
				printf(" %s\n", strap_info[i].information);
				continue;
			}

			if (j == 0)
				printf("/%s\n", strap_info[i].information);
			else if (j == length - 1)
				printf("\\ \"\n");
			else
				printf("| \"\n");
		}
	}
}

static int otp_strap_bit_confirm(struct otpstrap_status *otpstrap, int offset, int value, int pbit)
{
	int prog_flag = 0;

	printf("OTPSTRAP[0x%X]:\n", offset);

	if (value == otpstrap->value) {
		if (!pbit) {
			printf("\tThe value is same as before, skip it.\n");
			return OTP_PROG_SKIP;
		}
		printf("\tThe value is same as before.\n");

	} else {
		prog_flag = 1;
	}

	if (otpstrap->protected == 1 && prog_flag) {
		printf("\tThis bit is protected and is not writable\n");
		return OTP_FAILURE;
	}

	if (otpstrap->remain_times == 0 && prog_flag) {
		printf("\tThis bit has no remaining chance to write.\n");
		return OTP_FAILURE;
	}

	if (pbit == 1)
		printf("\tThis bit will be protected and become non-writable.\n");

	if (prog_flag)
		printf("\tWrite 1 to OTPSTRAP[0x%X] OPTION[0x%X], that value becomes from 0x%X to 0x%X.\n",
		       offset, otpstrap->writeable_option, otpstrap->value, otpstrap->value ^ 1);

	return OTP_SUCCESS;
}

static void otp_print_strap_ext_info(void)
{
	const struct otpstrap_ext_info *strap_ext_info = info_cb.strap_ext_info;
	uint32_t bit_offset;
	uint32_t otp_value, otp_vld;
	uint32_t length;
	uint16_t data[8];
	uint16_t vld[8];
	int ret;
	int global_status;
	uint32_t region_ecc_en = 0, region_ecc_supported = 0;
	bool strapext_ecc_active;

	/* Read Flash strap */
	for (int i = 0; i < 8; i++)
		otp_read_strap_ext(i, &data[i]);

	/* Read Flash strap valid */
	for (int i = 0; i < 8; i++)
		otp_read_strap_ext_vld(i, &vld[i]);

	/*
	 * OTPSTRAP_EXT's ECC enable is a single per-region switch (not
	 * per-word); once it's active, re-programming a word that already
	 * has any bit set risks corrupting its ECC parity, so flag that
	 * case per word below instead of waiting for a program attempt to
	 * fail.
	 */
	ret = otp_ecc_get_status(&global_status);
	if (ret) {
		printf("Failed to get global ECC status, ret=%d\n", ret);
		return;
	}

	ret = otp_get_ecc_policy(OTP_REGION_ID_STRAPEXT, &region_ecc_en, &region_ecc_supported);
	if (ret) {
		printf("Failed to get OTPSTRAP_EXT ECC policy, ret=%d\n", ret);
		return;
	}

	strapext_ecc_active = region_ecc_supported &&
			       (global_status != OTP_ECC_GLOBAL_DISABLED || region_ecc_en);

	printf("OTPSTRAP_EXT ECC: %s%s" ANSI_COLOR_RESET "\n",
	       strapext_ecc_active ? ANSI_COLOR_CYAN : ANSI_COLOR_GREEN,
	       strapext_ecc_active ? "active" : "inactive");
	printf("BIT(hex) Value  Valid  Description                                                        Value Status    Valid Status\n");
	printf("____________________________________________________________________________________________________________________________\n");

	for (int i = 0; i < info_cb.strap_ext_info_len; i++) {
		bool must_not_prog_value;
		bool must_not_prog_vld;

		otp_value = 0;
		otp_vld = 0;
		bit_offset = strap_ext_info[i].bit_offset;
		length = strap_ext_info[i].length;

		int w_offset = bit_offset / 16;
		int b_offset = bit_offset % 16;

		otp_value = (data[w_offset] >> b_offset) &
			    GENMASK(length - 1, 0);
		otp_vld = (vld[w_offset] >> b_offset) &
			  GENMASK(length - 1, 0);

		if (otp_value != strap_ext_info[i].value)
			continue;

		/*
		 * Value and Valid are recorded in separate OTP words, so each
		 * carries its own independent ECC-parity programming risk.
		 */
		must_not_prog_value = strapext_ecc_active && data[w_offset] != 0;
		must_not_prog_vld = strapext_ecc_active && vld[w_offset] != 0;

		for (int j = 0; j < length; j++) {
			char desc[80];
			uint32_t bit_value = (otp_value & BIT(j)) >> j;
			uint32_t bit_vld = (otp_vld & BIT(j)) >> j;

			printf("0x%-7x", strap_ext_info[i].bit_offset + j);
			if (bit_value)
				printf(ANSI_COLOR_BOLD "0x%-5x" ANSI_COLOR_RESET, bit_value);
			else
				printf("0x%-5x", bit_value);
			if (bit_vld)
				printf(ANSI_COLOR_BOLD "0x%-5x" ANSI_COLOR_RESET, bit_vld);
			else
				printf("0x%-5x", bit_vld);

			if (length == 1)
				snprintf(desc, sizeof(desc), " %s", strap_ext_info[i].information);
			else if (j == 0)
				snprintf(desc, sizeof(desc), "/%s", strap_ext_info[i].information);
			else if (j == length - 1)
				snprintf(desc, sizeof(desc), "\\ \"");
			else
				snprintf(desc, sizeof(desc), "| \"");
			printf("%-67s", desc);

			if (must_not_prog_value)
				printf(ANSI_COLOR_RED "%-16s" ANSI_COLOR_RESET, "DO NOT PROGRAM");
			else
				printf(ANSI_COLOR_GREEN "%-16s" ANSI_COLOR_RESET, "OK");

			if (must_not_prog_vld)
				printf(ANSI_COLOR_RED "%s" ANSI_COLOR_RESET "\n", "DO NOT PROGRAM");
			else
				printf(ANSI_COLOR_GREEN "%s" ANSI_COLOR_RESET "\n", "OK");
		}
	}
}

static int otp_patch_prog(uint8_t *addr, uint32_t offset, uint32_t size)
{
	int ret = 0;
	uint32_t val;

	printf("%s: addr:0x%p, offset:0x%x, size:0x%x\n", __func__,
	       addr, offset, size);

	for (int i = 0; i < size / 2; i++) {
		// val = readl((uintptr_t)addr + i * 4);
		val = *(addr + i * 4);
		printf("read 0x%p = 0x%x..., prog into OTP addr 0x%x\n",
		       addr + i * 4, val, offset + i * 2);
		ret += otp_prog(offset + i * 2, val & GENMASK(15, 0));
		ret += otp_prog(offset + i * 2 + 1, (val >> 16) & GENMASK(15, 0));
	}

	return ret;
}

static int otp_patch_enable_pre(uint16_t offset, size_t size)
{
	int ret;

	/* Set location - OTPCFG4[10:1] */
	ret = otp_prog_data(OTP_REGION_CONF, 4, 1, offset, 1, true);
	if (ret) {
		printf("%s: Prog location Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	/* Set Size - OTPCFG5[9:0] */
	ret = otp_prog_data(OTP_REGION_CONF, 5, 0, size, 1, true);
	if (ret) {
		printf("%s: Prog size Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	/* enable pre_otp_patch_vld - OTPCFG4[0] */
	ret = otp_prog_data(OTP_REGION_CONF, 4, 0, 1, 1, true);
	if (ret) {
		printf("%s: Enable pre_otp_patch_vld Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	return 0;
}

static int otp_patch_enable_post(uint16_t offset, size_t size)
{
	int ret;

	/* Set location - OTPCFG6[10:1] */
	ret = otp_prog_data(OTP_REGION_CONF, 6, 1, offset, 1, true);
	if (ret) {
		printf("%s: Prog location Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	/* Set Size - OTPCFG7[9:0] */
	ret = otp_prog_data(OTP_REGION_CONF, 7, 0, size, 1, true);
	if (ret) {
		printf("%s: Prog size Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	/* enable pre_otp_patch_vld - OTPCFG6[0] */
	ret = otp_prog_data(OTP_REGION_CONF, 6, 0, 1, 1, true);
	if (ret) {
		printf("%s: Enable post_otp_patch_vld Failed, ret:0x%x\n", __func__, ret);
		return ret;
	}

	return 0;
}

static int otp_print_rom_image(struct otp_image_layout *image_layout)
{
	uint32_t *buf;
	int size;

	buf = (uint32_t *)image_layout->rom;
	size = image_layout->rom_length;

	for (int i = 0; i < size / 4; i++) {
		if (i % 4 == 0)
			printf("\n%04x:", i * 4);
		printf(" %08x", buf[i]);
	}
	printf("\n");

	return 0;
}

static int otp_print_user_image(struct otp_image_layout *image_layout)
{
	uint32_t *buf;
	int size;

	buf = (uint32_t *)image_layout->user;
	size = image_layout->user_length;

	for (int i = 0; i < size / 4; i++) {
		if (i % 4 == 0)
			printf("\n%04x:", i * 4);
		printf(" %08x", buf[i]);
	}
	printf("\n");

	return 0;
}

static int _otp_print_key(uint32_t header, uint32_t offset, uint8_t *data)
{
	const struct otpkey_type *key_info_array = info_cb.key_info;
	struct otpkey_type key_info = { .value = -1 };
	int key_id, key_w_offset, key_offset, key_type;
	int last;
	int i;

	if (!header)
		return -1;

	key_id = OTP_KH_KEY_ID(header);
	key_w_offset = OTP_KH_OFFSET(header);
	key_offset = key_w_offset * 2;
	key_type = OTP_KH_KEY_TYPE(header);
	last = OTP_KH_LAST(header);

	printf("\nKey[%d]:\n", offset);
	printf("Header: %x\n", header);

	for (i = 0; i < info_cb.key_info_len; i++) {
		if (key_type == key_info_array[i].value) {
			key_info = key_info_array[i];
			break;
		}
	}

	if (i == info_cb.key_info_len) {
		printf("Error: Cannot find the key type\n");
		return -1;
	}

	printf("Key Type: ");
	printf("%s\n", key_info.information);
	printf("Key Number ID: %d\n", key_id);
	printf("Key Word Offset: 0x%x\n", key_w_offset);
	if (last)
		printf("This is the last key\n");

	if (!data)
		return -1;

	printf("Key Value:\n");
	if (key_info.key_type == SOC_ECDSA_PUB) {
		printf("Q.x:\n");
		buf_print(&data[key_offset], 0x30);
		printf("Q.y:\n");
		buf_print(&data[key_offset + 0x30], 0x30);

	} else if (key_info.key_type == SOC_LMS_PUB) {
		printf("tree_type:\n");
		buf_print(&data[key_offset], 0x4);
		printf("otstype:\n");
		buf_print(&data[key_offset + 0x4], 0x4);
		printf("id:\n");
		buf_print(&data[key_offset + 0x8], 0x10);
		printf("digest:\n");
		buf_print(&data[key_offset + 0x18], 0x18);

	} else if (key_info.key_type == CAL_MANU_PUB_HASH) {
		buf_print(&data[key_offset], 0x30);
		printf("Manufacture ECC Key Mask: 0x%x\n", data[key_offset + 0x30]);
		printf("Manufacture LMS Key Mask: 0x%x\n", data[key_offset + 0x34]);

	} else if (key_info.key_type == CAL_OWN_PUB_HASH) {
		buf_print(&data[key_offset], 0x30);

	} else if (key_info.key_type == SOC_VAULT || key_info.key_type == SOC_VAULT_SEED) {
		buf_print(&data[key_offset], 0x20);
	} else if (key_info.key_type == OEM_DATA) {
		buf_print(&data[key_offset], 0x30);
	}

	return 0;
}

static void otp_print_key(uint32_t *data)
{
	uint8_t *byte_buf;
	int empty;

	byte_buf = (uint8_t *)data;
	empty = 1;

	for (int i = 0; i < OTP_KH_NUM; i++) {
		if (data[i] != 0)
			empty = 0;
	}

	if (empty) {
		printf("OTP data header is empty\n");
		return;
	}

	for (int i = 0; i < OTP_KH_NUM; i++)
		_otp_print_key(data[i], i, byte_buf);
}

static void otp_print_key_info(void)
{
	uint16_t buf[OTP_SEC_REGION_SIZE];
	int ret;

	ret = otp_read_sdata_multi(0, buf, OTP_SEC_REGION_SIZE);
	if (ret) {
		printf("Failed to read OTP secure region, ret = %d, errno = %d (%s)\n",
		       ret, errno, otp_cmd_errno_str(errno));
		return;
	}

	otp_print_key((uint32_t *)buf);
}

/* A1's ROM patch version register is one of these exact values, unlike A2's ASCII-ish encoding */
#define A1_OTP_ROM_PATCH_NONE		0x0
#define A1_OTP_ROM_PATCH_V1		0x3
#define A1_OTP_ROM_PATCH_V2		0x3276
#define A1_OTP_ROM_PATCH_V3		0x3376

static void otp_print_rom_patch_version(void)
{
	uint32_t ver;
	const char *str;
	int ret;

	ret = otp_get_rom_patch_version(&ver);
	if (ret) {
		printf("Failed to read ROM patch version, ret = %d, errno = %d (%s)\n",
		       ret, errno, otp_cmd_errno_str(errno));
		return;
	}

	if (info_cb.version == OTP_AST2700_A2) {
		uint8_t *b = (uint8_t *)&ver;
		bool valid = (b[0] == 'v');

		for (int i = 0; valid && i < 4 && b[i] != 0; i++)
			valid = isprint(b[i]) != 0;

		if (ver == 0x0)
			printf("ROM patch: None\n");
		else if (valid)
			printf("ROM patch: %.4s\n", (char *)&ver);
		else
			printf("ROM patch: Unknown (0x%x)\n", ver);
		return;
	}

	if (info_cb.version != OTP_AST2700_A1) {
		printf("ROM patch: unsupported chip version (0x%x)\n", info_cb.version);
		return;
	}

	switch (ver) {
	case A1_OTP_ROM_PATCH_NONE:
		str = "None";
		break;
	case A1_OTP_ROM_PATCH_V1:
		str = "v1";
		break;
	case A1_OTP_ROM_PATCH_V2:
		str = "v2";
		break;
	case A1_OTP_ROM_PATCH_V3:
		str = "v3";
		break;
	default:
		str = "Unknown";
		break;
	}
	printf("ROM patch: %s\n", str);
}

/*
 * OTPSTRAP word 0xf: six 2-bit manufacturing test stage records, stage 1
 * at bits[1:0] through stage 6 at bits[11:10]; bits[15:12] reserved.
 */
#define OTPSTRAP_MT_STAGE_W_OFFSET	0xf
#define OTPSTRAP_MT_STAGE_COUNT		6
#define OTPSTRAP_MT_STAGE_FIELD(val, stage)	(((val) >> ((stage) * 2)) & 0x3)

static void otp_print_strap_mt_stage(uint16_t mt_stage)
{
	printf("OTPSTRAP MT stage records (word 0x%x):\n", OTPSTRAP_MT_STAGE_W_OFFSET);
	for (int stage = 0; stage < OTPSTRAP_MT_STAGE_COUNT; stage++)
		printf("stage%-3d", stage + 1);
	printf("\n");
	for (int stage = 0; stage < OTPSTRAP_MT_STAGE_COUNT; stage++)
		printf("--------");
	printf("\n");
	for (int stage = 0; stage < OTPSTRAP_MT_STAGE_COUNT; stage++)
		printf("0x%-6x", OTPSTRAP_MT_STAGE_FIELD(mt_stage, stage));
	printf("\n");
}

/* Reads OTPSTRAP's MT stage word directly, for "otp info mt-stage" */
static int otp_print_mt_stage_info(void)
{
	uint16_t mt_stage;
	int ret;

	ret = otp_read_strap(OTPSTRAP_MT_STAGE_W_OFFSET, &mt_stage);
	if (ret) {
		otp_err("Failed to read OTPSTRAP MT stage word");
		return OTP_FAILURE;
	}

	otp_print_strap_mt_stage(mt_stage);

	return OTP_SUCCESS;
}

/*
 * OTPCAL word 0x12: start of the 48-byte (24-word) vendor key hash. Its
 * first two words identify which HSM solution signed the provisioning
 * image.
 */
#define CAL_VENDOR_KEY_HASH_OFFSET	0x12
#define CAL_VENDOR_KEY_HASH_DUAL_HSM	0xddd4b37b
#define CAL_VENDOR_KEY_HASH_SINGLE_HSM	0x428d18b0

static int otp_print_hsm_info(void)
{
	uint16_t hash[2];
	uint32_t hash_prefix;
	const char *hsm_solution;
	int ret;

	ret = otp_read_raw_multi(CAL_REGION_START_ADDR + CAL_VENDOR_KEY_HASH_OFFSET, hash,
				 ARRAY_SIZE(hash));
	if (ret) {
		otp_err("Failed to read vendor key hash");
		return OTP_FAILURE;
	}

	hash_prefix = ((uint32_t)be16toh(hash[0]) << 16) | be16toh(hash[1]);

	if (hash_prefix == CAL_VENDOR_KEY_HASH_DUAL_HSM)
		hsm_solution = "Dual-HSM";
	else if (hash_prefix == CAL_VENDOR_KEY_HASH_SINGLE_HSM)
		hsm_solution = "Single-HSM";
	else
		hsm_solution = "unknown";

	printf("Vendor key hash: %04x%04x... (%s)\n",
	       be16toh(hash[0]), be16toh(hash[1]), hsm_solution);

	return OTP_SUCCESS;
}

/*
 * Dynamic region-protect registers (see otp_get_region_protect()): each
 * field of struct otp_region_protect is LOCK(bit31)/WEN(bits 15:8, one per
 * master)/REN(bits 7:0), except .puf which has its own 4-bit lock-only
 * layout.
 */
#define OTP_PROT_LOCK_BIT		BIT(31)
#define OTP_PROT_WEN_MASK		0xff00
#define OTP_PROT_REN_MASK		0xff

/* secure/usr/caliptra *_range fields: bits31:16=size, bits15:0=start offset (OTP words) */
#define OTP_PROT_RANGE_SIZE(range)	(((range) >> 16) & 0xffff)
#define OTP_PROT_RANGE_START(range)	((range) & 0xffff)

/*
 * rom_patch/otpcfg/otpstrap/strap_ext have no *_RANGE register - unlike
 * secure/usr/caliptra, their address window is fixed in hardware, not
 * runtime-configurable. Synthesize a range value in the same encoding from
 * this file's own region constants so otp_print_protect_row() can print
 * them the same way.
 */
static inline uint32_t otp_prot_fixed_range(uint32_t start, uint32_t end)
{
	return ((uint32_t)(end - start) << 16) | start;
}

#define OTP_PROT_SW_PUF_RLOCK_BIT	BIT(8)
#define OTP_PROT_HW_PUF_RLOCK_BIT	BIT(4)
#define OTP_PROT_HW_PUF_WLOCK_BIT	BIT(1)
#define OTP_PROT_SW_PUF_WLOCK_BIT	BIT(0)

/* Underline separating a table's header row from its data rows. */
static void otp_print_protect_sep(int len)
{
	printf("  ");
	while (len-- > 0)
		printf("_");
	printf("\n");
}

/*
 * Region column widened to 20 and a blank filler after Write, matching the
 * Lock/WEN/REN and RLock/WLock tables' layout, so all three tables' Start/
 * End columns land in the same place.
 */
static void otp_print_static_row(const char *name, int has_read, int read_prot, int write_prot,
				 uint32_t start, uint32_t end)
{
	if (has_read)
		printf("  %-20s %-8d%-8d%-6s0x%04x    0x%04x\n", name, read_prot, write_prot,
		       "", start, end);
	else
		printf("  %-20s %-8s%-8d%-6s0x%04x    0x%04x\n", name, "-", write_prot,
		       "", start, end);
}

/*
 * has_range is false for ROM_PATCH, OTPCFG, OTPSTRAP, STRAP_EXT, and the
 * RBP_* registers - only secure/usr/caliptra have a configurable address
 * window, and its START_OFFSET field is relative to that group's own fixed
 * base (e.g. USER_REGION_START_ADDR for usr0-3) rather than OTP address 0,
 * so base is added in to show the same global OTP word offset "otp
 * read"/"otp pb" use. end is exclusive (start + size), matching this
 * file's existing START_ADDR/END_ADDR region-boundary convention.
 */
static void otp_print_protect_row(const char *name, uint32_t value, int has_range,
				  uint32_t range, uint32_t base)
{
	uint32_t start;

	if (has_range) {
		start = base + OTP_PROT_RANGE_START(range);
		printf("  %-20s 0x%02x    0x%02x    %-6d0x%04x    0x%04x\n", name,
		       value & OTP_PROT_REN_MASK,
		       (value & OTP_PROT_WEN_MASK) >> 8,
		       !!(value & OTP_PROT_LOCK_BIT),
		       start, start + OTP_PROT_RANGE_SIZE(range));
	} else {
		printf("  %-20s 0x%02x    0x%02x    %-6d%-10s%s\n", name,
		       value & OTP_PROT_REN_MASK,
		       (value & OTP_PROT_WEN_MASK) >> 8,
		       !!(value & OTP_PROT_LOCK_BIT),
		       "-", "-");
	}
}

/*
 * PUF has no combined region-wide LOCK bit and no per-master WEN/REN mask -
 * sw_puf/hw_puf each just get their own single read-lock and write-lock
 * bit, so this gets its own header (RLock/WLock) rather than reusing the
 * Lock/WEN/REN table's columns, which mean "enabled" rather than "locked".
 * The trailing "" is an unlabeled filler, just wide enough to make up for
 * having one fewer value column than the Lock/WEN/REN table, so Start/End
 * land in the same place in both.
 */
static void otp_print_puf_row(const char *name, int rlock, int wlock, uint32_t start, uint32_t end)
{
	printf("  %-20s %-8d%-8d%-6s0x%04x    0x%04x\n", name, rlock, wlock, "", start, end);
}

/*
 * "otp info prot": static protect is OTPCFG word 0 (fuse, permanent) - read
 * fresh here rather than reusing info_cb.pro_sts, so this command is
 * self-contained and doesn't depend on do_ast_otp()'s dispatch-time
 * refresh of that global. Dynamic protect is the OTPMISCREG lock/wen/ren
 * registers (SoC-side, settable at runtime until their own LOCK bit is
 * set) - native ioctl or IPC/BootMCU, whichever otp_get_region_protect()
 * picks.
 */
static int otp_print_protect_info(void)
{
	union otp_pro_sts s;
	struct otp_region_protect prot;
	uint16_t otp_conf0 = 0;
	int ret;

	ret = otp_read_conf(0, &otp_conf0);
	if (ret) {
		otp_err("Failed to read OTPCFG word 0 for static protect status");
		return OTP_FAILURE;
	}
	s.value = otp_conf0;

	printf("Static protect (OTPCFG word 0, fuse - permanent):\n");
	printf("  %-20s %-8s%-8s%-6s%-10s%s\n", "Region", "RLock", "WLock", "", "Start", "End");
	otp_print_protect_sep(59);
	/* Rows below are in offset order; mem_lock covers the whole OTP (ties
	 * rom's start at 0x0) so it's listed first as the broadest of the two.
	 */
	otp_print_static_row("mem_lock", 0, 0, s.fields.mem_lock,
			      ROM_REGION_START_ADDR, HW_PUF_REGION_END_ADDR);
	otp_print_static_row("rom", 1, s.fields.r_prot_rom, s.fields.w_prot_rom,
			      ROM_REGION_START_ADDR, ROM_REGION_END_ADDR);
	otp_print_static_row("rbp", 0, 0, s.fields.w_prot_rbp,
			      RBP_REGION_START_ADDR, RBP_REGION_END_ADDR);
	otp_print_static_row("conf", 1, s.fields.r_prot_conf, s.fields.w_prot_conf,
			      CONF_REGION_START_ADDR, CONF_REGION_END_ADDR);
	otp_print_static_row("strap", 1, s.fields.r_prot_strap, s.fields.w_prot_strap,
			      STRAP_REGION_START_ADDR, STRAP_REGION_END_ADDR);
	otp_print_static_row("strap_ext", 1, s.fields.r_prot_strap_ext, s.fields.w_prot_strap_ext,
			      STRAPEXT_REGION_START_ADDR, STRAPEXT_REGION_END_ADDR);
	otp_print_static_row("cptra", 1, s.fields.r_prot_cal, s.fields.w_prot_cal,
			      CAL_REGION_START_ADDR, CAL_REGION_END_ADDR);
	otp_print_static_row("puf", 0, 0, s.fields.w_prot_puf,
			      SW_PUF_REGION_START_ADDR, HW_PUF_REGION_END_ADDR);

	printf("\nDynamic protect (OTP control registers, per-boot - settable until locked):\n");
	if (otp_get_region_protect(&prot)) {
		otp_err("Failed to read OTP region-protect registers");
		return OTP_FAILURE;
	}

	printf("  %-20s %-8s%-8s%-6s%-10s%s\n", "Region", "REN", "WEN", "Lock", "Start", "End");
	otp_print_protect_sep(59);
	/*
	 * Offset order. RBP_* have no *_RANGE register (unlike secure/usr/
	 * caliptra - see struct otp_region_protect's comment); their fixed
	 * word sub-ranges within the RBP region are hardcoded here instead.
	 */
	otp_print_protect_row("ROM_PATCH", prot.rom_patch, 1,
			       otp_prot_fixed_range(ROM_REGION_START_ADDR, ROM_REGION_END_ADDR), 0);
	otp_print_protect_row("RBP_SOC_KEYRETIRE", prot.rbp_soc_keyretire, 1,
			       otp_prot_fixed_range(RBP_REGION_START_ADDR,
						     RBP_REGION_START_ADDR + 2), 0);
	otp_print_protect_row("RBP_CALIP_KEYRETIRE", prot.rbp_calip_keyretire, 1,
			       otp_prot_fixed_range(RBP_REGION_START_ADDR + 3,
						     RBP_REGION_START_ADDR + 4), 0);
	otp_print_protect_row("RBP_SOC_SVN", prot.rbp_soc_svn, 1,
			       otp_prot_fixed_range(RBP_REGION_START_ADDR + 4,
						     RBP_REGION_START_ADDR + 8), 0);
	otp_print_protect_row("RBP_CALIP_SVN", prot.rbp_calip_svn, 1,
			       otp_prot_fixed_range(RBP_REGION_START_ADDR + 8,
						     RBP_REGION_START_ADDR + 0x12), 0);
	otp_print_protect_row("OTPCFG", prot.otpcfg, 1,
			       otp_prot_fixed_range(CONF_REGION_START_ADDR,
						     CONF_REGION_END_ADDR), 0);
	otp_print_protect_row("OTPSTRAP", prot.otpstrap, 1,
			       otp_prot_fixed_range(STRAP_REGION_START_ADDR,
						     STRAP_REGION_END_ADDR), 0);
	otp_print_protect_row("STRAP_EXT", prot.strap_ext, 1,
			       otp_prot_fixed_range(STRAPEXT_REGION_START_ADDR,
						     STRAPEXT_REGION_END_ADDR), 0);
	otp_print_protect_row("USR0", prot.usr0, 1, prot.usr0_range, USER_REGION_START_ADDR);
	otp_print_protect_row("USR1", prot.usr1, 1, prot.usr1_range, USER_REGION_START_ADDR);
	otp_print_protect_row("USR2", prot.usr2, 1, prot.usr2_range, USER_REGION_START_ADDR);
	otp_print_protect_row("USR3", prot.usr3, 1, prot.usr3_range, USER_REGION_START_ADDR);
	otp_print_protect_row("SECURE0", prot.secure0, 1,
			       prot.secure0_range, SEC_REGION_START_ADDR);
	otp_print_protect_row("SECURE1", prot.secure1, 1,
			       prot.secure1_range, SEC_REGION_START_ADDR);
	otp_print_protect_row("SECURE2", prot.secure2, 1,
			       prot.secure2_range, SEC_REGION_START_ADDR);
	otp_print_protect_row("SECURE3", prot.secure3, 1,
			       prot.secure3_range, SEC_REGION_START_ADDR);
	otp_print_protect_row("CALIPTRA0", prot.caliptra0, 1,
			       prot.caliptra0_range, CAL_REGION_START_ADDR);
	otp_print_protect_row("CALIPTRA1", prot.caliptra1, 1,
			       prot.caliptra1_range, CAL_REGION_START_ADDR);
	otp_print_protect_row("CALIPTRA2", prot.caliptra2, 1,
			       prot.caliptra2_range, CAL_REGION_START_ADDR);
	otp_print_protect_row("CALIPTRA3", prot.caliptra3, 1,
			       prot.caliptra3_range, CAL_REGION_START_ADDR);

	printf("\n  %-20s %-8s%-8s%-6s%-10s%s\n", "Region", "RLock", "WLock", "", "Start", "End");
	otp_print_protect_sep(59);
	otp_print_puf_row("SW_PUF", !!(prot.puf & OTP_PROT_SW_PUF_RLOCK_BIT),
			   !!(prot.puf & OTP_PROT_SW_PUF_WLOCK_BIT),
			   SW_PUF_REGION_START_ADDR, SW_PUF_REGION_END_ADDR);
	otp_print_puf_row("HW_PUF", !!(prot.puf & OTP_PROT_HW_PUF_RLOCK_BIT),
			   !!(prot.puf & OTP_PROT_HW_PUF_WLOCK_BIT),
			   HW_PUF_REGION_START_ADDR, HW_PUF_REGION_END_ADDR);

	return OTP_SUCCESS;
}

static int otp_print_secure_image(struct otp_image_layout *image_layout)
{
	uint32_t *buf;

	buf = (uint32_t *)image_layout->secure;
	otp_print_key(buf);

	return OTP_SUCCESS;
}

static int otp_print_rbp_image(struct otp_image_layout *image_layout)
{
	const struct otprbp_info *rbp_info = info_cb.rbp_info;
	uint16_t *OTPRBP = (uint16_t *)image_layout->rbp;
	uint32_t w_offset;
	uint32_t length;

	printf("W     bit-length Description                               Value\n");
	printf("__________________________________________________________________________\n");
	for (int i = 0; i < info_cb.rbp_info_len; i++) {
		w_offset = rbp_info[i].w_offset;
		length = rbp_info[i].length;

		printf("0x%-4X", w_offset);
		printf("0x%-9X", length);
		printf("%-40s: ", rbp_info[i].information);

		for (int j = 0; j < (length + 15) / 16; j++)
			printf("0x%04x ", OTPRBP[w_offset + j]);
		printf("\n");
	}

	return OTP_SUCCESS;
}

static int otp_print_conf_image(struct otp_image_layout *image_layout)
{
	const struct otpconf_info *conf_info = info_cb.conf_info;
	uint16_t *OTPCFG = (uint16_t *)image_layout->conf;
	uint32_t w_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	uint32_t mask;

	printf("Word    Bit        Value       Description\n");
	printf("__________________________________________________________________________\n");
	for (int i = 0; i < info_cb.conf_info_len; i++) {
		w_offset = conf_info[i].w_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[w_offset] >> bit_offset) & mask;

		if (!otp_value)
			continue;

		if (conf_info[i].value != OTP_REG_VALUE && otp_value != conf_info[i].value)
			continue;

		printf("0x%-4X", w_offset);

		if (conf_info[i].length == 1) {
			printf("0x%-9X", conf_info[i].bit_offset);
		} else {
			printf("0x%-2X:0x%-4X",
			       conf_info[i].bit_offset + conf_info[i].length - 1,
			       conf_info[i].bit_offset);
		}
		printf("0x%-10x", otp_value);

		if (conf_info[i].value == OTP_REG_RESERVED) {
			printf("Reserved\n");

		} else if (conf_info[i].value == OTP_REG_VALUE) {
			printf(conf_info[i].information, otp_value);
			printf("\n");

		} else {
			printf("%s\n", conf_info[i].information);
		}
	}

	return OTP_SUCCESS;
}

static int otp_print_strap_image(struct otp_image_layout *image_layout)
{
	const struct otpstrap_info *strap_info = info_cb.strap_info;
	uint16_t *OTPSTRAP;
	uint16_t *OTPSTRAP_PRO;
	uint32_t w_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	uint32_t otp_protect;
	uint32_t mask;

	OTPSTRAP = (uint16_t *)image_layout->strap;
	OTPSTRAP_PRO = OTPSTRAP + 2;

	printf("Bit(hex)   Value       Protect     Description\n");
	printf("__________________________________________________________________________________________\n");

	for (int i = 0; i < info_cb.strap_info_len; i++) {
		if (strap_info[i].bit_offset > 15) {
			w_offset = 1;
			bit_offset = strap_info[i].bit_offset - 16;
		} else {
			w_offset = 0;
			bit_offset = strap_info[i].bit_offset;
		}

		mask = BIT(strap_info[i].length) - 1;
		otp_value = (OTPSTRAP[w_offset] >> bit_offset) & mask;
		otp_protect = (OTPSTRAP_PRO[w_offset] >> bit_offset) & mask;

		if (otp_value != strap_info[i].value)
			continue;

		if (strap_info[i].length == 1) {
			printf("0x%-9X", strap_info[i].bit_offset);
		} else {
			printf("0x%-2X:0x%-4X",
			       strap_info[i].bit_offset + strap_info[i].length - 1,
			       strap_info[i].bit_offset);
		}
		printf("0x%-10x", otp_value);
		printf("0x%-10x", otp_protect);
		printf("%s\n", strap_info[i].information);
	}

	return OTP_SUCCESS;
}

static int otp_print_strap_ext_image(struct otp_image_layout *image_layout)
{
	const struct otpstrap_ext_info *strap_ext_info = info_cb.strap_ext_info;
	uint16_t *OTPSTRAP_EXT;
	uint16_t *OTPSTRAP_EXT_VLD;
	uint32_t w_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	uint32_t otp_valid;
	uint32_t mask;

	OTPSTRAP_EXT = (uint16_t *)image_layout->strap_ext;
	OTPSTRAP_EXT_VLD = OTPSTRAP_EXT + 8;

	printf("Bit(hex)   Value       Valid     Description\n");
	printf("__________________________________________________________________________________________\n");

	for (int i = 0; i < info_cb.strap_ext_info_len; i++) {
		w_offset = strap_ext_info[i].bit_offset / 16;
		bit_offset = strap_ext_info[i].bit_offset % 16;

		mask = BIT(strap_ext_info[i].length) - 1;
		otp_value = (OTPSTRAP_EXT[w_offset] >> bit_offset) & mask;
		otp_valid = (OTPSTRAP_EXT_VLD[w_offset] >> bit_offset) & mask;

		if (!otp_value && !otp_valid)
			continue;

		if (otp_value != strap_ext_info[i].value)
			continue;

		if (strap_ext_info[i].length == 1) {
			printf("0x%-9X", strap_ext_info[i].bit_offset);
		} else {
			printf("0x%-2X:0x%-4X",
			       strap_ext_info[i].bit_offset + strap_ext_info[i].length - 1,
			       strap_ext_info[i].bit_offset);
		}
		printf("0x%-10x", otp_value);
		printf("0x%-10x", otp_valid);
		printf("%s\n", strap_ext_info[i].information);
	}

	return OTP_SUCCESS;
}

static int otp_print_cptra_image(struct otp_image_layout *image_layout)
{
	const struct otpcal_info *cal_info = info_cb.cal_info;
	uint16_t *OTPCAL = (uint16_t *)image_layout->cptra;
	uint32_t w_offset;
	uint32_t otp_value;
	uint32_t bit_len;

	printf("Word    Bit-length      Value       Description\n");
	printf("__________________________________________________________________________\n");
	for (int i = 0; i < info_cb.cal_info_len; i++) {
		w_offset = cal_info[i].w_offset;
		bit_len = cal_info[i].length;

		if (bit_len <= 32)
			otp_value = OTPCAL[w_offset] & (BIT(bit_len) - 1);
		else
			otp_value = OTPCAL[w_offset];

		if (cal_info[i].value != OTP_REG_VALUE && otp_value != cal_info[i].value)
			continue;

		printf("0x%-6X0x%-14X0x%-10x", w_offset, bit_len, otp_value);

		if (cal_info[i].value == OTP_REG_RESERVED) {
			printf("Reserved\n");

		} else if (cal_info[i].value == OTP_REG_VALUE) {
			printf(cal_info[i].information, otp_value);
			for (int i = 0; i < bit_len / 16; i++) {
				if (!otp_value)
					break;
				if (i % 8 == 0)
					printf("\n\t\t\t\t%02x: 0x%04x ", i, OTPCAL[w_offset + i]);
				else
					printf("0x%04x ", OTPCAL[w_offset + i]);
			}
			printf("\n");

		} else {
			printf("%s\n", cal_info[i].information);
		}
	}

	return OTP_SUCCESS;
}

static int otp_check_strap_image(struct otp_image_layout *image_layout,
				 struct otpstrap_status *otpstrap)
{
	int bit, pbit, ret;
	int fail = 0;
	uint16_t *strap;

	strap = (uint16_t *)image_layout->strap;

	for (int i = 0; i < 32; i++) {
		if (i < 16) {
			bit = (strap[0] >> i) & 0x1;
			pbit = (strap[2] >> i) & 0x1;
		} else {
			bit = (strap[1] >> (i - 16)) & 0x1;
			pbit = (strap[3] >> (i - 16)) & 0x1;
		}

		ret = otp_strap_bit_confirm(&otpstrap[i], i, bit, pbit);

		if (ret == OTP_FAILURE)
			fail = 1;
	}

	if (fail == 1) {
		printf("Input image can't program into OTP, please check.\n");
		return OTP_FAILURE;
	}

	return OTP_SUCCESS;
}

static int otp_prog_image(char *path, int nconfirm, bool ecc_force)
{
	struct otp_image_layout image_layout;
	struct otpstrap_status otpstrap[32];
	struct otp_header *otp_header;
	int image_soc_ver = 0;
	int image_size;
	int ret;
	uint8_t *checksum;
	uint8_t *buf;
	long fsize;
	FILE *fd;

	fd = fopen(path, "rb");
	if (!fd) {
		printf("failed to open %s\n", path);
		ret = OTP_FAILURE;
		goto end;
	}
	fseek(fd, 0, SEEK_END);
	fsize = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	buf = malloc(fsize + 1);
	ret = fread(buf, 1, fsize, fd);
	if (ret != fsize) {
		printf("Reading \"%s\" failed\n", path);
		ret = OTP_FAILURE;
		goto end;
	}
	fclose(fd);
	buf[fsize] = 0;

	otp_header = (struct otp_header *)buf;
	if (!otp_header) {
		printf("Failed to map physical memory\n");
		ret = OTP_FAILURE;
		goto end;
	}

	image_size = OTP_IMAGE_SIZE(otp_header->image_info);
	printf("image_info:0x%x image_size: 0x%x\n", otp_header->image_info, image_size);

	checksum = buf + otp_header->checksum_offset;

	/* Check Image Magic */
	if (strncmp(OTP_MAGIC, (char *)otp_header->otp_magic, strlen(OTP_MAGIC)) != 0) {
		printf("Image is invalid, magic 0x%x should be %s\n",
		       *(uint32_t *)otp_header->otp_magic, OTP_MAGIC);
		ret = OTP_FAILURE;
		goto end;
	}

	image_layout.rom_length = OTP_REGION_SIZE(otp_header->rom_info);
	image_layout.rom = buf + OTP_REGION_OFFSET(otp_header->rom_info);

	image_layout.rbp_length = OTP_REGION_SIZE(otp_header->rbp_info);
	image_layout.rbp = buf + OTP_REGION_OFFSET(otp_header->rbp_info);

	image_layout.conf_length = OTP_REGION_SIZE(otp_header->config_info);
	image_layout.conf = buf + OTP_REGION_OFFSET(otp_header->config_info);

	image_layout.strap_length = OTP_REGION_SIZE(otp_header->strap_info);
	image_layout.strap = buf + OTP_REGION_OFFSET(otp_header->strap_info);

	image_layout.strap_ext_length = OTP_REGION_SIZE(otp_header->strap_ext_info);
	image_layout.strap_ext = buf + OTP_REGION_OFFSET(otp_header->strap_ext_info);

	image_layout.secure_length = OTP_REGION_SIZE(otp_header->secure_info);
	image_layout.secure = buf + OTP_REGION_OFFSET(otp_header->secure_info);

	image_layout.cptra_length = OTP_REGION_SIZE(otp_header->cptra_info);
	image_layout.cptra = buf + OTP_REGION_OFFSET(otp_header->cptra_info);

	image_layout.user_length = OTP_REGION_SIZE(otp_header->user_info);
	image_layout.user = buf + OTP_REGION_OFFSET(otp_header->user_info);

	if (otp_header->soc_ver == SOC_AST2700A0) {
		image_soc_ver = OTP_AST2700_A0;
	} else if (otp_header->soc_ver == SOC_AST2700A1) {
		image_soc_ver = OTP_AST2700_A1;
	} else if (otp_header->soc_ver == SOC_AST2700A2) {
		image_soc_ver = OTP_AST2700_A2;
	} else {
		printf("Image SOC Version is not supported\n");
		ret = OTP_FAILURE;
		goto end;
	}

	if (image_soc_ver != info_cb.version) {
		printf("Image SOC version is not match to HW SOC version\n");
		ret = OTP_FAILURE;
		goto end;
	}

	ret = otp_verify_image(buf, image_size, checksum);
	if (ret) {
		printf("checksum is invalid\n");
		ret = OTP_FAILURE;
		goto end;
	}

	if (info_cb.pro_sts.fields.mem_lock) {
		printf("OTP memory is locked\n");
		ret = OTP_FAILURE;
		goto end;
	}

	ret = 0;
	if (otp_header->image_info & OTP_INC_ROM) {
		if (info_cb.pro_sts.fields.w_prot_rom) {
			printf("OTP rom region is write protected\n");
			ret = -1;
		}
	}

	if (otp_header->image_info & OTP_INC_CONFIG) {
		if (info_cb.pro_sts.fields.w_prot_conf) {
			printf("OTP config region is write protected\n");
			ret = -1;
		}
	}

	if (otp_header->image_info & OTP_INC_STRAP) {
		if (info_cb.pro_sts.fields.w_prot_strap) {
			printf("OTP strap region is write protected\n");
			ret = -1;
		}
		printf("Read OTP Strap Region:\n");
		otp_strap_status(otpstrap);

		printf("Check writable...\n");
		if (otp_check_strap_image(&image_layout, otpstrap) == OTP_FAILURE)
			ret = -1;
	}

	if (otp_header->image_info & OTP_INC_STRAP_EXT) {
		if (info_cb.pro_sts.fields.w_prot_strap_ext) {
			printf("OTP strap extension region is write protected\n");
			ret = -1;
		}
	}

	if (otp_header->image_info & OTP_INC_CALIPTRA) {
		if (info_cb.pro_sts.fields.w_prot_cal) {
			printf("OTP cptra region is write protected\n");
			ret = -1;
		}
	}

	if (ret == -1) {
		ret = OTP_FAILURE;
		goto end;
	}

	if (!nconfirm) {
		if (otp_header->image_info & OTP_INC_ROM) {
			printf("\nOTP ROM region :\n");
			if (otp_print_rom_image(&image_layout) < 0) {
				printf("OTP print rom error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_RBP) {
			printf("\nOTP RBP region :\n");
			if (otp_print_rbp_image(&image_layout) < 0) {
				printf("OTP print rbp error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_SECURE) {
			printf("\nOTP secure region :\n");
			if (otp_print_secure_image(&image_layout) < 0) {
				printf("OTP print secure error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_CONFIG) {
			printf("\nOTP configuration region :\n");
			if (otp_print_conf_image(&image_layout) < 0) {
				printf("OTP config error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_STRAP) {
			printf("\nOTP strap region :\n");
			if (otp_print_strap_image(&image_layout) < 0) {
				printf("OTP strap error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_STRAP_EXT) {
			printf("\nOTP strap extension region :\n");
			if (otp_print_strap_ext_image(&image_layout) < 0) {
				printf("OTP strap_ext error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_CALIPTRA) {
			printf("\nOTP caliptra region :\n");
			if (otp_print_cptra_image(&image_layout) < 0) {
				printf("OTP caliptra error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}
		if (otp_header->image_info & OTP_INC_USER) {
			printf("\nOTP user region :\n");
			if (otp_print_user_image(&image_layout) < 0) {
				printf("OTP user error, please check.\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}

		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			ret = OTP_FAILURE;
			goto end;
		}
	}

	if (otp_header->image_info & OTP_INC_ROM) {
		printf("programing rom region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_ROM, ecc_force);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_RBP) {
		printf("programing rbp region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_RBP, ecc_force);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_SECURE) {
		printf("programing secure region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_SECURE, ecc_force);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_CONFIG) {
		printf("programing configuration region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CONF, ecc_force);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		printf("programing strap region ...\n");
		ret = otp_prog_strap_image(&image_layout, otpstrap);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_STRAP_EXT) {
		printf("programing strap extension region ...\n");
		ret = otp_prog_strap_ext_image(&image_layout, ecc_force);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_CALIPTRA) {
		printf("programing caliptra region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CALIPTRA, ecc_force);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_USER) {
		printf("programing user region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_USER, ecc_force);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}

	return OTP_SUCCESS;
end:
	return ret;
}

struct reprog_ecc_entry {
	const char *name;
	uint32_t    ecc_id;      /* OTP_REGION_ID_* for ASPEED_OTP_SET_ECC_POLICY */
	int         mode;        /* OTP_REGION_* for otp_prog_data */
	uint32_t    word_offset; /* starting word offset within the region */
	uint32_t    n_words;
	int        (*read_fn)(uint32_t offset, uint16_t *data);
};

/* within USER: [0, ROMPATCH_WORD_OFFSET) is user data, the rest is rom patch */
#define USER_REGION_ROMPATCH_WORD_OFFSET	0x280

static int otp_ecc_policy_region_id(const char *name, uint32_t *id);

static const struct reprog_ecc_entry reprog_ecc_tbl[] = {
	{ "rom",           OTP_REGION_ID_ROM,      OTP_REGION_ROM,           0,
	  OTP_ROM_REGION_SIZE, otp_read_rom },
	{ "conf",          OTP_REGION_ID_CFG,      OTP_REGION_CONF,          0,
	  OTP_CONF_REGION_SIZE, otp_read_conf },
	{ "strap-ext",     OTP_REGION_ID_STRAPEXT, OTP_REGION_STRAP_EXT,     0,
	  OTP_STRAP_EXT_REGION_SIZE / 2, otp_read_strap_ext },
	{ "strap-ext-vld", OTP_REGION_ID_STRAPEXT, OTP_REGION_STRAP_EXT_VLD, 0,
	  OTP_STRAP_EXT_REGION_SIZE / 2, otp_read_strap_ext_vld },
	{ "u-data",        OTP_REGION_ID_USR,      OTP_REGION_USER,         0,
	  USER_REGION_ROMPATCH_WORD_OFFSET, otp_read_udata },
	{ "u-rompatch",    OTP_REGION_ID_USR,      OTP_REGION_USER,
	  USER_REGION_ROMPATCH_WORD_OFFSET,
	  OTP_USER_REGION_SIZE - USER_REGION_ROMPATCH_WORD_OFFSET, otp_read_udata },
	{ "s-data",        OTP_REGION_ID_SEC,      OTP_REGION_SECURE,       0,
	  OTP_SEC_REGION_SIZE, otp_read_sdata },
	{ "cptra",         OTP_REGION_ID_CAL,      OTP_REGION_CALIPTRA,     0,
	  OTP_CAL_REGION_SIZE, otp_read_cptra },
};

/*
 * Reads [start, end) raw (non-ECC) looking for a word with a non-zero
 * hardware ECC code. That is unambiguous proof the region was burned
 * with ECC parity - a cell's ECC bits can't end up non-zero unless ECC
 * encoding actually wrote them. The converse does not hold: a word's
 * ECC code can legitimately compute to zero even when ECC was used (it
 * depends on the data pattern), so a zero code proves nothing and is
 * not interesting here - only the first non-zero one, wherever it is,
 * settles the question and ends the scan.
 *
 * A locked word (OTP_CMD_ERR_REGION_FAIL) proves nothing either way, so
 * it's skipped and the scan continues - it would otherwise mask whatever
 * the rest of the region's words have to say. Any other read error means
 * the probe itself can't be trusted, so unlike a locked word it's
 * reported back to the caller via *probe_failed rather than guessed at.
 *
 * Returns true if ECC was found, false otherwise; *probe_failed is set
 * if a non-lock read error cut the scan short, in which case the false
 * returned alongside it does NOT mean "confirmed no ECC".
 */
static bool otp_region_has_ecc(uint32_t start, uint32_t end, const char *name,
			       bool *probe_failed)
{
	uint16_t data;
	uint32_t ecc_code;
	uint32_t addr;

	*probe_failed = false;

	for (addr = start; addr < end; addr++) {
		data = 0;
		ecc_code = 0;
		if (otp_read_ecc_code(addr, &data, &ecc_code)) {
			if (errno == OTP_CMD_ERR_REGION_FAIL)
				continue;
			printf("OTP reprog_ecc: %s ECC-code probe failed at 0x%x: %s\n",
			       name, addr, otp_cmd_errno_str(errno));
			*probe_failed = true;
			return false;
		}

		if (data && ecc_code) {
			printf("  %-14s 0x%04x   0x%04x   0x%02x\n", name, addr, data, ecc_code);
			return true;
		}
	}

	printf("  %-14s %-9s%-9sno ECC found\n", name, "-", "-");
	return false;
}

/*
 * reprog_ecc --ref <verified_dump>
 *
 * The reference is an otp dump image that the caller has already verified
 * (word N of the OTP is at byte offset 2 * N). A word is only re-programmed
 * when the raw device read is identical to the reference.
 *
 * A word that cannot be read because it is locked (OTP_CMD_ERR_REGION_FAIL) is
 * neither compared nor programmed; the locked ranges are reported so that the
 * caller can check them. Any other read error fails the command.
 */
#define REPROG_REF_MAX_BYTES        0x10000
#define REPROG_MISMATCH_PRINT_MAX   16

/* A single OTP write pulse does not always fully latch a fuse bit on the
 * first try, so each word is burned this many times, waiting between
 * passes - matching u-boot's reprog_ecc.
 */
#define OTP_REPROG_ECC_PASSES       3
#define OTP_REPROG_ECC_WAIT_SEC     3

/* Absolute OTP word address (= word index in an otp dump) of word w of entry r */
static uint32_t reprog_ecc_abs_addr(const struct reprog_ecc_entry *r, uint32_t w)
{
	uint32_t off = r->word_offset + w;

	switch (r->mode) {
	case OTP_REGION_ROM:
		return ROM_REGION_START_ADDR + off;
	case OTP_REGION_CONF:
		return CONF_REGION_START_ADDR + off;
	case OTP_REGION_STRAP_EXT:
		return STRAPEXT_REGION_START_ADDR + off;
	case OTP_REGION_STRAP_EXT_VLD:
		return STRAPEXT_REGION_START_ADDR + 0x8 + off;
	case OTP_REGION_USER:
		return USER_REGION_START_ADDR + off;
	case OTP_REGION_SECURE:
		return SEC_REGION_START_ADDR + off;
	case OTP_REGION_CALIPTRA:
		return CAL_REGION_START_ADDR + off;
	default:
		return UINT32_MAX;
	}
}

static int reprog_load_ref(const char *path, uint16_t **buf, size_t *n_words)
{
	FILE *fd = fopen(path, "rb");
	long size;
	size_t got;

	if (!fd) {
		printf("Failed to open reference file '%s': %s\n", path, strerror(errno));
		return -1;
	}
	if (fseek(fd, 0, SEEK_END)) {
		printf("Failed to get the size of reference file '%s'\n", path);
		fclose(fd);
		return -1;
	}
	size = ftell(fd);
	if (size < 0 || fseek(fd, 0, SEEK_SET)) {
		printf("Failed to get the size of reference file '%s'\n", path);
		fclose(fd);
		return -1;
	}
	if (size == 0 || (size & 1) || size > REPROG_REF_MAX_BYTES) {
		printf("Reference file '%s' has an invalid size (%ld bytes)\n", path, size);
		fclose(fd);
		return -1;
	}

	*buf = malloc(size);
	if (!*buf) {
		printf("Out of memory\n");
		fclose(fd);
		return -1;
	}
	got = fread(*buf, 1, size, fd);
	fclose(fd);
	if (got != (size_t)size) {
		printf("Failed to read reference file '%s'\n", path);
		free(*buf);
		*buf = NULL;
		return -1;
	}

	*n_words = size / 2;
	return 0;
}

/*
 * Compare the raw read of table entry r (buf, locked) with the reference.
 * Words that are locked or differ from the reference are cleared in buf so
 * that they are never programmed. Returns -1 if the reference does not cover
 * the entry, otherwise 0 with *mismatches increased by the number of differing
 * words.
 */
static int reprog_ecc_check_ref(const struct reprog_ecc_entry *r, uint16_t *buf,
				const bool *locked, const uint16_t *ref, size_t ref_words,
				unsigned int *mismatches)
{
	unsigned int n_cmp = 0, n_lock = 0;
	bool in_lock = false;
	uint32_t lock_first = 0, lock_last = 0;

	for (uint32_t w = 0; w < r->n_words; w++) {
		uint32_t waddr = reprog_ecc_abs_addr(r, w);
		bool bad = false;

		if (waddr >= ref_words) {
			printf("  Reference file is too short for '%s' (word 0x%x, reference has %zu words)\n",
			       r->name, waddr, ref_words);
			return -1;
		}

		if (locked[w]) {
			n_lock++;
		} else {
			n_cmp++;
			if (buf[w] != ref[waddr])
				bad = true;
		}

		if (bad) {
			if (*mismatches < REPROG_MISMATCH_PRINT_MAX)
				printf("  MISMATCH '%s' word 0x%04x: device=0x%04x ref=0x%04x\n",
				       r->name, waddr, buf[w], ref[waddr]);
			(*mismatches)++;
		}

		if (locked[w] && in_lock && waddr == lock_last + 1) {
			lock_last = waddr;
		} else {
			if (in_lock)
				printf("  LOCKED '%s' words 0x%04x-0x%04x\n", r->name, lock_first, lock_last);
			in_lock = locked[w];
			lock_first = waddr;
			lock_last = waddr;
		}

		if (locked[w] || bad)
			buf[w] = 0;
	}
	if (in_lock)
		printf("  LOCKED '%s' words 0x%04x-0x%04x\n", r->name, lock_first, lock_last);

	printf("  '%s': compared %u, locked %u\n", r->name, n_cmp, n_lock);
	return 0;
}

static void otp_print_hash_line(const uint8_t *hash, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x", hash[i]);
	printf("\n");
}

static int do_otpreprog_ecc(int argc, char *const argv[])
{
	int global_status = OTP_ECC_GLOBAL_DISABLED;
	int nconfirm = 0;
	int filter_ecc_id = -1;
	const char *filter_name = NULL;
	const char *ref_path = NULL;
	bool dry_run = false;
	bool ref_mode;
	bool region_has_ecc[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	bool region_probe_failed[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	bool region_mismatch[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	bool region_read_failed[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	/*
	 * Sticky across the whole command: ret itself gets reassigned by
	 * every later step (even on success), so a probe failure recorded
	 * here would otherwise be overwritten by a later step's success
	 * before reaching the final "ret == CMD_RET_SUCCESS" check.
	 */
	bool any_probe_failed = false;
	bool policy_saved[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	uint32_t saved_ecc_en[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	uint16_t *bufs[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	bool *locked[ARRAY_SIZE(reprog_ecc_tbl)] = {};
	uint16_t *ref = NULL;
	size_t ref_words = 0;
	unsigned int mismatches = 0;
	uint8_t pre_hash[ARRAY_SIZE(reprog_ecc_tbl)][48];
	uint8_t post_hash[48];
	int ret;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "o")) {
			nconfirm = 1;
		} else if (!strcmp(argv[i], "--ref") && i + 1 < argc && !ref_path) {
			ref_path = argv[++i];
		} else if (!strcmp(argv[i], "--dry_run")) {
			dry_run = true;
		} else {
			uint32_t id;

			if (filter_ecc_id >= 0 || otp_ecc_policy_region_id(argv[i], &id))
				return CMD_RET_USAGE;
			filter_ecc_id = (int)id;
			filter_name = argv[i];
		}
	}

	ref_mode = ref_path;
	if (dry_run && !ref_mode)
		return CMD_RET_USAGE;

	if (filter_ecc_id >= 0) {
		bool has_entry = false;

		for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
			if ((int)reprog_ecc_tbl[i].ecc_id == filter_ecc_id)
				has_entry = true;
		}
		if (!has_entry) {
			printf("Region '%s' cannot be re-programmed\n", filter_name);
			return CMD_RET_FAILURE;
		}
	}

	if (ref_mode) {
		if (reprog_load_ref(ref_path, &ref, &ref_words)) {
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
	}

	/* Step 1: check global ECC */
	ret = otp_ecc_get_status(&global_status);
	if (ret) {
		printf("Failed to get ECC status\n");
		ret = CMD_RET_FAILURE;
		goto free_bufs;
	}

	if (global_status != OTP_ECC_GLOBAL_DISABLED) {
		printf("Global ECC is already enabled\n");
		ret = CMD_RET_SUCCESS;
		goto free_bufs;
	}

	printf("Global ECC is disabled\n");

	/* Each region is probed over its own full address range from the table. */
	printf("OTP reprog_ecc: ECC detection\n");
	printf("  %-14s %-9s%-9s%s\n", "Region", "Addr", "Data", "ECC Code");
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];
		bool probe_failed;

		if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
			continue;

		region_has_ecc[i] = otp_region_has_ecc(reprog_ecc_abs_addr(r, 0),
							reprog_ecc_abs_addr(r, r->n_words),
							r->name, &probe_failed);
		if (probe_failed) {
			region_probe_failed[i] = true;
			region_has_ecc[i] = true; /* fail-safe: still skip steps 2-4 */
			any_probe_failed = true;
		}
	}

	if (filter_ecc_id >= 0 && !any_probe_failed) {
		bool all_has_ecc = true;

		for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
			if ((int)reprog_ecc_tbl[i].ecc_id != filter_ecc_id)
				continue;
			if (!region_has_ecc[i])
				all_has_ecc = false;
		}
		if (all_has_ecc) {
			printf("Region '%s' already has ECC, nothing to do\n", filter_name);
			ret = CMD_RET_SUCCESS;
			goto free_bufs;
		}
	}

	if (!nconfirm && !dry_run) {
		if (filter_ecc_id >= 0)
			printf("This will re-program the '%s' OTP region with ECC.\n", filter_name);
		else
			printf("This will re-program all ECC-capable OTP regions with ECC.\n");
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf("Aborting\n");
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
	}

	/*
	 * A region's own ECC policy can force raw reads to come back
	 * ECC-decoded even while the global switch below is off, so each
	 * touched region's policy is saved and forced off for the duration
	 * of this command, restored in free_bufs: regardless of outcome.
	 *
	 * Some entries share an ecc_id (e.g. strap-ext/strap-ext-vld are
	 * both OTP_REGION_ID_STRAPEXT, u-data/u-rompatch are both
	 * OTP_REGION_ID_USR), since one hardware policy register can cover
	 * more than one table row. A duplicate must not be read again here
	 * - the first pass already forced it to 0, so a second read would
	 * save that 0 instead of the real original value and clobber the
	 * correct restore done for the first occurrence. Copy the already
	 * saved value instead and skip touching the hardware again.
	 */
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];
		uint32_t ecc_supported;
		int dup;

		if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
			continue;

		for (dup = 0; dup < i; dup++) {
			if (policy_saved[dup] && reprog_ecc_tbl[dup].ecc_id == r->ecc_id)
				break;
		}
		if (dup < i) {
			saved_ecc_en[i] = saved_ecc_en[dup];
			policy_saved[i] = true;
			continue;
		}

		if (otp_get_ecc_policy(r->ecc_id, &saved_ecc_en[i], &ecc_supported)) {
			printf("OTP reprog_ecc: failed to read %s's ECC policy\n", r->name);
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
		if (otp_set_ecc_policy(r->ecc_id, 0)) {
			printf("OTP reprog_ecc: failed to disable %s's ECC policy\n", r->name);
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
		policy_saved[i] = true;
	}

	/*
	 * Step 2: read all regions raw. Matches u-boot's reprog_ecc: ECC
	 * encode/decode during the read/program sequence below is toggled
	 * via the temporary global switch (otp_ecc_ctrl()), not by leaving
	 * any region's persistent ECC policy changed - that policy was only
	 * forced off above to stop it from interfering with this raw read,
	 * and is restored in free_bufs: regardless of outcome.
	 */
	ret = otp_ecc_ctrl(false);
	if (ret) {
		ret = CMD_RET_FAILURE;
		goto free_bufs;
	}

	printf("Reading all regions (raw, ECC disabled)...\n");
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];

		if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
			continue;
		if (region_has_ecc[i])
			continue;

		bufs[i] = calloc(r->n_words, sizeof(uint16_t));
		locked[i] = calloc(r->n_words, sizeof(bool));
		if (!bufs[i] || !locked[i]) {
			printf("Out of memory\n");
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
		for (uint32_t w = 0; w < r->n_words; w++) {
			uint32_t addr = r->word_offset + w;
			uint16_t val = 0;

			if (r->read_fn(addr, &val)) {
				if (errno == OTP_CMD_ERR_REGION_FAIL) {
					/*
					 * Locked word: not compared, not programmed. Marked
					 * regardless of ref_mode so Step 4's verify re-read
					 * (which checks locked[]) skips it too, instead of
					 * re-triggering the same read failure there.
					 */
					locked[i][w] = true;
					val = 0;
				} else if (ref_mode || errno < OTP_CMD_ERR_BASE) {
					printf("  Read failed at '%s' offset 0x%x: %s\n",
					       r->name, addr, otp_cmd_errno_str(errno));
					ret = CMD_RET_FAILURE;
					goto free_bufs;
				}
			}
			bufs[i][w] = val;
		}

		otp_sha384((uint8_t *)bufs[i], r->n_words * sizeof(uint16_t), pre_hash[i]);
		printf("  '%-13s' pre-hash (sha384):  ", r->name);
		otp_print_hash_line(pre_hash[i], 48);
	}

	/*
	 * Compare the raw read with the reference; nothing is programmed on
	 * a mismatch. cptra holds per-chip-unique key material, so there is
	 * no such thing as a reference dump valid across chips for it - skip
	 * it here and reprogram it from its own raw read instead, same as
	 * when no reference is given at all.
	 */
	if (ref_mode) {
		printf("Comparing %s with reference '%s'...\n",
		       filter_name ? filter_name : "all regions", ref_path);
		for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
			if (filter_ecc_id >= 0 && (int)reprog_ecc_tbl[i].ecc_id != filter_ecc_id)
				continue;
			if (region_has_ecc[i])
				continue;
			if (reprog_ecc_tbl[i].ecc_id == OTP_REGION_ID_CAL)
				continue;

			if (reprog_ecc_check_ref(&reprog_ecc_tbl[i], bufs[i], locked[i],
						 ref, ref_words, &mismatches)) {
				ret = CMD_RET_FAILURE;
				goto free_bufs;
			}
		}
		if (mismatches) {
			printf("Reference mismatch on %u word(s), nothing programmed\n", mismatches);
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}
		if (dry_run) {
			printf("Dry run: reference matches, nothing programmed\n");
			ret = CMD_RET_SUCCESS;
			goto free_bufs;
		}
	}

	/*
	 * Step 3: re-program each region so HW computes and burns ECC bits,
	 * over multiple passes (matching u-boot's reprog_ecc). ECC is
	 * turned on via the temporary global switch right before each
	 * region's words are written, rather than via that region's
	 * persistent ECC policy.
	 */
	for (int pass = 0; pass < OTP_REPROG_ECC_PASSES; pass++) {
		if (pass > 0) {
			printf("Waiting %ds...\n", OTP_REPROG_ECC_WAIT_SEC);
			sleep(OTP_REPROG_ECC_WAIT_SEC);
		}
		printf("Pass %d/%d\n", pass + 1, OTP_REPROG_ECC_PASSES);

		for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
			const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];

			if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
				continue;
			if (region_has_ecc[i])
				continue;

			ret = otp_ecc_ctrl(true);
			if (ret) {
				ret = CMD_RET_FAILURE;
				goto free_bufs;
			}

			for (uint32_t w = 0; w < r->n_words; w++) {
				uint32_t addr = r->word_offset + w;
				uint16_t val = bufs[i][w];

				if (!val)
					continue;
				ret = otp_prog_data(r->mode, addr, 0, val, 1, false);
				if (ret) {
					printf("  Prog failed at '%s' offset 0x%x: %s\n",
					       r->name, addr, otp_cmd_errno_str(errno));
					ret = CMD_RET_FAILURE;
					goto free_bufs;
				}
			}
		}
	}

	/*
	 * Step 4: verify - ECC-read each programmed region back and compare
	 * its hash against the pre-program (raw) hash. Programming is
	 * supposed to only add ECC parity, never change the visible data, so
	 * a mismatch here means something went wrong - but since the OTP
	 * write already happened and can't be undone, every region is still
	 * checked and reported rather than aborting on the first mismatch.
	 *
	 * This step only prepares region *data* for ECC; it never touches
	 * the OTPSTRAP global-ECC fuse itself - run 'otp <dev> ecc enable'
	 * separately afterward to permanently latch global ECC on.
	 */
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];
		bool read_ok = true;

		if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
			continue;
		if (region_has_ecc[i])
			continue;

		ret = otp_ecc_ctrl(true);
		if (ret) {
			ret = CMD_RET_FAILURE;
			goto free_bufs;
		}

		for (uint32_t w = 0; w < r->n_words; w++) {
			uint32_t addr = r->word_offset + w;

			if (locked[i] && locked[i][w])
				continue;

			if (r->read_fn(addr, &bufs[i][w])) {
				printf("  Verify read failed at '%s' offset 0x%x: %s\n",
				       r->name, addr, otp_cmd_errno_str(errno));
				read_ok = false;
				break;
			}
		}

		if (!read_ok) {
			printf("  '%s': skipping hash verification (read failed)\n", r->name);
			region_read_failed[i] = true;
			ret = CMD_RET_FAILURE;
			continue;
		}

		otp_sha384((uint8_t *)bufs[i], r->n_words * sizeof(uint16_t), post_hash);

		if (memcmp(pre_hash[i], post_hash, 48) != 0) {
			printf("  '%-13s' post-hash (sha384): ", r->name);
			otp_print_hash_line(post_hash, 48);
			printf("  '%-13s' hash mismatch after programming - data may be corrupted\n",
			       r->name);
			region_mismatch[i] = true;
			ret = CMD_RET_FAILURE;
		}
	}

	printf("\nOTP reprog_ecc: summary\n");
	printf("  %-14s %-13s%-10s%s\n", "Region", "Policy(orig)", "Pre-ECC", "Result");
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		const struct reprog_ecc_entry *r = &reprog_ecc_tbl[i];
		const char *policy, *pre_ecc, *result, *color;

		if (filter_ecc_id >= 0 && (int)r->ecc_id != filter_ecc_id)
			continue;

		policy = policy_saved[i] ? (saved_ecc_en[i] ? "enabled" : "disabled") : "n/a";
		pre_ecc = region_probe_failed[i] ? "unknown" : (region_has_ecc[i] ? "yes" : "no");

		if (region_probe_failed[i]) {
			result = "PROBE FAILED";
			color = ANSI_COLOR_RED;
		} else if (region_has_ecc[i]) {
			result = "skipped";
			color = ANSI_COLOR_CYAN;
		} else if (region_read_failed[i]) {
			result = "READ FAILED";
			color = ANSI_COLOR_RED;
		} else if (region_mismatch[i]) {
			result = "MISMATCH";
			color = ANSI_COLOR_RED;
		} else {
			result = "verified OK";
			color = ANSI_COLOR_GREEN;
		}

		printf("  %-14s %-13s%-10s%s%s" ANSI_COLOR_RESET "\n",
		       r->name, policy, pre_ecc, color, result);
	}

	if (any_probe_failed)
		ret = CMD_RET_FAILURE;

	if (ret == CMD_RET_SUCCESS)
		printf(ANSI_COLOR_GREEN
		       "Done. Run 'otp <dev> ecc enable' to permanently enable global ECC."
		       ANSI_COLOR_RESET "\n");

free_bufs:
	/* Don't bother if ECC was never (or can't be) toggled off, e.g. it's hardware-latched on */
	if (global_status != OTP_ECC_GLOBAL_HW_ENABLED)
		otp_ecc_ctrl(false);
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		if (!policy_saved[i])
			continue;
		if (otp_set_ecc_policy(reprog_ecc_tbl[i].ecc_id, saved_ecc_en[i]))
			printf("OTP reprog_ecc: failed to restore %s's ECC policy\n",
			       reprog_ecc_tbl[i].name);
	}
	for (int i = 0; i < (int)ARRAY_SIZE(reprog_ecc_tbl); i++) {
		free(bufs[i]);
		free(locked[i]);
	}
	free(ref);
	return ret;
}

#define OTP_SCREEN_PROGRESS_STEP	1024	/* print a progress line every N words */

static int otp_screen_read_all(const char *phase_name, uint16_t *buf, bool *ok, int n_words)
{
	/*
	 * Try an OTP_IPC_READ_MAX_WORDS-word batch read first to cut down on
	 * mailbox round trips (the dominant per-word cost over IPC); both the
	 * native ioctl and the IPC path fail a batch all-or-nothing, so a
	 * batch that hits an unreadable word falls back to reading just that
	 * batch's words one at a time so the exact bad word(s) can still be
	 * marked unreadable instead of losing the whole batch's data.
	 */
	int offset = 0;

	while (offset < n_words) {
		uint16_t chunk[OTP_IPC_READ_MAX_WORDS];
		int batch_count = n_words - offset;
		bool got_batch;

		if (batch_count > OTP_IPC_READ_MAX_WORDS)
			batch_count = OTP_IPC_READ_MAX_WORDS;

		got_batch = (otp_read_raw_multi(offset, chunk, batch_count) == 0);
		if (!got_batch)
			batch_count = 1;

		for (int w = 0; w < batch_count; w++) {
			int cur = offset + w;
			int rc;

			if (cur && cur % OTP_SCREEN_PROGRESS_STEP == 0)
				printf("screen: %s read progress 0x%03x/0x%03x words (%u%%)\n",
				       phase_name, cur, n_words, cur * 100 / n_words);

			if (got_batch) {
				buf[cur] = chunk[w];
				ok[cur] = true;
				continue;
			}

			rc = otp_read_raw(cur, &buf[cur]);
			if (rc) {
				if (errno >= OTP_CMD_ERR_BASE) {
					/* any OTP-specific error: treat as unreadable, skip */
					buf[cur] = 0xffff;
					ok[cur] = false;
				} else {
					printf("OTP read failed at addr 0x%x: %s\n",
					       cur, otp_cmd_errno_str(errno));
					return rc;
				}
			} else {
				ok[cur] = true;
			}
		}

		offset += batch_count;
	}
	printf("screen: %s read done (%d words)\n", phase_name, n_words);
	return 0;
}

/*
 * otp screen              -- normal read -> margin read (IREF=OTP_SCREEN_IREF) -> compare
 * otp screen <golden.bin> -- golden binary -> margin read -> compare
 *
 * otp_set_read_mode() switches the read reference current before each read
 * phase and restores it to normal afterwards - native: direct /dev/mem
 * write to the DAP timing register; IPC: bootmcu does the same write on
 * its own OTP controller instance. Bits that differ between the reference
 * and the margin read are printed individually; the total error count is
 * shown at the end.
 */
static int do_otpscreen(int argc, char *const argv[])
{
	int n_words = SW_PUF_REGION_END_ADDR;
	uint16_t *normal_buf = NULL, *margin_buf = NULL, *golden_buf = NULL;
	bool *ok_normal = NULL, *ok_margin = NULL;
	int ret = CMD_RET_FAILURE;
	int margin_rc;
	int total_err = 0;
	int total_ones = 0;

	if (argc != 1 && argc != 2)
		return CMD_RET_USAGE;

	normal_buf = malloc(n_words * sizeof(uint16_t));
	margin_buf = malloc(n_words * sizeof(uint16_t));
	ok_normal  = malloc(n_words * sizeof(bool));
	ok_margin  = malloc(n_words * sizeof(bool));
	if (!normal_buf || !margin_buf || !ok_normal || !ok_margin) {
		printf("malloc failed\n");
		goto out;
	}

	/* --- Normal read phase --- */
	printf("Normal read...\n");
	if (otp_screen_read_all("normal", normal_buf, ok_normal, n_words))
		goto out;

	/* --- Margin read phase (IREF = OTP_SCREEN_IREF) --- */
	printf("Margin read (IREF=0x%x, DAP_RQ=0x%08x)...\n",
	       OTP_SCREEN_IREF, OTP_MARGIN_TIMING);
	if (otp_set_read_mode(OTP_READ_MODE_MARGIN)) {
		printf("Failed to switch to margin read mode\n");
		goto out;
	}
	margin_rc = otp_screen_read_all("margin", margin_buf, ok_margin, n_words);

	if (otp_set_read_mode(OTP_READ_MODE_NORMAL))
		printf("Warning: failed to restore normal read mode\n");

	if (margin_rc)
		goto out;

	/* --- Load golden binary if provided --- */
	if (argc == 2) {
		FILE *fd = fopen(argv[1], "rb");

		if (!fd) {
			printf("Failed to open golden file '%s': %s\n", argv[1], strerror(errno));
			goto out;
		}
		golden_buf = malloc(n_words * sizeof(uint16_t));
		if (!golden_buf) {
			fclose(fd);
			printf("malloc failed\n");
			goto out;
		}
		size_t got = fread(golden_buf, sizeof(uint16_t), n_words, fd);

		fclose(fd);
		if ((int)got != n_words) {
			printf("Golden file too short: got %zu words, need %d\n", got, n_words);
			goto out;
		}
	}

	/* --- Compare --- */
	const uint16_t *ref      = golden_buf ? golden_buf : normal_buf;
	const bool     *ok_ref   = golden_buf ? ok_margin  : ok_normal;
	const char     *ref_name = golden_buf ? "golden"   : "normal";

	printf("\n=== OTP screening: %s vs margin (IREF=0x%x) ===\n",
	       ref_name, OTP_SCREEN_IREF);

	for (int i = 0; i < n_words; i++) {
		uint16_t diff;

		if (!ok_ref[i] || !ok_margin[i])
			continue;

		total_ones += __builtin_popcount(ref[i]);

		diff = ref[i] ^ margin_buf[i];
		if (!diff)
			continue;

		for (int bit = 0; bit < 16; bit++) {
			if (!(diff & (1u << bit)))
				continue;
			printf("  word_addr=0x%04x  byte_offset=0x%05x  bit=%-2d"
			       "  %s=0x%04x  margin=0x%04x\n",
			       i, i * 2, bit, ref_name, ref[i], margin_buf[i]);
			total_err++;
		}
	}
	printf("\nTotal scanned bits (=1): %d\n", total_ones);
	printf("Total error bits:        %d\n", total_err);
	ret = CMD_RET_SUCCESS;

out:
	free(golden_buf);
	free(ok_margin);
	free(ok_normal);
	free(margin_buf);
	free(normal_buf);
	return ret;
}

static int do_otpinfo(int argc, char *const argv[])
{
	if (argc != 2 && argc != 3) {
		otp_err("otp info: bad argc %d", argc);
		return CMD_RET_USAGE;
	}

	if (!strcmp(argv[1], "rbp")) {
		otp_print_rbp_info();
	} else if (!strcmp(argv[1], "conf")) {
		otp_print_conf_info();
	} else if (!strcmp(argv[1], "strap")) {
		otp_print_strap_info();
	} else if (!strcmp(argv[1], "strap-ext")) {
		otp_print_strap_ext_info();
	} else if (!strcmp(argv[1], "key")) {
		otp_print_key_info();
	} else if (!strcmp(argv[1], "rompatch")) {
		otp_print_rom_patch_version();
	} else if (!strcmp(argv[1], "mt-stage")) {
		otp_print_mt_stage_info();
	} else if (!strcmp(argv[1], "hsm")) {
		otp_print_hsm_info();
	} else if (!strcmp(argv[1], "prot")) {
		return otp_print_protect_info() == OTP_SUCCESS ? CMD_RET_SUCCESS : CMD_RET_FAILURE;
	} else {
		otp_err("otp info: unknown region '%s'", argv[1]);
		return CMD_RET_USAGE;
	}

	return CMD_RET_SUCCESS;
}

static const struct {
	uint32_t start;
	const char *name;
} otp_dump_regions[] = {
	{ ROM_REGION_START_ADDR,      "ROM"       },
	{ RBP_REGION_START_ADDR,      "RBP"       },
	{ CONF_REGION_START_ADDR,     "CONF"      },
	{ STRAP_REGION_START_ADDR,    "STRAP"     },
	{ STRAPEXT_REGION_START_ADDR, "STRAP_EXT" },
	{ USER_REGION_START_ADDR,     "USER"      },
	{ SEC_REGION_START_ADDR,      "SECURE"    },
	{ CAL_REGION_START_ADDR,      "CALIPTRA"  },
	{ SW_PUF_REGION_START_ADDR,   "SW_PUF"    },
};

/*
 * Raw sequential dump of every OTP word except HW PUF (SOCOTP's one-way
 * cell-unique secret, not meant to ever be printed). All other regions are
 * laid out back-to-back from ROM_REGION_START_ADDR up to
 * HW_PUF_REGION_START_ADDR (== SW_PUF_REGION_END_ADDR), so a single flat
 * read covers ROM/RBP/CONF/STRAP/STRAPEXT/USER/SECURE/CALIPTRA/SW_PUF
 * without needing per-region dispatch.
 */
static int otp_print_all(void)
{
	uint16_t buf[8];
	uint32_t addr;
	int remaining, chunk;
	int rc;

	addr = ROM_REGION_START_ADDR;
	remaining = HW_PUF_REGION_START_ADDR - ROM_REGION_START_ADDR;

	printf("WordAddr  ByteAddr  Data\n");
	while (remaining > 0) {
		chunk = remaining > (int)ARRAY_SIZE(buf) ? (int)ARRAY_SIZE(buf) : remaining;

		for (int i = 0; i < (int)ARRAY_SIZE(otp_dump_regions); i++) {
			if (addr == otp_dump_regions[i].start) {
				printf("-- %s --\n", otp_dump_regions[i].name);
				break;
			}
		}

		rc = otp_read_raw_multi(addr, buf, chunk);
		if (rc) {
			otp_err("OTP read failed at word addr 0x%x", addr);
			return OTP_FAILURE;
		}

		printf("0x%04x    0x%04x   ", addr, addr * 2);
		for (int i = 0; i < chunk; i++)
			printf(" %04x", buf[i]);
		printf("\n");

		addr += chunk;
		remaining -= chunk;
	}

	return OTP_SUCCESS;
}

static int do_otpread(int argc, char *const argv[])
{
	uint32_t offset;
	int count;
	int ret;

	if (argc == 2 && !strcmp(argv[1], "all")) {
		ret = otp_print_all();
		return ret == OTP_SUCCESS ? CMD_RET_SUCCESS : CMD_RET_FAILURE;
	}

	if (argc == 4) {
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		count = (int)strtoul(argv[3], NULL, 16);
	} else if (argc == 3) {
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		count = 1;
	} else if (argc == 2) {
		/* region name only: dump the whole region from offset 0 */
		offset = 0;
		count = -1;
	} else {
		otp_err("otp read: bad argc %d", argc);
		return CMD_RET_USAGE;
	}

	if (!strcmp(argv[1], "rom")) {
		ret = otp_print_rom(offset, count);
	} else if (!strcmp(argv[1], "rbp")) {
		ret = otp_print_rbp(offset, count);
	} else if (!strcmp(argv[1], "conf")) {
		ret = otp_print_conf(offset, count);
	} else if (!strcmp(argv[1], "strap")) {
		ret = otp_print_strap(offset, count);
	} else if (!strcmp(argv[1], "strap-pro")) {
		ret = otp_print_strap_pro(offset, count);
	} else if (!strcmp(argv[1], "strap-ext")) {
		ret = otp_print_strap_ext(offset, count);
	} else if (!strcmp(argv[1], "strap-ext-vld")) {
		ret = otp_print_strap_ext_valid(offset, count);
	} else if (!strcmp(argv[1], "u-data")) {
		ret = otp_print_user_data(offset, count);
	} else if (!strcmp(argv[1], "s-data")) {
		ret = otp_print_sec_data(offset, count);
	} else if (!strcmp(argv[1], "cptra")) {
		ret = otp_print_cptra(offset, count);
	} else if (!strcmp(argv[1], "puf")) {
		ret = otp_print_puf(offset, count);
	} else {
		otp_err("otp read: unknown region '%s'", argv[1]);
		return CMD_RET_USAGE;
	}

	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	return CMD_RET_USAGE;
}

static int do_otpdump(int argc, char *const argv[])
{
	uint32_t offset;
	uint16_t data;
	int ret;
	FILE *fd;
	const char *filename = NULL;
	bool skip_locked_regions = false;
	int i;

	if (argc != 2 && argc != 3)
		return CMD_RET_USAGE;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--skip_locked_regions"))
			skip_locked_regions = true;
		else
			filename = argv[i];
	}

	if (!filename)
		return CMD_RET_USAGE;

	fd = fopen(filename, "wb");
	if (!fd) {
		printf("failed to open %s\n", filename);
		return CMD_RET_FAILURE;
	}

	/*
	 * Read all OTP memory up to the end of the SWPUF region. Try an
	 * OTP_IPC_READ_MAX_WORDS-word batch read first to cut down on
	 * mailbox round trips (the dominant per-word cost over IPC); both
	 * the native ioctl and the IPC path fail a batch all-or-nothing, so
	 * a batch that hits a read-protected word falls back to reading
	 * just that batch's words one at a time so --skip_locked_regions
	 * can still pinpoint exactly which word(s) are locked.
	 */
	offset = 0;
	while (offset < SW_PUF_REGION_END_ADDR) {
		uint16_t chunk[OTP_IPC_READ_MAX_WORDS];
		uint32_t batch_count = SW_PUF_REGION_END_ADDR - offset;
		bool got_batch;

		if (batch_count > OTP_IPC_READ_MAX_WORDS)
			batch_count = OTP_IPC_READ_MAX_WORDS;

		got_batch = (otp_read_raw_multi(offset, chunk, batch_count) == 0);
		if (!got_batch)
			batch_count = 1;

		for (uint32_t w = 0; w < batch_count; w++) {
			uint32_t cur = offset + w;

			for (int r = 0; r < ARRAY_SIZE(otp_dump_regions); r++) {
				if (cur == otp_dump_regions[r].start) {
					printf("dump: entering %-10s region at offset 0x%03x (%u/%u words)\n",
					       otp_dump_regions[r].name, cur, cur,
					       SW_PUF_REGION_END_ADDR);
					break;
				}
			}

			if (got_batch) {
				data = chunk[w];
			} else {
				ret = otp_read_raw(cur, &data);
				if (ret) {
					if (skip_locked_regions && errno == OTP_CMD_ERR_REGION_FAIL) {
						data = 0xffff;
					} else {
						printf("Failed to read OTP at offset 0x%x, ret = %d, errno = %d (%s)\n",
						       cur, ret, errno, otp_cmd_errno_str(errno));
						fclose(fd);
						return CMD_RET_FAILURE;
					}
				}
			}

			/* Write the 16-bit word to the file */
			if (fwrite(&data, 2, 1, fd) != 1) {
				printf("Failed to write to %s\n", filename);
				fclose(fd);
				return CMD_RET_FAILURE;
			}
		}

		offset += batch_count;
	}

	fclose(fd);
	printf("Successfully dumped OTP to %s\n", filename);

	return CMD_RET_SUCCESS;
}

static int do_otppatch(int argc, char *const argv[])
{
	uint8_t *addr;
	uint32_t offset;
	size_t size;
	int ret;

	printf("%s: argc:%d\n", __func__, argc);

	if (argc != 5)
		return CMD_RET_USAGE;

	/* Drop the cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "prog")) {
		addr = (uint8_t *)strtoul(argv[1], NULL, 16);
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		size = (size_t)strtoul(argv[3], NULL, 16);

		ret = otp_patch_prog(addr, offset, (uint32_t)size);

	} else if (!strcmp(argv[0], "enable")) {
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		size = (size_t)strtoul(argv[3], NULL, 16);

		if (!strcmp(argv[1], "pre"))
			ret = otp_patch_enable_pre(offset, size);

		else if (!strcmp(argv[1], "post"))
			ret = otp_patch_enable_post(offset, size);

		else
			return CMD_RET_USAGE;
	}

	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	else if (ret == OTP_FAILURE)
		return CMD_RET_FAILURE;
	else
		return CMD_RET_USAGE;
}

static int do_otpprog(int argc, char *const argv[])
{
	int ret, nconfirm = 0;
	/* "force": force past otp_prog_image_region()/otp_prog_strap_ext_image()'s
	 * incremental-program ECC warning
	 */
	bool ecc_force = false;
	char *path;
	int next = 1;

	while (argc > next && (!strcmp(argv[next], "o") || !strcmp(argv[next], "force"))) {
		if (!strcmp(argv[next], "o"))
			nconfirm = 1;
		else
			ecc_force = true;
		next++;
	}

	if (argc != next + 1) {
		otp_err("otp prog: bad argc %d", argc);
		return CMD_RET_USAGE;
	}

	path = argv[next];

	ret = otp_prog_image(path, nconfirm, ecc_force);
	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	else if (ret == OTP_FAILURE)
		return CMD_RET_FAILURE;
	else
		return CMD_RET_USAGE;
}

/* Maps otp_prog_data()'s otp_region to its ECC-policy region ID. */
static int otp_prog_region_ecc_id(int mode, uint32_t *id)
{
	switch (mode) {
	case OTP_REGION_ROM:
		*id = OTP_REGION_ID_ROM;
		break;
	case OTP_REGION_RBP:
		*id = OTP_REGION_ID_RBP;
		break;
	case OTP_REGION_CONF:
		*id = OTP_REGION_ID_CFG;
		break;
	case OTP_REGION_STRAP:
		*id = OTP_REGION_ID_STRAP;
		break;
	case OTP_REGION_STRAP_EXT:
	case OTP_REGION_STRAP_EXT_VLD:
		*id = OTP_REGION_ID_STRAPEXT;
		break;
	case OTP_REGION_USER:
		*id = OTP_REGION_ID_USR;
		break;
	case OTP_REGION_SECURE:
		*id = OTP_REGION_ID_SEC;
		break;
	case OTP_REGION_CALIPTRA:
		*id = OTP_REGION_ID_CAL;
		break;
	default:
		return -1;
	}

	return 0;
}

/* Whether this region's ECC is currently active (global force or its own policy). */
static int otp_region_ecc_active(int mode, bool *active)
{
	uint32_t region_id;
	int global_status;
	uint32_t ecc_en = 0, ecc_supported = 0;

	*active = false;

	if (otp_prog_region_ecc_id(mode, &region_id) ||
	    otp_ecc_get_status(&global_status) ||
	    otp_get_ecc_policy(region_id, &ecc_en, &ecc_supported))
		return -1;

	*active = ecc_supported && (global_status != OTP_ECC_GLOBAL_DISABLED || ecc_en);

	return 0;
}

/* Reads otp_w_offset's current value for whichever region otp_region selects. */
static int otp_prog_read_current(int mode, int otp_w_offset, uint16_t *value)
{
	switch (mode) {
	case OTP_REGION_ROM:
		return otp_read_rom(otp_w_offset, value);
	case OTP_REGION_RBP:
		return otp_read_rbp(otp_w_offset, value);
	case OTP_REGION_CONF:
		return otp_read_conf(otp_w_offset, value);
	case OTP_REGION_STRAP:
		return otp_read_strap(otp_w_offset, value);
	case OTP_REGION_STRAP_EXT:
		return otp_read_strap_ext(otp_w_offset, value);
	case OTP_REGION_STRAP_EXT_VLD:
		return otp_read_strap_ext_vld(otp_w_offset, value);
	case OTP_REGION_USER:
		return otp_read_udata(otp_w_offset, value);
	case OTP_REGION_SECURE:
		return otp_read_sdata(otp_w_offset, value);
	case OTP_REGION_CALIPTRA:
		return otp_read_cptra(otp_w_offset, value);
	default:
		return -1;
	}
}

/*
 * otp pb's safety net against incremental-program ECC corruption: if this
 * word already has data and this region's ECC is active, programming it
 * again would corrupt the parity locked in by whichever write set those
 * bits, with no indication beyond a later ECC read error. Refuse unless the
 * caller passed "force" to force it anyway. Also prints an upfront heads-up
 * whenever this region's ECC is active, even on a first write (no existing
 * data, or "force" given), since the word can never be safely reprogrammed
 * with a different value afterwards.
 */
static int otp_pb_check_repeat(int mode, int otp_w_offset, bool force)
{
	uint16_t current = 0;
	bool ecc_active = false;

	otp_region_ecc_active(mode, &ecc_active);
	if (ecc_active)
		printf(ANSI_COLOR_YELLOW
		       "Note: word 0x%x's region has ECC active - programmable once, no rewrites."
		       ANSI_COLOR_RESET "\n", otp_w_offset);

	if (force)
		return OTP_SUCCESS;

	if (otp_prog_read_current(mode, otp_w_offset, &current) || !current)
		return OTP_SUCCESS;

	if (!ecc_active)
		return OTP_SUCCESS;

	printf(ANSI_COLOR_RED
	       "Warning: word 0x%x=0x%x already set, ECC active - rewrite would corrupt it. Use \"force\" to override."
	       ANSI_COLOR_RESET "\n", otp_w_offset, current);

	return OTP_FAILURE;
}

/*
 * Both STRAP_EXT and STRAP_EXT_VLD support ECC, so programming the same
 * word more than once would corrupt its parity. For a caller who wants to
 * set several bits in the same word but doesn't already know its final
 * value, collect every bit first, then program each word exactly once -
 * see otp_pb_strap_ext_word() for the non-interactive counterpart.
 */
static int otp_pb_strap_ext_interactive(int mode, int nconfirm, bool force)
{
	const char *label = mode == OTP_REGION_STRAP_EXT_VLD ? "OTPSTRAPEXT_VLD" : "OTPSTRAPEXT";
	uint16_t word_value[8] = {0};
	bool word_dirty[8] = {false};
	bool any = false;
	char line[32];
	int ret;

	printf("Enter %s bit offsets (0x0~0x7f) to program, one at a time.\n", label);
	printf("Type \"end\" when done.\n");

	while (1) {
		unsigned long bit_offset;
		char *endp;
		size_t len;

		printf("bit offset: ");
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin)) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}

		len = strlen(line);
		if (len && line[len - 1] == '\n')
			line[len - 1] = '\0';

		if (!strcmp(line, "end"))
			break;

		bit_offset = strtoul(line, &endp, 16);
		if (endp == line || *endp != '\0' || bit_offset >= 128) {
			printf("Invalid bit offset, must be a hex number < 0x80\n");
			continue;
		}

		word_value[bit_offset / 16] |= BIT(bit_offset % 16);
		word_dirty[bit_offset / 16] = true;
		any = true;
		printf("Queued bit 0x%lx (word 0x%lx)\n", bit_offset, bit_offset / 16);
	}

	if (!any) {
		printf("Nothing to program.\n");
		return OTP_SUCCESS;
	}

	printf("\nThe following %s words will be programmed:\n", label);
	for (int w = 0; w < 8; w++) {
		if (word_dirty[w])
			printf("  word 0x%x = 0x%04x\n", w, word_value[w]);
	}

	for (int w = 0; w < 8; w++) {
		if (!word_dirty[w])
			continue;

		ret = otp_pb_check_repeat(mode, w, force);
		if (ret)
			return OTP_FAILURE;
	}

	if (!nconfirm) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	for (int w = 0; w < 8; w++) {
		if (!word_dirty[w])
			continue;

		ret = otp_prog_data(mode, w, 0, word_value[w], 1, false);
		if (ret)
			return OTP_FAILURE;
	}

	printf("\nProgram successful. Current %s values:\n", label);
	for (int w = 0; w < 8; w++) {
		uint16_t readback;

		if (!word_dirty[w])
			continue;

		if (otp_prog_read_current(mode, w, &readback))
			printf("  word 0x%x: failed to read back\n", w);
		else
			printf("  word 0x%x = 0x%04x\n", w, readback);
	}

	return OTP_SUCCESS;
}

/*
 * Non-interactive counterpart to otp_pb_strap_ext_interactive(): lets a
 * caller who already knows the word's full target value burn it in one
 * shot. Only a word-aligned bit_offset (a multiple of 16) is accepted so
 * the whole word is always programmed in a single otp_prog_data() call.
 */
static int otp_pb_strap_ext_word(int mode, const char *bit_offset_str, const char *value_str,
				 int nconfirm, bool force)
{
	char *endp;
	uint32_t bit_offset;
	uint32_t value;
	int ret;

	bit_offset = strtoul(bit_offset_str, &endp, 16);
	if (endp == bit_offset_str || *endp != '\0' || bit_offset >= 128 ||
	    bit_offset % 16 != 0) {
		printf("bit_offset must be a word-aligned (multiple of 16) hex number < 0x80\n");
		return OTP_USAGE;
	}

	ret = otp_pb_check_repeat(mode, bit_offset / 16, force);
	if (ret)
		return ret;

	value = strtoul(value_str, &endp, 16);
	if (endp == value_str || *endp != '\0') {
		otp_err("value must be a valid hex number");
		return OTP_USAGE;
	}

	return otp_prog_data(mode, bit_offset / 16, 0, value, nconfirm, true);
}

static int do_otppb(int argc, char *const argv[])
{
	struct otpstrap_status otpstrap[32];
	int mode = 0;
	int nconfirm = 0;
	/*
	 * uint32_t, not int: these come straight from strtoul() (unsigned
	 * long), and every bounds check below (e.g. "bit_offset >= 32") needs
	 * to run as an unsigned comparison so a huge hex input can't wrap
	 * into a negative value and slip past it.
	 */
	uint32_t otp_addr = 0;
	uint32_t bit_offset;
	uint32_t value;
	int ret;
	/* "force": force past otp_pb_check_repeat()'s incremental-program ECC warning */
	bool force = false;

	if (argc >= 2 && !strcmp(argv[1], "strap-ext")) {
		int next = 2;

		while (argc > next && (!strcmp(argv[next], "o") || !strcmp(argv[next], "force"))) {
			if (!strcmp(argv[next], "o"))
				nconfirm = 1;
			else
				force = true;
			next++;
		}

		if (argc == next) {
			ret = otp_pb_strap_ext_interactive(OTP_REGION_STRAP_EXT, nconfirm, force);
		} else if (argc == next + 2) {
			ret = otp_pb_strap_ext_word(OTP_REGION_STRAP_EXT, argv[next],
						argv[next + 1], nconfirm, force);
		} else {
			otp_err("otp pb strap-ext: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		goto end;
	}

	if (argc >= 2 && !strcmp(argv[1], "strap-ext-vld") &&
	    !(argc >= 3 && !strcmp(argv[2], "all"))) {
		int next = 2;

		while (argc > next && (!strcmp(argv[next], "o") || !strcmp(argv[next], "force"))) {
			if (!strcmp(argv[next], "o"))
				nconfirm = 1;
			else
				force = true;
			next++;
		}

		if (argc == next) {
			ret = otp_pb_strap_ext_interactive(OTP_REGION_STRAP_EXT_VLD, nconfirm,
							    force);
		} else if (argc == next + 2) {
			ret = otp_pb_strap_ext_word(OTP_REGION_STRAP_EXT_VLD, argv[next],
						argv[next + 1], nconfirm, force);
		} else {
			otp_err("otp pb strap-ext-vld: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		goto end;
	}

	if (argc != 3 && argc != 4 && argc != 5 && argc != 6 && argc != 7) {
		printf("%s: argc:%d\n", __func__, argc);
		return CMD_RET_USAGE;
	}

	/* Drop the pb cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "conf")) {
		mode = OTP_REGION_CONF;
	} else if (!strcmp(argv[0], "rbp")) {
		mode = OTP_REGION_RBP;
	} else if (!strcmp(argv[0], "strap")) {
		mode = OTP_REGION_STRAP;
	} else if (!strcmp(argv[0], "strap-ext-vld")) {
		mode = OTP_REGION_STRAP_EXT_VLD;
	} else if (!strcmp(argv[0], "u-data")) {
		mode = OTP_REGION_USER;
	} else if (!strcmp(argv[0], "s-data")) {
		mode = OTP_REGION_SECURE;
	} else if (!strcmp(argv[0], "cptra")) {
		mode = OTP_REGION_CALIPTRA;
	} else {
		otp_err("otp pb: unknown region '%s'", argv[0]);
		return CMD_RET_USAGE;
	}

	/* Drop the region cmd */
	argc--;
	argv++;

	while (argc > 0 && (!strcmp(argv[0], "o") || !strcmp(argv[0], "force"))) {
		if (!strcmp(argv[0], "o"))
			nconfirm = 1;
		else
			force = true;
		argc--;
		argv++;
	}

	if (mode == OTP_REGION_STRAP) {
		if (argc != 2) {
			otp_err("otp pb strap: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		bit_offset = (int)strtoul(argv[0], NULL, 16);
		value = (int)strtoul(argv[1], NULL, 16);
		if (bit_offset >= 32) {
			otp_err("bit_offset 0x%x must be < 0x20", bit_offset);
			return CMD_RET_USAGE;
		}
		if (value != 0 && value != 1) {
			otp_err("value must be 0 or 1");
			return CMD_RET_USAGE;
		}

	} else if (mode == OTP_REGION_STRAP_EXT_VLD) {
		/* do_otppb()'s top-level interception only lets "all" [o] [force] reach here */
		int next = 1;

		while (argc > next && (!strcmp(argv[next], "o") || !strcmp(argv[next], "force"))) {
			if (!strcmp(argv[next], "o"))
				nconfirm = 1;
			else
				force = true;
			next++;
		}

		if (argc != next) {
			otp_err("otp pb strap-ext-vld all: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		for (int i = 0; i < 8; i++) {
			ret = otp_pb_check_repeat(mode, i, force);
			if (ret)
				goto end;
		}

		if (!nconfirm) {
			printf("This will mark every OTPSTRAPEXT_VLD bit as valid.\n");
			printf("type \"YES\" (no quotes) to continue:\n");
			if (!confirm_yesno()) {
				printf(" Aborting\n");
				ret = OTP_FAILURE;
				goto end;
			}
		}

		for (int i = 0; i < 8; i++) {
			ret = otp_prog_data(mode, i, 0, GENMASK(15, 0), 1, true);
			if (ret)
				goto end;
		}

		goto end;

	} else {
		if (argc != 3) {
			otp_err("otp pb: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		otp_addr = (int)strtoul(argv[0], NULL, 16);
		bit_offset = (int)strtoul(argv[1], NULL, 16);
		value = (int)strtoul(argv[2], NULL, 16);
		if (bit_offset >= 16) {
			otp_err("bit_offset 0x%x must be < 0x10", bit_offset);
			return CMD_RET_USAGE;
		}
		/*
		 * value << bit_offset must still fit in the 16-bit word:
		 * otp_prog_data() silently truncates anything past bit 15,
		 * which would otherwise burn the wrong pattern with no
		 * warning - and OTP can't be unburned.
		 */
		if (value > (0xffffU >> bit_offset)) {
			otp_err("value 0x%x too large for bit_offset 0x%x", value, bit_offset);
			return CMD_RET_USAGE;
		}
	}

	/* Check param */
	if (mode == OTP_REGION_RBP) {
		if (otp_addr >= OTP_RBP_REGION_SIZE) {
			otp_err("otp_addr 0x%x must be < 0x%x", otp_addr, OTP_RBP_REGION_SIZE);
			return CMD_RET_USAGE;
		}

	} else if (mode == OTP_REGION_CONF) {
		if (otp_addr >= OTP_CONF_REGION_SIZE) {
			otp_err("otp_addr 0x%x must be < 0x%x", otp_addr, OTP_CONF_REGION_SIZE);
			return CMD_RET_USAGE;
		}

	} else if (mode == OTP_REGION_STRAP) {
		// get otpstrap status
		otp_strap_status(otpstrap);

		ret = otp_strap_bit_confirm(&otpstrap[bit_offset], bit_offset, value, 0);
		if (ret != OTP_SUCCESS)
			return ret;

		// assign writable otp address
		if (bit_offset < 16) {
			otp_addr = 2 + otpstrap[bit_offset].writeable_option * 2;
		} else {
			otp_addr = 3 + otpstrap[bit_offset].writeable_option * 2;
			bit_offset -= 16;
		}

		value = 1;

	} else if (mode == OTP_REGION_USER) {
		if (otp_addr >= OTP_USER_REGION_SIZE) {
			otp_err("otp_addr 0x%x must be < 0x%x", otp_addr, OTP_USER_REGION_SIZE);
			return CMD_RET_USAGE;
		}

	} else if (mode == OTP_REGION_SECURE) {
		if (otp_addr >= OTP_SEC_REGION_SIZE) {
			otp_err("otp_addr 0x%x must be < 0x%x", otp_addr, OTP_SEC_REGION_SIZE);
			return CMD_RET_USAGE;
		}

	} else if (mode == OTP_REGION_CALIPTRA) {
		if (otp_addr >= OTP_CAL_REGION_SIZE) {
			otp_err("otp_addr 0x%x must be < 0x%x", otp_addr, OTP_CAL_REGION_SIZE);
			return CMD_RET_USAGE;
		}
	}

	ret = otp_pb_check_repeat(mode, otp_addr, force);
	if (ret)
		goto end;

	ret = otp_prog_data(mode, otp_addr, bit_offset, value, nconfirm, true);

end:
	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	else if (ret == OTP_FAILURE)
		return CMD_RET_FAILURE;
	else
		return CMD_RET_USAGE;
}

static const struct {
	const char *name;
	uint32_t id;
} otp_ecc_policy_region_tbl[] = {
	{ "rom",       OTP_REGION_ID_ROM      },
	{ "rbp",       OTP_REGION_ID_RBP      },
	{ "conf",      OTP_REGION_ID_CFG      },
	{ "strap",     OTP_REGION_ID_STRAP    },
	{ "strap-ext", OTP_REGION_ID_STRAPEXT },
	{ "u-data",    OTP_REGION_ID_USR      },
	{ "s-data",    OTP_REGION_ID_SEC      },
	{ "cptra",     OTP_REGION_ID_CAL      },
	{ "puf",       OTP_REGION_ID_PUF      },
};

static int otp_ecc_policy_region_id(const char *name, uint32_t *id)
{
	for (int i = 0; i < ARRAY_SIZE(otp_ecc_policy_region_tbl); i++) {
		if (!strcmp(name, otp_ecc_policy_region_tbl[i].name)) {
			*id = otp_ecc_policy_region_tbl[i].id;
			return 0;
		}
	}

	return -1;
}

/* OTPSTRAP word that aspeed_otp_ecc_init() reads to latch otp_hw_glb_ecc_effect */
#define OTPSTRAP_ECC_EN_W_OFFSET	0xe
#define OTPSTRAP_ECC_EN_BIT		0x1
/* bit0 is the real ECC-enable bit; bit1 is an unused dummy bit burned alongside it */
#define OTPSTRAP_ECC_EN_BURN_VALUE	0x3

/*
 * Permanently burns the OTPSTRAP ECC-enable fuse, unlike otp_ecc_ctrl() which
 * only flips a RAM flag for the current session. Once burned, every future
 * boot reads otp_hw_glb_ecc_effect == 1 and global ECC can never be turned
 * off again. Reads the real hardware strap directly rather than any cached
 * gbl_ecc_en-type state, since this must reflect what's actually fused
 * regardless of what has or hasn't been probed this session.
 */
static int otp_ecc_hw_enable(int nconfirm)
{
	uint16_t val;
	int ret;

	ret = otp_read_strap(OTPSTRAP_ECC_EN_W_OFFSET, &val);
	if (ret) {
		printf("Failed to read OTP strap ECC enable bit\n");
		return CMD_RET_FAILURE;
	}

	if (val & OTPSTRAP_ECC_EN_BIT) {
		printf("OTP strap ECC enable bit is already programmed\n");
		return CMD_RET_SUCCESS;
	}

	printf("WARNING: this permanently burns the OTP strap ECC-enable fuse.\n");
	printf("Global ECC will be forced on by hardware on every future boot and can never be turned off again.\n");

	if (!nconfirm) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf("Aborting\n");
			return CMD_RET_FAILURE;
		}
	}

	ret = otp_prog(STRAP_REGION_START_ADDR + OTPSTRAP_ECC_EN_W_OFFSET,
			OTPSTRAP_ECC_EN_BURN_VALUE);
	if (ret) {
		printf("OTP cannot be programmed\n");
		return CMD_RET_FAILURE;
	}

	ret = otp_read_strap(OTPSTRAP_ECC_EN_W_OFFSET, &val);
	if (ret || (val & OTPSTRAP_ECC_EN_BURN_VALUE) != OTPSTRAP_ECC_EN_BURN_VALUE) {
		printf("OTP strap ECC enable bit readback mismatch, got 0x%x\n", val);
		return CMD_RET_FAILURE;
	}

	printf("SUCCESS: OTP strap ECC enable bit burned\n");
	printf("note: hardware-forced global ECC only takes effect after the next power cycle; this session is unaffected\n");

	return CMD_RET_SUCCESS;
}

/*
 * global_status (enum otp_ecc_global_status) reflects the ASPEED_OTP_GET_ECC
 * force switch: whenever it's not OTP_ECC_GLOBAL_DISABLED, the driver forces
 * ECC on for every region with ecc_supported, overriding that region's own
 * ecc_en, while ecc_supported=false regions (rbp/strap) always stay off
 * regardless of the global switch.
 */
static int otp_ecc_policy_dump_all(int global_status)
{
	uint32_t ecc_en, ecc_supported;
	int ret;
	int fail = 0;
	bool global_forced = global_status != OTP_ECC_GLOBAL_DISABLED;

	if (global_status == OTP_ECC_GLOBAL_HW_ENABLED)
		printf("note: global ECC switch is enabled (hardware strap), forcing ECC on for every capable region below\n");
	else if (global_status == OTP_ECC_GLOBAL_SW_ENABLED)
		printf("note: global ECC switch is enabled (temporarily, by software), forcing ECC on for every capable region below\n");

	printf("%-14s  %-14s  %s\n", "region", "ecc_supported", "ecc_enabled");
	printf("----------------------------------------\n");

	for (int i = 0; i < ARRAY_SIZE(otp_ecc_policy_region_tbl); i++) {
		int effective_en;

		ret = otp_get_ecc_policy(otp_ecc_policy_region_tbl[i].id, &ecc_en, &ecc_supported);
		if (ret) {
			printf("%-14s  failed to get ECC policy, ret = %d, errno = %d (%s)\n",
			       otp_ecc_policy_region_tbl[i].name, ret, errno,
			       otp_cmd_errno_str(errno));
			fail = 1;
			continue;
		}

		/* global switch forces ECC on for capable regions, no effect otherwise */
		effective_en = ecc_supported && (global_forced || ecc_en);

		printf("%-14s  %-14s  %s%s\n",
		       otp_ecc_policy_region_tbl[i].name,
		       ecc_supported ? "yes" : "no",
		       effective_en ? "on" : "off",
		       (global_forced && ecc_supported) ? " (forced)" : "");
	}

	return fail ? CMD_RET_FAILURE : CMD_RET_SUCCESS;
}

static int do_otpecc_policy(int argc, char *const argv[], int global_status)
{
	uint32_t region_id;
	uint32_t ecc_en;
	int ret;

	if (argc < 1) {
		otp_err("otp ecc policy: missing subcommand");
		return CMD_RET_USAGE;
	}

	if (!strcmp(argv[0], "dump")) {
		if (argc != 1) {
			otp_err("otp ecc policy dump: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		return otp_ecc_policy_dump_all(global_status);

	} else if (!strcmp(argv[0], "set")) {
		if (argc != 3) {
			otp_err("otp ecc policy set: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		if (global_status == OTP_ECC_GLOBAL_HW_ENABLED) {
			printf("OTP ECC policy cannot be set: hardware strap forces global ECC on\n");
			return CMD_RET_FAILURE;
		}

		if (otp_ecc_policy_region_id(argv[1], &region_id)) {
			printf("Unknown OTP region '%s'\n", argv[1]);
			return CMD_RET_USAGE;
		}

		if (region_id == OTP_REGION_ID_RBP || region_id == OTP_REGION_ID_STRAP) {
			printf("region '%s' does not support ECC, nothing to set\n", argv[1]);
			return CMD_RET_USAGE;
		}

		if (!strcmp(argv[2], "enable")) {
			ecc_en = OTP_ECC_ENABLE;
		} else if (!strcmp(argv[2], "disable")) {
			ecc_en = OTP_ECC_DISABLE;
		} else {
			printf("ECC enable value must be 'enable' or 'disable'\n");
			return CMD_RET_USAGE;
		}

		ret = otp_set_ecc_policy(region_id, ecc_en);
		if (ret) {
			if (errno == EINVAL)
				printf("Failed to set ECC policy for region '%s': region does not support ECC\n",
				       argv[1]);
			else
				printf("Failed to set ECC policy for region '%s', ret = %d, errno = %d (%s)\n",
				       argv[1], ret, errno, otp_cmd_errno_str(errno));
			return CMD_RET_FAILURE;
		}

		printf("region %s ECC policy set to %s\n", argv[1], ecc_en ? "enabled" : "disabled");

		return otp_ecc_policy_dump_all(global_status);
	}

	otp_err("otp ecc policy: unknown subcommand '%s'", argv[0]);
	return CMD_RET_USAGE;
}

static int do_otpecc(int argc, char *const argv[])
{
	int ret;
	int global_status = OTP_ECC_GLOBAL_DISABLED;

	if (argc < 2) {
		otp_err("otp ecc: missing subcommand");
		return CMD_RET_USAGE;
	}

	/* Get ECC status */
	ret = otp_ecc_get_status(&global_status);
	if (ret)
		return CMD_RET_FAILURE;

	/* Drop the ecc cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "status")) {
		switch (global_status) {
		case OTP_ECC_GLOBAL_HW_ENABLED:
			printf("OTP ECC is " ANSI_COLOR_CYAN
			       "ENABLED (hardware strap, cannot be disabled until next power-on)"
			       ANSI_COLOR_RESET "\n");
			printf("note: this forces ECC on for every region that supports it, overriding "
			       "that region's own 'ecc policy' setting. Regions that don't support ECC "
			       "(rbp/strap) are unaffected and stay disabled regardless.\n");
			break;
		case OTP_ECC_GLOBAL_SW_ENABLED:
			printf("OTP ECC is " ANSI_COLOR_YELLOW
			       "ENABLED (temporarily, by software)"
			       ANSI_COLOR_RESET "\n");
			printf("note: this forces ECC on for every region that supports it, overriding "
			       "that region's own 'ecc policy' setting. Regions that don't support ECC "
			       "(rbp/strap) are unaffected and stay disabled regardless.\n");
			break;
		default:
			printf("OTP ECC is " ANSI_COLOR_GREEN "DISABLED" ANSI_COLOR_RESET "\n");
			printf("note: each region's ECC now follows its own 'ecc policy' setting instead\n");
			break;
		}
		if (info_cb.otp_fd >= 0)
			printf("note: native backend - this reflects the kernel driver's in-RAM state, reset on the next Linux reboot\n");

		/*
		 * The fuse itself is non-volatile, so reading it back directly
		 * (rather than relying on any in-process state) correctly
		 * detects "burned but not yet in effect" regardless of which
		 * process or session burned it.
		 */
		if (global_status != OTP_ECC_GLOBAL_HW_ENABLED) {
			uint16_t val;

			if (!otp_read_strap(OTPSTRAP_ECC_EN_W_OFFSET, &val) &&
			    (val & OTPSTRAP_ECC_EN_BIT))
				printf(ANSI_COLOR_YELLOW
				       "note: the OTP strap ECC-enable fuse has been burned - it will take effect after the next power cycle"
				       ANSI_COLOR_RESET "\n");
		}

		return CMD_RET_SUCCESS;

	} else if (!strcmp(argv[0], "tmp-enable")) {
		switch (global_status) {
		case OTP_ECC_GLOBAL_HW_ENABLED:
			printf("OTP ECC is already enabled (hardware strap)\n");
			break;
		case OTP_ECC_GLOBAL_SW_ENABLED:
			printf("OTP ECC is already enabled (temporarily, by software)\n");
			break;
		default:
			ret = otp_ecc_ctrl(true);
			if (ret)
				return CMD_RET_FAILURE;

			global_status = OTP_ECC_GLOBAL_SW_ENABLED;
			printf("OTP ECC is enabled\n");
			break;
		}

		return otp_ecc_policy_dump_all(global_status);

	} else if (!strcmp(argv[0], "tmp-disable")) {
		switch (global_status) {
		case OTP_ECC_GLOBAL_HW_ENABLED:
			printf("OTP ECC cannot be disabled: hardware strap forces it on until next power-on\n");
			return CMD_RET_FAILURE;
		case OTP_ECC_GLOBAL_DISABLED:
			printf("OTP ECC is already disabled\n");
			break;
		default:
			ret = otp_ecc_ctrl(false);
			if (ret)
				return CMD_RET_FAILURE;

			global_status = OTP_ECC_GLOBAL_DISABLED;
			printf("OTP ECC is disabled\n");
			break;
		}

		return otp_ecc_policy_dump_all(global_status);

	} else if (!strcmp(argv[0], "enable")) {
		int nconfirm = (argc == 2 && !strcmp(argv[1], "o"));

		if (argc != 1 && !nconfirm) {
			otp_err("otp ecc enable: bad argc %d", argc);
			return CMD_RET_USAGE;
		}

		return otp_ecc_hw_enable(nconfirm);

	} else if (!strcmp(argv[0], "policy")) {
		/* Drop the policy cmd */
		argc--;
		argv++;

		return do_otpecc_policy(argc, argv, global_status);

	} else {
		otp_err("otp ecc: unknown subcommand '%s'", argv[0]);
		return CMD_RET_USAGE;
	}

	return CMD_RET_SUCCESS;
}

static int do_otpver(int argc, char *const argv[])
{
	printf("OTP tool version: %s\n", OTP_VER);
	printf("OTP info version: %s\n", OTP_INFO_VER);

	return CMD_RET_SUCCESS;
}

struct cmd_tbl {
	char *name;
	int maxargs;
	int (*cmd)(int argc, char *const argv[]);
};

static struct cmd_tbl cmd_otp[] = {
	{ "version", 2, do_otpver    },
	{ "read",    5, do_otpread   },
	{ "prog",    5, do_otpprog   },
	{ "pb",      8, do_otppb     },
	{ "patch",   6, do_otppatch  },
	{ "ecc",     6, do_otpecc    },
	{ "info",    3, do_otpinfo   },
	{ "dump",    4, do_otpdump   },
	{ "screen",     3, do_otpscreen     },
	{ "reprog_ecc", 8, do_otpreprog_ecc },
};

static void usage(void)
{
	printf("ASPEED One-Time-Programmable sub-system\n"
	       "\totp <dev> version\n"
	       "\totp <dev> read rom|rbp|conf|strap|strap-pro|strap-ext|strap-ext-vld|u-data|s-data|cptra|puf [<otp_w_offset> <w_count>]\n"
	       "\totp <dev> read <region>: omitting <otp_w_offset>/<w_count> dumps that whole region\n"
	       "\totp <dev> read all (dumps every OTP word except HW PUF)\n"
	       "\totp <dev> pb rbp|conf|u-data|s-data|cptra [o] [force] <otp_w_offset> <bit_offset> <value>\n"
	       "\totp <dev> pb strap [o] <bit_offset> <value>\n"
	       "\totp <dev> pb strap-ext-vld all [o] [force]\n"
	       "\totp <dev> pb strap-ext|strap-ext-vld [o] [force] (interactive: enter bit offsets one at a time, \"end\" to finish)\n"
	       "\totp <dev> pb strap-ext|strap-ext-vld [o] [force] <word-aligned bit_offset> <full word value>\n"
	       "\totp <dev> pb: \"o\" skips \"type YES\"; \"force\" overrides the refusal to rewrite an\n"
	       "\t    ECC-active word that already has data (rewriting it would corrupt its parity)\n"
	       "\totp <dev> prog [o] [force] <path>\n"
	       "\totp <dev> prog: \"o\" skips \"type YES\"; \"force\" overrides the refusal to rewrite an\n"
	       "\t    ECC-active region whose existing data conflicts with the image\n"
	       "\totp <dev> info key|rbp|conf|strap|strap-ext|rompatch|mt-stage|hsm|prot\n"
	       "\totp <dev> patch prog <dram_addr> <otp_w_offset> <w_count>\n"
	       "\totp <dev> patch enable pre|post <otp_start_w_offset> <w_count>\n"
	       "\totp <dev> ecc status|tmp-enable|tmp-disable\n"
	       "\totp <dev> ecc enable [o] (permanently burns the OTP strap ECC-enable fuse)\n"
	       "\totp <dev> ecc policy dump\n"
	       "\totp <dev> ecc policy set rom|conf|strap-ext|u-data|s-data|cptra|puf enable|disable\n"
	       "\totp <dev> dump <file> [--skip_locked_regions]\n"
	       "\totp <dev> screen\n"
	       "\totp <dev> screen <golden.bin>\n"
	       "\totp <dev> reprog_ecc [rom|conf|strap-ext|u-data|s-data|cptra] [--ref <verified_dump>] [--dry_run] [o]\n"
	       "\totp <dev> reprog_ecc: re-programs ECC-capable regions' data with parity and\n"
	       "\t    verifies each one's hash is unchanged; auto-skips any region that already\n"
	       "\t    has ECC; does not touch the global-ECC fuse - follow with 'otp <dev> ecc enable'\n");
}

struct cmd_tbl *find_cmd_tbl(const char *cmd, struct cmd_tbl *table,
			     int table_len)
{
	struct cmd_tbl *cmdtp;
	int len = strlen(cmd);

	for (cmdtp = table; cmdtp != table + table_len; cmdtp++) {
		if (strncmp(cmd, cmdtp->name, len) == 0) {
			if (len == strlen(cmdtp->name))
				return cmdtp;	/* full match */
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	union otp_pro_sts *pro_sts;
	struct cmd_tbl *cp;
	uint32_t ver;
	int ret;
	uint16_t otp_conf0;

	if (argc < 3 || argc > 10) {
		ret = OTP_USAGE;
		goto end;
	}

	/*
	 * /dev/aspeed-otp may legitimately be absent: once bootmcu locks OTP
	 * master access to itself, the kernel's own OTP driver probe fails
	 * too, so there's nothing to open here. Don't bail out yet - try the
	 * IPC path below before giving up.
	 */
	info_cb.otp_fd = open("/dev/aspeed-otp", O_RDWR);

	/*
	 * Direct CA35 register access via /dev/aspeed-otp takes priority when
	 * available; OTP read/program/ECC ops only go over the bootmcu IPC
	 * mailbox as a fallback for when bootmcu has locked CA35 out of OTP.
	 */
	otp_ipc_probe();

	if (info_cb.otp_fd == -1 && !otp_ipc_available()) {
		printf("Can't open /dev/aspeed-otp and no BOOTMCU OTP IPC channel found, "
		       "please install driver or check bootmcu firmware!!\n");
		exit(EXIT_FAILURE);
	}

	printf("OTP driver: %s\n", info_cb.otp_fd >= 0 ? "native (CA35 direct)" : "IPC (via BOOTMCU)");

	if (strcmp(argv[1], "0") && strcmp(argv[1], "1")) {
		otp_err("Invalid otp device %s, only support 0 and 1", argv[1]);
		ret = OTP_USAGE;
		goto end;
	}

	/* Drop the otp command */
	argc--;
	argv++;

	cp = find_cmd_tbl(argv[1], cmd_otp, ARRAY_SIZE(cmd_otp));
	if (!cp) {
		otp_err("otp: unknown subcommand '%s'", argv[1]);
		ret = OTP_USAGE;
		goto end;
	}
	if (argc > cp->maxargs) {
		otp_err("otp %s: too many arguments (%d)", argv[1], argc);
		ret = OTP_USAGE;
		goto end;
	}

	/* Drop the otp command */
	argc--;
	argv++;

	ver = chip_version();
	switch (ver) {
	case OTP_AST2700_A1:
		printf("Chip: AST2700-A1\n");
		info_cb.version = OTP_AST2700_A1;
		info_cb.rbp_info = a1_rbp_info;
		info_cb.rbp_info_len = ARRAY_SIZE(a1_rbp_info);
		info_cb.conf_info = a1_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a1_conf_info);
		info_cb.strap_info = a1_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a1_strap_info);
		info_cb.strap_ext_info = a1_strap_ext_info;
		info_cb.strap_ext_info_len = ARRAY_SIZE(a1_strap_ext_info);
		info_cb.cal_info = a1_cal_info;
		info_cb.cal_info_len = ARRAY_SIZE(a1_cal_info);
		info_cb.key_info = a1_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a1_key_type);
		break;
	case OTP_AST2700_A2:
		printf("Chip: AST2700-A2\n");
		info_cb.version = OTP_AST2700_A2;
		info_cb.rbp_info = a2_rbp_info;
		info_cb.rbp_info_len = ARRAY_SIZE(a2_rbp_info);
		info_cb.conf_info = a2_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a2_conf_info);
		info_cb.strap_info = a2_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a2_strap_info);
		info_cb.strap_ext_info = a2_strap_ext_info;
		info_cb.strap_ext_info_len = ARRAY_SIZE(a2_strap_ext_info);
		info_cb.cal_info = a2_cal_info;
		info_cb.cal_info_len = ARRAY_SIZE(a2_cal_info);
		info_cb.key_info = a2_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a2_key_type);
		break;
	default:
		printf("SOC is not supported\n");
		return CMD_RET_FAILURE;
	}

	otp_read_conf(0, &otp_conf0);
	pro_sts = &info_cb.pro_sts;
	pro_sts->value = otp_conf0;

	ret = cp->cmd(argc, argv);

end:
	if (ret == OTP_USAGE) {
		usage();
		return EXIT_FAILURE;

	} else if (ret == OTP_FAILURE) {
		return EXIT_FAILURE;

	} else {
		return EXIT_SUCCESS;
	}
}
