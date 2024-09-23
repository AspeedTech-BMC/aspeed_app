// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Aspeed Technology Inc.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
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
#include <openssl/evp.h>
#include "utils.h"
#include "aspeed-otp.h"
#include "otp_info_ast2700.h"

enum otp_region {
	OTP_REGION_ROM,
	OTP_REGION_RBP,
	OTP_REGION_CONF,
	OTP_REGION_STRAP,
	OTP_REGION_STRAP_EXT,
	OTP_REGION_STRAP_EXT_VLD,
	OTP_REGION_USER_DATA,
	OTP_REGION_SECURE,
	OTP_REGION_CALIPTRA,
	OTP_REGION_PUF,
};

enum otp_status {
	OTP_FAILURE = -2,
	OTP_USAGE = -1,
	OTP_SUCCESS = 0,
	OTP_PROG_SKIP,
};

#define OTP_VER				"1.1.0"

#define OTP_AST2700_A0			0
#define OTP_AST2700_A1			1

#define ID0_AST2700A0			0x06000003
#define ID1_AST2700A0			0x06000003
#define ID0_AST2700A1			0x06010003
#define ID1_AST2700A1			0x06010003

#define SOC_AST2700A0			8
#define SOC_AST2700A1			9

/* OTP memory address from 0x0~0x2000. (unit: Single Word 16-bits) */
/* ----  0x0  -----
 *       ROM
 * ---- 0x3e0 -----
 *       RBP
 * ---- 0x400 -----
 *      CONF
 * ---- 0x420 -----
 *      STRAP
 * ---- 0x430 -----
 *    STRAP EXT
 * ---- 0x440 -----
 *   User Region
 * ---- 0x1000 ----
 *  Secure Region
 * ---- 0x1c00 ----
 *     Caliptra
 * ---- 0x1f80 ----
 *      SW PUF
 * ---- 0x1fc0 ----
 *      HW PUF
 * ---- 0x2000 ----
 */
#define ROM_REGION_START_ADDR		0x0
#define ROM_REGION_END_ADDR		0x3e0
#define RBP_REGION_START_ADDR		ROM_REGION_END_ADDR
#define RBP_REGION_END_ADDR		0x400
#define CONF_REGION_START_ADDR		RBP_REGION_END_ADDR
#define CONF_REGION_END_ADDR		0x420
#define STRAP_REGION_START_ADDR		CONF_REGION_END_ADDR
#define STRAP_REGION_END_ADDR		0x430
#define STRAPEXT_REGION_START_ADDR	STRAP_REGION_END_ADDR
#define STRAPEXT_REGION_END_ADDR	0x440
#define USER_REGION_START_ADDR		STRAPEXT_REGION_END_ADDR
#define USER_REGION_END_ADDR		0x1000
#define SEC_REGION_START_ADDR		USER_REGION_END_ADDR
#define SEC_REGION_END_ADDR		0x1c00
#define CAL_REGION_START_ADDR		SEC_REGION_END_ADDR
#define CAL_REGION_END_ADDR		0x1f80
#define SW_PUF_REGION_START_ADDR	CAL_REGION_END_ADDR
#define SW_PUF_REGION_END_ADDR		0x1fc0
#define HW_PUF_REGION_START_ADDR	SW_PUF_REGION_END_ADDR
#define HW_PUF_REGION_END_ADDR		0x2000

#define OTP_MEM_ADDR_MAX		HW_PUF_REGION_START_ADDR
#define OTP_ROM_REGION_SIZE		(ROM_REGION_END_ADDR - ROM_REGION_START_ADDR)
#define OTP_RBP_REGION_SIZE		(RBP_REGION_END_ADDR - RBP_REGION_START_ADDR)
#define OTP_CONF_REGION_SIZE		(CONF_REGION_END_ADDR - CONF_REGION_START_ADDR)
#define OTP_STRAP_REGION_SIZE		(STRAP_REGION_END_ADDR - STRAP_REGION_START_ADDR - 4)
#define OTP_STRAP_EXT_REGION_SIZE	(STRAPEXT_REGION_END_ADDR - STRAPEXT_REGION_START_ADDR)
#define OTP_USER_REGION_SIZE		(USER_REGION_END_ADDR - USER_REGION_START_ADDR)
#define OTP_SEC_REGION_SIZE		(SEC_REGION_END_ADDR - SEC_REGION_START_ADDR)
#define OTP_CAL_REGION_SIZE		(CAL_REGION_END_ADDR - CAL_REGION_START_ADDR)
#define OTP_PUF_REGION_SIZE		(HW_PUF_REGION_END_ADDR - SW_PUF_REGION_START_ADDR)

/* OTPRBP */
#define OTPRBP0_ADDR			OTPRBP_START_ADDR
#define OTPRBP1_ADDR			0x1
#define OTPRBP2_ADDR			0x2
#define OTPRBP3_ADDR			0x3
#define OTPRBP4_ADDR			0x4
#define OTPRBP8_ADDR			0x8
#define OTPRBP10_ADDR			0xa
#define OTPRBP18_ADDR			0x12

#define SOC_ECC_KEY_RETIRE		OTPRBP0_ADDR
#define SOC_LMS_KEY_RETIRE		OTPRBP1_ADDR
#define CAL_OWN_KEY_RETURE		OTPRBP3_ADDR
#define SOC_HW_SVN_ADDR			OTPRBP4_ADDR
#define CAL_FMC_HW_SVN_ADDR		OTPRBP8_ADDR
#define CAL_RT_HW_SVN_ADDR		OTPRBP10_ADDR
#define CAL_MANU_ECC_KEY_MASK		OTPRBP18_ADDR

#define OTP_DEVICE_NAME_0		"otp@14c07000"
#define OTP_DEVICE_NAME_1		"otp@30c07000"

#define OTP_MAGIC			"SOCOTP"
#define CHECKSUM_LEN			48
#define OTP_INC_ROM			BIT(31)
#define OTP_INC_RBP			BIT(30)
#define OTP_INC_CONFIG			BIT(29)
#define OTP_INC_STRAP			BIT(28)
#define OTP_INC_STRAP_EXT		BIT(27)
#define OTP_INC_SECURE			BIT(26)
#define OTP_INC_CALIPTRA		BIT(25)
#define OTP_REGION_SIZE(info)		(((info) >> 16) & 0xffff)
#define OTP_REGION_OFFSET(info)		((info) & 0xffff)
#define OTP_IMAGE_SIZE(info)		((info) & 0xffff)

/* OTP key header format */
#define OTP_KH_NUM			80
#define OTP_KH_KEY_ID(kh)		((kh) & 0xf)
#define OTP_KH_KEY_TYPE(kh)		(((kh) >> 4) & 0x7)
#define OTP_KH_LAST(kh)			(((kh) >> 15) & 0x1)
#define OTP_KH_OFFSET(kh)		(((kh) >> 16) & 0xfff)

enum command_ret_t {
	CMD_RET_SUCCESS,	/* 0 = Success */
	CMD_RET_FAILURE,	/* 1 = Failure */
	CMD_RET_USAGE = -1,	/* Failure, please report 'usage' error */
};

enum otp_ioctl_cmds {
	GET_ECC_STATUS = 1,
	SET_ECC_ENABLE,
};

enum otp_ecc_codes {
	OTP_ECC_MISMATCH = -1,
	OTP_ECC_DISABLE = 0,
	OTP_ECC_ENABLE = 1,
};

struct otp_header {
	uint8_t		otp_magic[8];
	uint32_t	soc_ver;
	uint32_t	otptool_ver;
	uint32_t	image_info;
	uint32_t	rom_info;
	uint32_t	rbp_info;
	uint32_t	config_info;
	uint32_t	strap_info;
	uint32_t	strap_ext_info;
	uint32_t	secure_info;
	uint32_t	cptra_info;
	uint32_t	checksum_offset;
} __packed;

struct otpstrap_status {
	int value;
	int option_value[6];
	int remain_times;
	int writeable_option;
	int protected;
};

union otp_pro_sts {
	uint32_t value;
	struct {
		char r_prot_strap_ext : 1;
		char r_prot_rom : 1;
		char r_prot_conf : 1;
		char r_prot_strap : 1;
		char w_prot_strap_ext : 1;
		char w_prot_rom : 1;
		char w_prot_conf : 1;
		char w_prot_strap : 1;
		char retire_option : 1;
		char en_sec_boot : 1;
		char w_prot_rbp : 1;
		char r_prot_cal : 1;
		char w_prot_cal : 1;
		char dis_otp_bist : 1;
		char w_prot_puf : 1;
		char mem_lock : 1;
	} fields;
};

struct otp_info_cb {
	int otp_fd;
	int version;
	char ver_name[3];
	const struct otprbp_info *rbp_info;
	int rbp_info_len;
	const struct otpconf_info *conf_info;
	int conf_info_len;
	const struct otpstrap_info *strap_info;
	int strap_info_len;
	const struct otpstrap_ext_info *strap_ext_info;
	int strap_ext_info_len;
	const struct otpcal_info *cal_info;
	int cal_info_len;
	const struct otpkey_type *key_info;
	int key_info_len;
	union otp_pro_sts pro_sts;
};

static struct otp_info_cb info_cb;

struct otp_image_layout {
	int rom_length;
	int rbp_length;
	int conf_length;
	int strap_length;
	int strap_ext_length;
	int secure_length;
	int cptra_length;
	uint8_t *rom;
	uint8_t *rbp;
	uint8_t *conf;
	uint8_t *strap;
	uint8_t *strap_ext;
	uint8_t *secure;
	uint8_t *cptra;
};

struct udevice *otp_dev;

static uint32_t chip_version(void)
{
	struct otp_revid revid;
	uint32_t revid0, revid1;
	int ret;

	ret = ioctl(info_cb.otp_fd, ASPEED_OTP_GET_REVID, &revid);
	if (ret)
		goto end;

	revid0 = revid.revid0;
	revid1 = revid.revid1;

	if (revid0 == ID0_AST2700A0 && revid1 == ID1_AST2700A0) {
		/* AST2700-A0 */
		return OTP_AST2700_A0;
	} else if (revid0 == ID0_AST2700A1 && revid1 == ID1_AST2700A1) {
		/* AST2700-A1 */
		return OTP_AST2700_A1;
	}

end:
	return OTP_FAILURE;
}

int confirm_yesno(void)
{
	int i;
	char str_input[5];

	i = 0;
	while (i < sizeof(str_input)) {
		str_input[i] = getc(stdin);
		if (str_input[i] == '\n')
			break;
		i++;
	}

	if (strncmp(str_input, "y\n", 2) == 0 ||
	    strncmp(str_input, "Y\n", 2) == 0 ||
	    strncmp(str_input, "yes\n", 4) == 0 ||
	    strncmp(str_input, "YES\n", 4) == 0)
		return 1;
	return 0;
}

static void buf_print(uint8_t *buf, int len)
{
	int i;

	printf("      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%04X: ", i);
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

static int otp_read(uint32_t offset, uint16_t *data)
{
	struct otp_read rdata;

	rdata.offset = offset;
	rdata.len = 1;
	rdata.data = (uint8_t *)data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_READ_DATA, &rdata);
	// return misc_read(otp_dev, offset, data, 1);
}

static int otp_prog(uint32_t offset, uint16_t data)
{
	struct otp_prog pdata;

	pdata.w_offset = offset;
	pdata.len = 1;
	pdata.data = (uint8_t *)&data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_PROG_DATA, &pdata);
	// return misc_write(otp_dev, offset, &data, 1);
}

static int otp_prog_multi(uint32_t offset, uint16_t *data, int num)
{
	struct otp_prog pdata;

	pdata.w_offset = offset;
	pdata.len = num;
	pdata.data = (uint8_t *)data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_PROG_DATA, &pdata);
	// return misc_write(otp_dev, offset, data, num);
}

static int otp_read_rom(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + ROM_REGION_START_ADDR, data);
}

static int otp_read_rbp(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + RBP_REGION_START_ADDR, data);
}

static int otp_read_conf(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + CONF_REGION_START_ADDR, data);
}

static int otp_read_strap(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAP_REGION_START_ADDR, data);
}

static int otp_read_strap_ext(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAPEXT_REGION_START_ADDR, data);
}

static int otp_read_strap_ext_vld(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAPEXT_REGION_START_ADDR + 0x8, data);
}

static int otp_read_data(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + USER_REGION_START_ADDR, data);
}

static int otp_read_secure(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + SEC_REGION_START_ADDR, data);
}

static int otp_read_secure_multi(uint32_t offset, uint16_t *data, int num)
{
	struct otp_read rdata;

	rdata.offset = offset + SEC_REGION_START_ADDR;
	rdata.len = num;
	rdata.data = (uint8_t *)data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_READ_DATA, &rdata);
	// return misc_read(otp_dev, offset + SEC_REGION_START_ADDR, data, num);
}

static int otp_read_cptra(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + CAL_REGION_START_ADDR, data);
}

static int otp_print_rom(uint32_t offset, int w_count)
{
	int range = OTP_ROM_REGION_SIZE;
	uint16_t ret[1];
	int rc;

	if (offset + w_count > range)
		return OTP_USAGE;

	printf("ROM_REGION: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(ROM_REGION_START_ADDR + i, &ret[0]);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(RBP_REGION_START_ADDR + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(CONF_REGION_START_ADDR + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(STRAP_REGION_START_ADDR + 2 + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(STRAP_REGION_START_ADDR + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(STRAPEXT_REGION_START_ADDR + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(STRAPEXT_REGION_START_ADDR + 0x8 + i, ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	printf("User Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(USER_REGION_START_ADDR + i, &ret[0]);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	printf("Secure Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(SEC_REGION_START_ADDR + i, &ret);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	printf("Caliptra Region: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(CAL_REGION_START_ADDR + i, &ret[0]);
		if (rc)
			return rc;

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

	if (offset + w_count > range)
		return OTP_USAGE;

	printf("PUF: 0x%x~0x%x\n", offset, offset + w_count);
	for (int i = offset; i < offset + w_count; i++) {
		rc = otp_read(SW_PUF_REGION_START_ADDR + i, &ret[0]);
		if (rc)
			return rc;

		if (i % 8 == 0)
			printf("\n%03X: %04X ", i * 2, ret[0]);
		else
			printf("%04X ", ret[0]);
	}
	printf("\n");

	return OTP_SUCCESS;
}

static int otp_prog_data(int mode, int otp_w_offset, int bit_offset,
			 int value, int nconfirm, bool debug)
{
	bool prog_multi = false;
	uint32_t prog_address;
	uint16_t data[8];
	uint16_t read[1];
	int ret = 0;
	int w_count;

	memset(data, 0, sizeof(data));

	switch (mode) {
	case OTP_REGION_ROM:
		otp_read_rom(otp_w_offset, read);
		prog_address = ROM_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPROM%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_RBP:
		otp_read_rbp(otp_w_offset, read);

		if (otp_w_offset >= SOC_HW_SVN_ADDR && otp_w_offset < CAL_FMC_HW_SVN_ADDR) {
			prog_multi = true;
			w_count = 4;
			prog_address = RBP_REGION_START_ADDR + SOC_HW_SVN_ADDR;
			data[otp_w_offset - SOC_HW_SVN_ADDR] = value << bit_offset;

		} else if (otp_w_offset >= CAL_FMC_HW_SVN_ADDR && otp_w_offset < CAL_RT_HW_SVN_ADDR) {
			prog_multi = true;
			w_count = 2;
			prog_address = RBP_REGION_START_ADDR + CAL_FMC_HW_SVN_ADDR;
			data[otp_w_offset - CAL_FMC_HW_SVN_ADDR] = value << bit_offset;

		} else if (otp_w_offset >= CAL_RT_HW_SVN_ADDR && otp_w_offset < CAL_MANU_ECC_KEY_MASK) {
			prog_multi = true;
			w_count = 8;
			prog_address = RBP_REGION_START_ADDR + CAL_RT_HW_SVN_ADDR;
			data[otp_w_offset - CAL_RT_HW_SVN_ADDR] = value << bit_offset;

		} else {
			prog_address = RBP_REGION_START_ADDR + otp_w_offset;
		}

		if (debug)
			printf("Program OTPRBP%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);

		if (prog_multi && debug) {
			printf("Program OTPRBP%d = ", prog_address - RBP_REGION_START_ADDR);
			for (int i = 0; i < w_count; i++)
				printf("0x%04x ", data[i]);
			printf("\n");
		}

		break;
	case OTP_REGION_CONF:
		otp_read_conf(otp_w_offset, read);
		prog_address = CONF_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPCFG%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_STRAP:
		otp_read_strap(otp_w_offset, read);
		prog_address = STRAP_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPSTRAP%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_STRAP_EXT:
		otp_read_strap_ext(otp_w_offset, read);
		prog_address = STRAPEXT_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPSTRAPEXT%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_STRAP_EXT_VLD:
		otp_read_strap_ext_vld(otp_w_offset, read);
		prog_address = STRAPEXT_REGION_START_ADDR + 0x8 + otp_w_offset;
		if (debug)
			printf("Program OTPSTRAPEXT_VLD%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_USER_DATA:
		otp_read_data(otp_w_offset, read);
		prog_address = USER_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPDATA%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_SECURE:
		otp_read_secure(otp_w_offset, read);
		prog_address = SEC_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPSEC%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_CALIPTRA:
		otp_read_cptra(otp_w_offset, read);
		prog_address = CAL_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPCAL%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	default:
		printf("mode 0x%x is not supported\n", mode);
		return OTP_FAILURE;
	}

	if (!nconfirm) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	if (prog_multi) {
		ret = otp_prog_multi(prog_address, data, w_count);
	} else {
		value = value << bit_offset;
		ret = otp_prog(prog_address, value);
	}

	if (ret) {
		printf("OTP cannot be programmed\n");
		printf("FAILURE\n");
		return OTP_FAILURE;
	}

	if (debug)
		printf("SUCCESS\n");

	return OTP_SUCCESS;
}

static void otp_strap_status(struct otpstrap_status *otpstrap)
{
	int strap_start, strap_end;
	uint16_t data[2];
	int ret;

	/* Initial otpstrap */
	for (int i = 0; i < 32; i++) {
		otpstrap[i].value = 0;
		otpstrap[i].remain_times = 6;
		otpstrap[i].writeable_option = -1;
		otpstrap[i].protected = 0;
	}

	/* Check OTP strap value */
	strap_start = 2;
	strap_end = 2 + 12;

	for (int i = strap_start; i < strap_end; i += 2) {
		int option = (i - strap_start) / 2;

		otp_read_strap(i, &data[0]);
		otp_read_strap(i + 1, &data[1]);

		for (int j = 0; j < 16; j++) {
			char bit_value = ((data[0] >> j) & 0x1);

			if (bit_value == 0 && otpstrap[j].writeable_option == -1)
				otpstrap[j].writeable_option = option;
			if (bit_value == 1)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bit_value;
			otpstrap[j].option_value[option] = bit_value;
		}

		for (int j = 16; j < 32; j++) {
			char bit_value = ((data[1] >> (j - 16)) & 0x1);

			if (bit_value == 0 && otpstrap[j].writeable_option == -1)
				otpstrap[j].writeable_option = option;
			if (bit_value == 1)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bit_value;
			otpstrap[j].option_value[option] = bit_value;
		}
	}

	/* Check OTP strap write protect */
	ret = otp_read_strap(0, &data[0]);
	ret += otp_read_strap(1, &data[1]);
	if (ret)
		printf("OTP read strap failed, ret=0x%x\n", ret);

	for (int j = 0; j < 16; j++) {
		if (((data[0] >> j) & 0x1) == 1)
			otpstrap[j].protected = 1;
	}

	for (int j = 16; j < 32; j++) {
		if (((data[1] >> (j - 16)) & 0x1) == 1)
			otpstrap[j].protected = 1;
	}

#ifdef DEBUG
	for (int i = 0; i < 32; i++) {
		printf("otpstrap[%d]: value:%d, remain_times:%d, writeable_option:%d, protected:%d\n",
		       i, otpstrap[i].value, otpstrap[i].remain_times,
		       otpstrap[i].writeable_option, otpstrap[i].protected);

		printf("option_value: ");
		for (int j = 0; j < 6; j++)
			printf("%d ", otpstrap[i].option_value[j]);
		printf("\n");
	}
#endif
}

static int otp_print_rbp_info(void)
{
	const struct otprbp_info *rbp_info = info_cb.rbp_info;
	uint16_t OTPRBP[21];
	uint32_t w_offset;
	uint32_t length;

	for (int i = 0; i < 21; i++)
		otp_read_rbp(i, &OTPRBP[i]);

	printf("W   bit-length            Description                       Value\n");
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

	for (int i = 0; i < 32; i++)
		otp_read_conf(i, &OTPCFG[i]);

	printf("W    BIT        Value       Description\n");
	printf("__________________________________________________________________________\n");
	for (int i = 0; i < info_cb.conf_info_len; i++) {
		w_offset = conf_info[i].w_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[w_offset] >> bit_offset) & mask;

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

static void otp_print_strap_info(void)
{
	const struct otpstrap_info *strap_info = info_cb.strap_info;
	struct otpstrap_status strap_status[32];
	uint32_t bit_offset;
	uint32_t length;
	uint32_t otp_value;
	uint32_t otp_protect;

	otp_strap_status(strap_status);

	printf("BIT(hex) Value  Remains  Protect   Description\n");
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
			printf("0x%-7X", strap_info[i].bit_offset + j);
			printf("0x%-5X", strap_status[bit_offset + j].value);
			printf("%-9d", strap_status[bit_offset + j].remain_times);
			printf("0x%-7X", strap_status[bit_offset + j].protected);
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

	/* Read Flash strap */
	for (int i = 0; i < 8; i++)
		otp_read_strap_ext(i, &data[i]);

	/* Read Flash strap valid */
	for (int i = 0; i < 8; i++)
		otp_read_strap_ext_vld(i, &vld[i]);

	printf("BIT(hex) Value  Valid   Description\n");
	printf("___________________________________________________________________________________________________\n");

	for (int i = 0; i < info_cb.strap_ext_info_len; i++) {
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

		for (int j = 0; j < length; j++) {
			printf("0x%-7x", strap_ext_info[i].bit_offset + j);
			printf("0x%-5x", (otp_value & BIT(j)) >> j);
			printf("0x%-5x", (otp_vld & BIT(j)) >> j);

			if (length == 1) {
				printf(" %s\n", strap_ext_info[i].information);
				continue;
			}

			if (j == 0)
				printf("/%s\n", strap_ext_info[i].information);
			else if (j == length - 1)
				printf("\\ \"\n");
			else
				printf("| \"\n");
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

static void sb_sha384(uint8_t *src, uint32_t len, uint8_t *digest_ret)
{
	EVP_Digest(src, len, digest_ret, NULL, EVP_sha384(), NULL);
}

static int otp_verify_image(uint8_t *src_buf, uint32_t length, uint8_t *digest_buf)
{
	uint8_t digest_ret[48];
	int digest_len;

	sb_sha384(src_buf, length, digest_ret);
	digest_len = 48;

	if (!memcmp(digest_buf, digest_ret, digest_len))
		return OTP_SUCCESS;

	printf("%s: digest should be:\n", __func__);
	buf_print(digest_ret, 48);
	return OTP_FAILURE;
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

	otp_read_secure_multi(0, buf, OTP_SEC_REGION_SIZE);
	otp_print_key((uint32_t *)buf);
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

	printf("W   bit-length            Description                       Value\n");
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

static int otp_prog_image_region(struct otp_image_layout *image_layout, enum otp_region region_type)
{
	int (*otp_read_func)(uint32_t offset, uint16_t *data);
	uint16_t otp_value;
	uint16_t *buf;
	int size, w_region_size;
	int ret;

	switch (region_type) {
	case OTP_REGION_ROM:
		buf = (uint16_t *)image_layout->rom;
		size = image_layout->rom_length;
		w_region_size = OTP_ROM_REGION_SIZE;
		otp_read_func = otp_read_rom;
		break;
	case OTP_REGION_RBP:
		buf = (uint16_t *)image_layout->rbp;
		size = image_layout->rbp_length;
		w_region_size = OTP_RBP_REGION_SIZE;
		otp_read_func = otp_read_rbp;
		break;
	case OTP_REGION_CONF:
		buf = (uint16_t *)image_layout->conf;
		size = image_layout->conf_length;
		w_region_size = OTP_CONF_REGION_SIZE;
		otp_read_func = otp_read_conf;
		break;
	case OTP_REGION_SECURE:
		buf = (uint16_t *)image_layout->secure;
		size = image_layout->secure_length;
		w_region_size = OTP_SEC_REGION_SIZE;
		otp_read_func = otp_read_secure;
		break;
	case OTP_REGION_CALIPTRA:
		buf = (uint16_t *)image_layout->cptra;
		size = image_layout->cptra_length;
		w_region_size = OTP_CAL_REGION_SIZE;
		otp_read_func = otp_read_cptra;
		break;
	default:
		printf("%s: region type 0x%x is not supported\n", __func__, region_type);
		return OTP_FAILURE;
	}

	if (size != w_region_size * 2) {
		printf("image size is mismatch, size:0x%x, should be:0x%x\n",
		       size, w_region_size * 2);
		return OTP_FAILURE;
	}

	printf("Start Programing...\n");
	for (int i = 0; i < size / 2; i++) {
		otp_read_func(i, &otp_value);
		if (otp_value) {
			if (otp_value != buf[i])
				printf("Warning: OTP region w_offset [0x%x]=0x%x prog to 0x%x\n",
				       i, otp_value, buf[i]);
			continue;
		} else {
			ret = otp_prog_data(region_type, i, 0, buf[i], 1, false);
			if (ret) {
				printf("%s: Prog Failed, ret:0x%x\n", __func__, ret);
				return ret;
			}
		}
	}
	printf("Done\n");

	return OTP_SUCCESS;
}

static int otp_prog_strap_image(struct otp_image_layout *image_layout,
				struct otpstrap_status *otpstrap)
{
	uint32_t *strap;
	uint32_t *strap_pro;
	uint32_t w_offset;
	int bit, pbit, offset;
	int fail = 0;
	int prog_flag = 0;
	int bit_offset;
	int ret;

	strap = (uint32_t *)image_layout->strap;
	strap_pro = strap + 1;

	printf("Start Programing...\n");
	for (int i = 0; i < 32; i++) {
		offset = i;
		bit = (strap[0] >> offset) & 0x1;
		bit_offset = i % 16;
		pbit = (strap_pro[0] >> offset) & 0x1;
		if (i < 16)
			w_offset = otpstrap[i].writeable_option * 2 + 2;
		else
			w_offset = otpstrap[i].writeable_option * 2 + 3;

		if (bit == otpstrap[i].value)
			prog_flag = 0;
		else
			prog_flag = 1;

		if (otpstrap[i].protected == 1 && prog_flag) {
			fail = 1;
			printf("Warning: OTPSTRAP[0x%x] is protected, cannot be programmed\n", i);
			continue;
		}
		if (otpstrap[i].remain_times == 0 && prog_flag) {
			fail = 1;
			printf("Warning: OTPSTRAP[0x%x] no remain times\n", i);
			continue;
		}

		if (prog_flag) {
			ret = otp_prog_data(OTP_REGION_STRAP, w_offset, bit_offset, bit, 1, false);
			if (ret)
				return OTP_FAILURE;
		}

		if (pbit) {
			if (i < 16)
				w_offset = 0;
			else
				w_offset = 1;

			ret = otp_prog_data(OTP_REGION_STRAP, w_offset, bit_offset, pbit, 1, false);
			if (ret)
				return OTP_FAILURE;
		}
	}

	if (fail == 1)
		return OTP_FAILURE;

	printf("Done\n");
	return OTP_SUCCESS;
}

static int otp_prog_strap_ext_image(struct otp_image_layout *image_layout)
{
	uint16_t *strap_ext;
	uint16_t *strap_ext_vld;
	int w_offset, bit_offset;
	int bit, vbit;
	int fail = 0;
	int ret;

	strap_ext = (uint16_t *)image_layout->strap_ext;
	strap_ext_vld = strap_ext + 8;

	printf("Start Programing...\n");
	for (int i = 0; i < 128; i++) {
		w_offset = i / 16;
		bit_offset = i % 16;
		bit = (strap_ext[w_offset] >> bit_offset) & 0x1;
		vbit = (strap_ext_vld[w_offset] >> bit_offset) & 0x1;

		if (bit) {
			ret = otp_prog_data(OTP_REGION_STRAP_EXT, w_offset, bit_offset, 1, 1,
					    false);
			if (ret)
				return OTP_FAILURE;
		}

		if (vbit) {
			ret = otp_prog_data(OTP_REGION_STRAP_EXT_VLD, w_offset, bit_offset, 1, 1,
					    false);
			if (ret)
				return OTP_FAILURE;
		}
	}

	if (fail == 1)
		return OTP_FAILURE;

	printf("Done\n");
	return OTP_SUCCESS;
}

static int otp_prog_image(uint8_t *buf, int nconfirm)
{
	struct otp_image_layout image_layout;
	struct otpstrap_status otpstrap[32];
	struct otp_header *otp_header;
	int image_soc_ver = 0;
	int image_size;
	int ret;
	uint8_t *checksum;

	otp_header = (struct otp_header *)buf;
	if (!otp_header) {
		printf("Failed to map physical memory\n");
		return OTP_FAILURE;
	}

	image_size = OTP_IMAGE_SIZE(otp_header->image_info);
	printf("image_info:0x%x image_size: 0x%x\n", otp_header->image_info, image_size);

	checksum = buf + otp_header->checksum_offset;

	/* Check Image Magic */
	if (strncmp(OTP_MAGIC, (char *)otp_header->otp_magic, strlen(OTP_MAGIC)) != 0) {
		printf("Image is invalid, magic 0x%x should be %s\n",
		       *(uint32_t *)otp_header->otp_magic, OTP_MAGIC);
		return OTP_FAILURE;
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

	if (otp_header->soc_ver == SOC_AST2700A0) {
		image_soc_ver = OTP_AST2700_A0;
	} else if (otp_header->soc_ver == SOC_AST2700A1) {
		image_soc_ver = OTP_AST2700_A1;
	} else {
		printf("Image SOC Version is not supported\n");
		return OTP_FAILURE;
	}

	if (image_soc_ver != info_cb.version) {
		printf("Image SOC version is not match to HW SOC version\n");
		return OTP_FAILURE;
	}

	ret = otp_verify_image(buf, image_size, checksum);
	if (ret) {
		printf("checksum is invalid\n");
		return OTP_FAILURE;
	}

	if (info_cb.pro_sts.fields.mem_lock) {
		printf("OTP memory is locked\n");
		return OTP_FAILURE;
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

	if (ret == -1)
		return OTP_FAILURE;

	if (!nconfirm) {
		if (otp_header->image_info & OTP_INC_ROM) {
			printf("\nOTP ROM region :\n");
			if (otp_print_rom_image(&image_layout) < 0) {
				printf("OTP print rom error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_RBP) {
			printf("\nOTP RBP region :\n");
			if (otp_print_rbp_image(&image_layout) < 0) {
				printf("OTP print rbp error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_SECURE) {
			printf("\nOTP secure region :\n");
			if (otp_print_secure_image(&image_layout) < 0) {
				printf("OTP print secure error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_CONFIG) {
			printf("\nOTP configuration region :\n");
			if (otp_print_conf_image(&image_layout) < 0) {
				printf("OTP config error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_STRAP) {
			printf("\nOTP strap region :\n");
			if (otp_print_strap_image(&image_layout) < 0) {
				printf("OTP strap error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_STRAP_EXT) {
			printf("\nOTP strap extension region :\n");
			if (otp_print_strap_ext_image(&image_layout) < 0) {
				printf("OTP strap_ext error, please check.\n");
				return OTP_FAILURE;
			}
		}
		if (otp_header->image_info & OTP_INC_CALIPTRA) {
			printf("\nOTP caliptra region :\n");
			if (otp_print_cptra_image(&image_layout) < 0) {
				printf("OTP caliptra error, please check.\n");
				return OTP_FAILURE;
			}
		}

		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	if (otp_header->image_info & OTP_INC_ROM) {
		printf("programing rom region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_ROM);
		if (ret) {
			printf("Error\n");
			return ret;
		}
		// printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_RBP) {
		printf("programing rbp region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_RBP);
		if (ret) {
			printf("Error\n");
			return ret;
		}
		// printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_SECURE) {
		printf("programing secure region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_SECURE);
		if (ret) {
			printf("Error\n");
			return ret;
		}
		//printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_CONFIG) {
		printf("programing configuration region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CONF);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		//printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		printf("programing strap region ...\n");
		ret = otp_prog_strap_image(&image_layout, otpstrap);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		//printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_STRAP_EXT) {
		printf("programing strap extension region ...\n");
		ret = otp_prog_strap_ext_image(&image_layout);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		//printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_CALIPTRA) {
		printf("programing caliptra region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CALIPTRA);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		//printf("Done\n");
	}

	return OTP_SUCCESS;
}

static int do_otpinfo(int argc, char *const argv[])
{
	if (argc != 2 && argc != 3)
		return CMD_RET_USAGE;

	if (!strcmp(argv[1], "rbp"))
		otp_print_rbp_info();
	if (!strcmp(argv[1], "conf"))
		otp_print_conf_info();
	else if (!strcmp(argv[1], "strap"))
		otp_print_strap_info();
	else if (!strcmp(argv[1], "strap-ext"))
		otp_print_strap_ext_info();
	else if (!strcmp(argv[1], "key"))
		otp_print_key_info();
	else
		return CMD_RET_USAGE;

	return CMD_RET_SUCCESS;
}

static int do_otpread(int argc, char *const argv[])
{
	uint32_t offset, count;
	int ret;

	printf("%s: %d: %s %s %s\n", __func__, argc, argv[1], argv[2], argv[3]);

	if (argc == 4) {
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		count = (uint32_t)strtoul(argv[3], NULL, 16);
	} else if (argc == 3) {
		offset = (uint32_t)strtoul(argv[2], NULL, 16);
		count = 1;
	} else {
		return CMD_RET_USAGE;
	}

	if (!strcmp(argv[1], "rom"))
		ret = otp_print_rom(offset, count);
	else if (!strcmp(argv[1], "rbp"))
		ret = otp_print_rbp(offset, count);
	else if (!strcmp(argv[1], "conf"))
		ret = otp_print_conf(offset, count);
	else if (!strcmp(argv[1], "strap"))
		ret = otp_print_strap(offset, count);
	else if (!strcmp(argv[1], "strap-pro"))
		ret = otp_print_strap_pro(offset, count);
	else if (!strcmp(argv[1], "strap-ext"))
		ret = otp_print_strap_ext(offset, count);
	else if (!strcmp(argv[1], "strap-ext-vld"))
		ret = otp_print_strap_ext_valid(offset, count);
	else if (!strcmp(argv[1], "u-data"))
		ret = otp_print_user_data(offset, count);
	else if (!strcmp(argv[1], "s-data"))
		ret = otp_print_sec_data(offset, count);
	else if (!strcmp(argv[1], "cptra"))
		ret = otp_print_cptra(offset, count);
	else if (!strcmp(argv[1], "puf"))
		ret = otp_print_puf(offset, count);
	else
		return CMD_RET_USAGE;

	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	return CMD_RET_USAGE;
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
	int ret, force = 0;
	uint8_t *buf;
	char *path;
	long fsize;
	FILE *fd;

	if (argc == 3) {
		if (strcmp(argv[1], "o"))
			return CMD_RET_USAGE;

		path = argv[2];
		force = 1;

	} else if (argc == 2) {
		path = argv[1];
		force = 0;

	} else {
		return CMD_RET_USAGE;
	}

	fd = fopen(path, "rb");
	if (!fd) {
		printf("failed to open %s\n", path);
		return OTP_FAILURE;
	}
	fseek(fd, 0, SEEK_END);
	fsize = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	buf = malloc(fsize + 1);
	ret = fread(buf, 1, fsize, fd);
	if (ret != fsize) {
		printf("Reading \"%s\" failed\n", path);
		return OTP_FAILURE;
	}
	fclose(fd);
	buf[fsize] = 0;

	ret = otp_prog_image(buf, force);

	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	else if (ret == OTP_FAILURE)
		return CMD_RET_FAILURE;
	else
		return CMD_RET_USAGE;
}

static int do_otppb(int argc, char *const argv[])
{
	struct otpstrap_status otpstrap[32];
	int mode = 0;
	int nconfirm = 0;
	int otp_addr = 0;
	int bit_offset;
	int value;
	int ret;

	if (argc != 3 && argc != 4 && argc != 5 && argc != 6) {
		printf("%s: argc:%d\n", __func__, argc);
		return CMD_RET_USAGE;
	}

	/* Drop the pb cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "conf"))
		mode = OTP_REGION_CONF;
	else if (!strcmp(argv[0], "rbp"))
		mode = OTP_REGION_RBP;
	else if (!strcmp(argv[0], "strap"))
		mode = OTP_REGION_STRAP;
	else if (!strcmp(argv[0], "strap-ext"))
		mode = OTP_REGION_STRAP_EXT;
	else if (!strcmp(argv[0], "strap-ext-vld"))
		mode = OTP_REGION_STRAP_EXT_VLD;
	else if (!strcmp(argv[0], "u-data"))
		mode = OTP_REGION_USER_DATA;
	else if (!strcmp(argv[0], "s-data"))
		mode = OTP_REGION_SECURE;
	else if (!strcmp(argv[0], "cptra"))
		mode = OTP_REGION_CALIPTRA;
	else
		return CMD_RET_USAGE;

	/* Drop the region cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "o")) {
		nconfirm = 1;
		/* Drop the force option */
		argc--;
		argv++;
	}

	if (mode == OTP_REGION_STRAP) {
		bit_offset = (int)strtoul(argv[0], NULL, 16);
		value = (int)strtoul(argv[1], NULL, 16);
		if (bit_offset >= 32)
			return CMD_RET_USAGE;
		if (value != 0 && value != 1)
			return CMD_RET_USAGE;

	} else if (mode == OTP_REGION_STRAP_EXT) {
		bit_offset = (int)strtoul(argv[0], NULL, 16);
		value = (int)strtoul(argv[1], NULL, 16);
		if (bit_offset >= 128)
			return CMD_RET_USAGE;
		if (value != 1)
			return CMD_RET_USAGE;

	} else if (mode == OTP_REGION_STRAP_EXT_VLD) {
		if (!strcmp(argv[0], "all")) {
			for (int i = 0; i < 8; i++) {
				ret = otp_prog_data(mode, i, 0, GENMASK(15, 0), 1, true);
				if (ret)
					goto end;
			}

			goto end;
		}

		bit_offset = (int)strtoul(argv[0], NULL, 16);
		value = (int)strtoul(argv[1], NULL, 16);
		if (bit_offset >= 128)
			return CMD_RET_USAGE;
		if (value != 1)
			return CMD_RET_USAGE;

	} else {
		otp_addr = (int)strtoul(argv[0], NULL, 16);
		bit_offset = (int)strtoul(argv[1], NULL, 16);
		value = (int)strtoul(argv[2], NULL, 16);
		if (bit_offset >= 16)
			return CMD_RET_USAGE;
	}

	/* Check param */
	if (mode == OTP_REGION_RBP) {
		if (otp_addr >= OTP_RBP_REGION_SIZE)
			return CMD_RET_USAGE;

	} else if (mode == OTP_REGION_CONF) {
		if (otp_addr >= OTP_CONF_REGION_SIZE)
			return CMD_RET_USAGE;

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

	} else if (mode == OTP_REGION_STRAP_EXT || mode == OTP_REGION_STRAP_EXT_VLD) {
		otp_addr = bit_offset / 16;
		bit_offset = bit_offset % 16;

	} else if (mode == OTP_REGION_USER_DATA) {
		if (otp_addr >= OTP_USER_REGION_SIZE)
			return CMD_RET_USAGE;

	} else if (mode == OTP_REGION_SECURE) {
		if (otp_addr >= OTP_SEC_REGION_SIZE)
			return CMD_RET_USAGE;

	} else if (mode == OTP_REGION_CALIPTRA) {
		if (otp_addr >= OTP_CAL_REGION_SIZE)
			return CMD_RET_USAGE;
	}

	ret = otp_prog_data(mode, otp_addr, bit_offset, value, nconfirm, true);

end:
	if (ret == OTP_SUCCESS)
		return CMD_RET_SUCCESS;
	else if (ret == OTP_FAILURE)
		return CMD_RET_FAILURE;
	else
		return CMD_RET_USAGE;
}

static int do_otpecc(int argc, char *const argv[])
{
	int ret;
	int ecc_en = 0;

	/* Get ECC status */
	ret = ioctl(info_cb.otp_fd, ASPEED_OTP_GET_ECC, &ecc_en);
	if (ret)
		return CMD_RET_FAILURE;

	/* Drop the ecc cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "status")) {
		if (ecc_en == OTP_ECC_ENABLE)
			printf("OTP ECC is enabled\n");
		else
			printf("OTP ECC is disabled\n");

		return CMD_RET_SUCCESS;

	} else if (!strcmp(argv[0], "enable")) {
		if (ecc_en == OTP_ECC_ENABLE) {
			printf("OTP ECC is already enabled\n");
			return CMD_RET_SUCCESS;
		}

		/* Set ECC enable */
		ret = ioctl(info_cb.otp_fd, ASPEED_OTP_SET_ECC, NULL);
		if (ret)
			return CMD_RET_FAILURE;

		printf("OTP ECC is enabled\n");

	} else {
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
	{ "version", 2, do_otpver   },
	{ "read",    5, do_otpread  },
	{ "prog",    3, do_otpprog  },
	{ "pb",      7, do_otppb    },
	{ "patch",   6, do_otppatch },
	{ "ecc",     3, do_otpecc   },
	{ "info",    3, do_otpinfo  }
};

static void usage(void)
{
	printf("ASPEED One-Time-Programmable sub-system\n"
	       "\totp <dev> version\n"
	       "\totp <dev> read rom|rbp|conf|strap|strap-pro|strap-ext|strap-ext-vld|u-data|s-data|cptra|puf <otp_w_offset> <w_count>\n"
	       "\totp <dev> pb rbp|conf|u-data|s-data|cptra [o] <otp_w_offset> <bit_offset> <value>\n"
	       "\totp <dev> pb strap|strap-ext|strap-ext-vld [o] <bit_offset> <value>\n"
	       "\totp <dev> pb strap-ext-vld all\n"
	       "\totp <dev> prog <addr>\n"
	       "\totp <dev> info key|rbp|conf|strap|strap-ext\n"
	       "\totp <dev> patch prog <dram_addr> <otp_w_offset> <w_count>\n"
	       "\totp <dev> patch enable pre|post <otp_start_w_offset> <w_count>\n"
	       "\totp <dev> ecc status|enable\n");
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

	if (argc < 2 || argc > 8) {
		ret = OTP_USAGE;
		goto end;
	}

	info_cb.otp_fd = open("/dev/aspeed-otp", O_RDWR);
	if (info_cb.otp_fd == -1) {
		printf("Can't open /dev/aspeed-otp, please install driver!!\n");
		exit(EXIT_FAILURE);
	}

	/* Drop the otp command */
	argc--;
	argv++;

	cp = find_cmd_tbl(argv[1], cmd_otp, ARRAY_SIZE(cmd_otp));
	if (!cp || argc > cp->maxargs) {
		printf("%s is not supported, argc:%d (max:%d)\n", argv[1], argc, cp->maxargs);
		ret = OTP_USAGE;
		goto end;
	}

	/* Drop the otp command */
	argc--;
	argv++;

	ver = chip_version();
	switch (ver) {
	case OTP_AST2700_A0:
		printf("Chip: AST2700-A0\n");
		info_cb.version = OTP_AST2700_A0;
		info_cb.strap_info = a0_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a0_strap_info);
		info_cb.strap_ext_info = a0_strap_ext_info;
		info_cb.strap_ext_info_len = ARRAY_SIZE(a0_strap_ext_info);
		break;
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
