// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Aspeed Technology Inc.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <openssl/evp.h>
#include "otp_ast2700.h"

struct otp_info_cb info_cb;

uint32_t chip_version(void)
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

	} else if ((revid0 == ID0_AST2700A1 && revid1 == ID1_AST2700A1) ||
		   (revid0 == ID0_AST2750A1 && revid1 == ID1_AST2750A1) ||
		   (revid0 == ID0_AST2720A1 && revid1 == ID1_AST2720A1)) {
		/* AST2700-A1 */
		return OTP_AST2700_A1;

	} else if ((revid0 == ID0_AST2700A2 || revid1 == ID1_AST2700A2) ||
		   (revid0 == ID0_AST2750A2 || revid1 == ID1_AST2750A2)) {
		/* AST2700-A2 */
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

void buf_print(uint8_t *buf, int len)
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
}

int otp_read_rom(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + ROM_REGION_START_ADDR, data);
}

int otp_read_rbp(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + RBP_REGION_START_ADDR, data);
}

int otp_read_conf(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + CONF_REGION_START_ADDR, data);
}

int otp_read_strap(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAP_REGION_START_ADDR, data);
}

int otp_read_strap_ext(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAPEXT_REGION_START_ADDR, data);
}

int otp_read_strap_ext_vld(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + STRAPEXT_REGION_START_ADDR + 0x8, data);
}

int otp_read_udata(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + USER_REGION_START_ADDR, data);
}

int otp_read_sdata(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + SEC_REGION_START_ADDR, data);
}

int otp_read_sdata_multi(uint32_t offset, uint16_t *data, int num)
{
	struct otp_read rdata;

	rdata.offset = offset + SEC_REGION_START_ADDR;
	rdata.len = num;
	rdata.data = (uint8_t *)data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_READ_DATA, &rdata);
}

int otp_read_cptra(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + CAL_REGION_START_ADDR, data);
}

int otp_read_swpuf(uint32_t offset, uint16_t *data)
{
	return otp_read(offset + SW_PUF_REGION_START_ADDR, data);
}

int otp_prog(uint32_t offset, uint16_t data)
{
	struct otp_prog pdata;

	pdata.w_offset = offset;
	pdata.len = 1;
	pdata.data = (uint8_t *)&data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_PROG_DATA, &pdata);
}

int otp_prog_multi(uint32_t offset, uint16_t *data, int num)
{
	struct otp_prog pdata;

	pdata.w_offset = offset;
	pdata.len = num;
	pdata.data = (uint8_t *)data;

	return ioctl(info_cb.otp_fd, ASPEED_OTP_PROG_DATA, &pdata);
}

static void sb_sha384(uint8_t *src, uint32_t len, uint8_t *digest_ret)
{
	EVP_Digest(src, len, digest_ret, NULL, EVP_sha384(), NULL);
}

int otp_verify_image(uint8_t *src_buf, uint32_t length, uint8_t *digest_buf)
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

int otp_prog_data(int mode, int otp_w_offset, int bit_offset,
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
		otp_read_udata(otp_w_offset, read);
		prog_address = USER_REGION_START_ADDR + otp_w_offset;
		if (debug)
			printf("Program OTPDATA%d[0x%X] = 0x%x...\n", otp_w_offset,
			       bit_offset, value);
		break;
	case OTP_REGION_SECURE:
		otp_read_sdata(otp_w_offset, read);
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

int otp_prog_image_region(struct otp_image_layout *image_layout, enum otp_region region_type)
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
		otp_read_func = otp_read_sdata;
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

int otp_prog_strap_image(struct otp_image_layout *image_layout,
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

int otp_prog_strap_ext_image(struct otp_image_layout *image_layout)
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
