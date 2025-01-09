// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 Aspeed Technology Inc.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "otp_ast2700.h"

bool lib_otp_is_init;

int lib_otp_init(void)
{
	info_cb.otp_fd = open("/dev/aspeed-otp", O_RDWR);
	if (info_cb.otp_fd == -1) {
		printf("Can't open /dev/aspeed-otp, please install driver!!\n");
		return -EIO;
	}

	lib_otp_is_init = true;

	return 0;
}

int lib_otp_read_data(int mode, int offset, int w_count, uint16_t *output)
{
	int (*otp_read_func)(uint32_t offset, uint16_t *data);
	uint16_t *data = output;
	int range;
	int rc;

	if (!lib_otp_is_init) {
		rc = lib_otp_init();
		if (rc) {
			printf("lib OTP init failed\n");
			goto end;
		}
	}

	if (!output) {
		printf("Invalid parameters\n");
		rc = -EINVAL;
		goto end;
	}

	switch (mode) {
	case OTP_REGION_ROM:
		otp_read_func = otp_read_rom;
		range = OTP_ROM_REGION_SIZE;
		break;
	case OTP_REGION_RBP:
		otp_read_func = otp_read_rbp;
		range = OTP_RBP_REGION_SIZE;
		break;
	case OTP_REGION_CONF:
		otp_read_func = otp_read_conf;
		range = OTP_CONF_REGION_SIZE;
		break;
	case OTP_REGION_STRAP:
		otp_read_func = otp_read_strap;
		range = OTP_STRAP_REGION_SIZE;
		break;
	case OTP_REGION_STRAP_EXT:
		otp_read_func = otp_read_strap_ext;
		range = OTP_STRAP_EXT_REGION_SIZE / 2;
		break;
	case OTP_REGION_STRAP_EXT_VLD:
		otp_read_func = otp_read_strap_ext_vld;
		range = OTP_STRAP_EXT_REGION_SIZE / 2;
		break;
	case OTP_REGION_USER_DATA:
		otp_read_func = otp_read_udata;
		range = OTP_USER_REGION_SIZE;
		break;
	case OTP_REGION_SECURE:
		otp_read_func = otp_read_sdata;
		range = OTP_SEC_REGION_SIZE;
		break;
	case OTP_REGION_CALIPTRA:
		otp_read_func = otp_read_cptra;
		range = OTP_CAL_REGION_SIZE;
		break;
	case OTP_REGION_PUF:
		otp_read_func = otp_read_swpuf;
		range = OTP_PUF_REGION_SIZE;
		break;
	default:
		printf("mode %d is not supported\n", mode);
		return -EINVAL;
	}

	if (offset + w_count > range) {
		printf("Out of range\n");
		rc = -EINVAL;
		goto end;
	}

	for (int i = 0; i < w_count; i++) {
		otp_read_func(offset + i, data + i);
		// printf("read data[%d]: 0x%x:0x%x\n", offset + i,
		//	(uintptr_t)(data + i), *(data + i));
	}

	return 0;

end:
	return rc;
}

int lib_otp_prog_data(int mode, int offset, int w_count, uint16_t *input)
{
	uint32_t prog_address;
	int range;
	int rc;

	if (!lib_otp_is_init) {
		rc = lib_otp_init();
		if (rc) {
			printf("lib OTP init failed\n");
			goto end;
		}
	}

	if (!input) {
		printf("Invalid parameters\n");
		rc = -EINVAL;
		goto end;
	}

	switch (mode) {
	case OTP_REGION_CALIPTRA:
		prog_address = CAL_REGION_START_ADDR + offset;
		range = OTP_CAL_REGION_SIZE;
		break;
	default:
		printf("mode %d is not supported\n", mode);
		break;
	}

	if (offset + w_count > range) {
		printf("Out of range\n");
		rc = -EINVAL;
		goto end;
	}

	for (int i = 0; i < w_count; i++) {
		rc = otp_prog(prog_address, *input);
		printf("OTP prog 0x%x=0x%x\n", prog_address, *input);
		if (rc) {
			printf("OTP prog failed\n");
			goto end;
		}
		prog_address++;
		input++;
	}

	return 0;
end:
	return rc;
}

int lib_otp_prog_image(char *path)
{
	struct otp_image_layout image_layout;
	struct otpstrap_status otpstrap[32];
	struct otp_header *otp_header;
	int image_soc_ver = 0;
	int image_size;
	int ret = 0;
	uint8_t *checksum;
	uint8_t *buf;
	long fsize;
	FILE *fd;
	int rc;

	if (!lib_otp_is_init) {
		rc = lib_otp_init();
		if (rc) {
			printf("lib OTP init failed\n");
			goto end;
		}
	}

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

	if (otp_header->soc_ver == SOC_AST2700A1) {
		image_soc_ver = OTP_AST2700_A1;
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

	if (otp_header->image_info & OTP_INC_ROM) {
		printf("programing rom region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_ROM);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_RBP) {
		printf("programing rbp region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_RBP);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_SECURE) {
		printf("programing secure region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_SECURE);
		if (ret) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_CONFIG) {
		printf("programing configuration region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CONF);
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
		ret = otp_prog_strap_ext_image(&image_layout);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}
	if (otp_header->image_info & OTP_INC_CALIPTRA) {
		printf("programing caliptra region ...\n");
		ret = otp_prog_image_region(&image_layout, OTP_REGION_CALIPTRA);
		if (ret != 0) {
			printf("Error\n");
			goto end;
		}
	}

	return OTP_SUCCESS;
end:
	return ret;
}
