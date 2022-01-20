/*
 * Copyright 2021 Aspeed Technology Inc.
 */

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
#include "aspeed-otp.h"
#include "otp_info.h"
#include "sha256.h"

#define OTP_VER				"1.2.1"

#define BIT(nr)					(1UL << (nr))
#define OTP_REGION_STRAP		BIT(0)
#define OTP_REGION_CONF			BIT(1)
#define OTP_REGION_DATA			BIT(2)

#define OTP_USAGE				-1
#define OTP_FAILURE				-2
#define OTP_SUCCESS				0

#define OTP_PROG_SKIP			1

#define OTP_KEY_TYPE_RSA_PUB	1
#define OTP_KEY_TYPE_RSA_PRIV	2
#define OTP_KEY_TYPE_AES		3
#define OTP_KEY_TYPE_VAULT		4
#define OTP_KEY_TYPE_HMAC		5

#define OTP_MAGIC		        "SOCOTP"
#define CHECKSUM_LEN	        32
#define OTP_INC_DATA	        BIT(31)
#define OTP_INC_CONF	        BIT(30)
#define OTP_INC_STRAP	        BIT(29)
#define OTP_ECC_EN		        BIT(28)
#define OTP_INC_SCU_PRO			BIT(25)
#define OTP_REGION_SIZE(info)	(((info) >> 16) & 0xffff)
#define OTP_REGION_OFFSET(info)	((info) & 0xffff)
#define OTP_IMAGE_SIZE(info)	((info) & 0xffff)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SOC_AST2600A0	0
#define SOC_AST2600A1	1
#define SOC_AST2600A2	2
#define SOC_AST2600A3	3

#define OTPTOOL_VERSION(a, b, c) (((a) << 24) + ((b) << 12) + (c))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

struct otp_header {
	u8	otp_magic[8];
	u32	soc_ver;
	u32	otptool_ver;
	u32	image_info;
	u32	data_info;
	u32	conf_info;
	u32	strap_info;
	u32	scu_protect_info;
	u32	checksum_offset;
} __packed;

struct otpstrap_status {
	int value;
	int option_array[7];
	int remain_times;
	int writeable_option;
	int protected;
};

struct otpconf_parse {
	int dw_offset;
	int bit;
	int length;
	int value;
	int ignore;
	char status[80];
};

struct otpkey_type {
	int value;
	int key_type;
	int need_id;
	char information[110];
};

struct otp_pro_sts {
	char mem_lock;
	char pro_key_ret;
	char pro_strap;
	char pro_conf;
	char pro_data;
	char pro_sec;
	u32 sec_size;
};

struct otp_info_cb {
	int otp_fd;
	int version;
	const struct otpstrap_info *strap_info;
	int strap_info_len;
	const struct otpconf_info *conf_info;
	int conf_info_len;
	const struct otpkey_type *key_info;
	int key_info_len;
	const struct scu_info *scu_info;
	int scu_info_len;
	struct otp_pro_sts pro_sts;
};

struct otp_image_layout {
	int data_length;
	int conf_length;
	int strap_length;
	int scu_pro_length;
	uint8_t *data;
	uint8_t *data_ignore;
	uint8_t *conf;
	uint8_t *conf_ignore;
	uint8_t *strap;
	uint8_t *strap_pro;
	uint8_t *strap_ignore;
	uint8_t *scu_pro;
	uint8_t *scu_pro_ignore;
};

static struct otp_info_cb info_cb;

static const struct otpkey_type a0_key_type[] = {
	{0, OTP_KEY_TYPE_AES,   0, "AES-256 as OEM platform key for image encryption/decryption"},
	{1, OTP_KEY_TYPE_VAULT, 0, "AES-256 as secret vault key"},
	{4, OTP_KEY_TYPE_HMAC,  1, "HMAC as encrypted OEM HMAC keys in Mode 1"},
	{8, OTP_KEY_TYPE_RSA_PUB,   1, "RSA-public as OEM DSS public keys in Mode 2"},
	{9, OTP_KEY_TYPE_RSA_PUB,   0, "RSA-public as SOC public key"},
	{10, OTP_KEY_TYPE_RSA_PUB,  0, "RSA-public as AES key decryption key"},
	{13, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as SOC private key"},
	{14, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as AES key decryption key"},
};

static const struct otpkey_type a1_key_type[] = {
	{1, OTP_KEY_TYPE_VAULT, 0, "AES-256 as secret vault key"},
	{2, OTP_KEY_TYPE_AES,   1, "AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM"},
	{8, OTP_KEY_TYPE_RSA_PUB,   1, "RSA-public as OEM DSS public keys in Mode 2"},
	{10, OTP_KEY_TYPE_RSA_PUB,  0, "RSA-public as AES key decryption key"},
	{14, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as AES key decryption key"},
};

static const struct otpkey_type a2_key_type[] = {
	{1, OTP_KEY_TYPE_VAULT, 0, "AES-256 as secret vault key"},
	{2, OTP_KEY_TYPE_AES,   1, "AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM"},
	{8, OTP_KEY_TYPE_RSA_PUB,   1, "RSA-public as OEM DSS public keys in Mode 2"},
	{10, OTP_KEY_TYPE_RSA_PUB,  0, "RSA-public as AES key decryption key"},
	{14, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as AES key decryption key"},
};

static const struct otpkey_type a3_key_type[] = {
	{1, OTP_KEY_TYPE_VAULT, 0, "AES-256 as secret vault key"},
	{2, OTP_KEY_TYPE_AES,   1, "AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM"},
	{8, OTP_KEY_TYPE_RSA_PUB,   1, "RSA-public as OEM DSS public keys in Mode 2"},
	{9, OTP_KEY_TYPE_RSA_PUB,   1, "RSA-public as OEM DSS public keys in Mode 2(big endian)"},
	{10, OTP_KEY_TYPE_RSA_PUB,  0, "RSA-public as AES key decryption key"},
	{11, OTP_KEY_TYPE_RSA_PUB,  0, "RSA-public as AES key decryption key(big endian)"},
	{12, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as AES key decryption key"},
	{13, OTP_KEY_TYPE_RSA_PRIV,  0, "RSA-private as AES key decryption key(big endian)"},
};

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

static int get_dw_bit(uint32_t *rid, int offset)
{
	int bit_offset;
	int i;

	if (offset < 32) {
		i = 0;
		bit_offset = offset;
	} else {
		i = 1;
		bit_offset = offset - 32;
	}
	if ((rid[i] >> bit_offset) & 0x1)
		return 1;
	else
		return 0;
}

static int get_rid_num(uint32_t *rid)
{
	int i;
	int fz = 0;
	int rid_num = 0;
	int ret = 0;

	for (i = 0; i < 64; i++) {
		if (get_dw_bit(rid, i) == 0) {
			if (!fz)
				fz = 1;

		} else {
			rid_num++;
			if (fz)
				ret = OTP_FAILURE;
		}
	}
	if (ret)
		return ret;

	return rid_num;
}

static int otp_strap_bit_confirm(struct otpstrap_status *otpstrap, int offset, int ibit, int bit, int pbit)
{
	int prog_flag = 0;

	// ignore this bit
	if (ibit == 1)
		return OTP_SUCCESS;
	printf("OTPSTRAP[0x%X]:\n", offset);

	if (bit == otpstrap->value) {
		if (!pbit) {
			printf("    The value is same as before, skip it.\n");
			return OTP_PROG_SKIP;
		}
		printf("    The value is same as before.\n");
	} else {
		prog_flag = 1;
	}
	if (otpstrap->protected == 1 && prog_flag) {
		printf("    This bit is protected and is not writable\n");
		return OTP_FAILURE;
	}
	if (otpstrap->remain_times == 0 && prog_flag) {
		printf("    This bit is no remaining times to write.\n");
		return OTP_FAILURE;
	}
	if (pbit == 1)
		printf("    This bit will be protected and become non-writable.\n");
	if (prog_flag)
		printf("    Write 1 to OTPSTRAP[0x%X] OPTION[0x%X], that value becomes from %d to %d.\n", offset, otpstrap->writeable_option + 1, otpstrap->value, otpstrap->value ^ 1);

	return OTP_SUCCESS;
}

static uint32_t chip_version(void)
{
	uint32_t ver;
	int ret;

	ret = ioctl(info_cb.otp_fd, ASPEED_OTP_VER, &ver);

	if (ret < 0) {
		printf("ioctl err:%d\n", ret);
		return OTP_FAILURE;
	}

	return ver;
}

static uint32_t sw_revid(u32 *sw_rid)
{
	int ret;

	ret = ioctl(info_cb.otp_fd, ASPEED_OTP_SW_RID, sw_rid);

	if (ret < 0) {
		printf("ioctl err:%d\n", ret);
		return OTP_FAILURE;
	}

	return OTP_SUCCESS;
}

static uint32_t sec_key_num(u32 *key_num)
{
	int ret;

	ret = ioctl(info_cb.otp_fd, ASPEED_SEC_KEY_NUM, key_num);

	if (ret < 0) {
		printf("ioctl err:%d\n", ret);
		return OTP_FAILURE;
	}

	return OTP_SUCCESS;
}

static int _otp_read(uint32_t offset, int len, uint32_t *data, unsigned long req)
{
	int ret;
	struct otp_read xfer;

	xfer.data = data;
	xfer.offset = offset;
	xfer.len = len;
	ret = ioctl(info_cb.otp_fd, req, &xfer);
	if (ret < 0) {
		printf("ioctl err:%d\n", ret);
		return OTP_FAILURE;
	}
	return OTP_SUCCESS;
}

static int _otp_prog(uint32_t dw_offset, uint32_t bit_offset, uint32_t value, unsigned long req)
{
	int ret;
	struct otp_prog prog;

	prog.dw_offset = dw_offset;
	prog.bit_offset = bit_offset;
	prog.value = value;

	ret = ioctl(info_cb.otp_fd, req, &prog);
	if (ret < 0) {
		printf("ioctl err:%d\n", ret);
		return OTP_FAILURE;
	}
	return OTP_SUCCESS;
}

static int otp_read_conf_buf(uint32_t offset, int len, uint32_t *data)
{
	return _otp_read(offset, len, data, ASPEED_OTP_READ_CONF);
}

static int otp_read_data_buf(uint32_t offset, int len, uint32_t *data)
{
	return _otp_read(offset, len, data, ASPEED_OTP_READ_DATA);
}

static int otp_read_conf(uint32_t offset, uint32_t *data)
{
	return _otp_read(offset, 1, data, ASPEED_OTP_READ_CONF);
}

static int otp_read_data(uint32_t offset, uint32_t *data)
{
	return _otp_read(offset, 1, data, ASPEED_OTP_READ_DATA);
}

static void otp_read_strap(struct otpstrap_status *otpstrap)
{
	uint32_t OTPSTRAP_RAW[16];
	int strap_end;
	int i, j, k;
	char bit_value;
	int option;

	if (info_cb.version == OTP_A0) {
		for (j = 0; j < 64; j++) {
			otpstrap[j].value = 0;
			otpstrap[j].remain_times = 7;
			otpstrap[j].writeable_option = -1;
			otpstrap[j].protected = 0;
		}
		strap_end = 30;
	} else {
		for (j = 0; j < 64; j++) {
			otpstrap[j].value = 0;
			otpstrap[j].remain_times = 6;
			otpstrap[j].writeable_option = -1;
			otpstrap[j].protected = 0;
		}
		strap_end = 28;
	}

	otp_read_conf_buf(16, 16, OTPSTRAP_RAW);

	for (i = 16, k = 0; i < strap_end; i += 2, k += 2) {
		option = (i - 16) / 2;

		for (j = 0; j < 32; j++) {
			bit_value = ((OTPSTRAP_RAW[k] >> j) & 0x1);

			if (bit_value == 0 && (otpstrap[j].writeable_option == -1))
				otpstrap[j].writeable_option = option;
			if (bit_value == 1)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bit_value;
			otpstrap[j].option_array[option] = bit_value;
		}
		for (j = 32; j < 64; j++) {
			bit_value = ((OTPSTRAP_RAW[k + 1] >> (j - 32)) & 0x1);

			if (bit_value == 0 && otpstrap[j].writeable_option == -1)
				otpstrap[j].writeable_option = option;
			if (bit_value == 1)
				otpstrap[j].remain_times--;
			otpstrap[j].value ^= bit_value;
			otpstrap[j].option_array[option] = bit_value;
		}
	}

	for (j = 0; j < 32; j++) {
		if (((OTPSTRAP_RAW[14] >> j) & 0x1) == 1)
			otpstrap[j].protected = 1;
	}
	for (j = 32; j < 64; j++) {
		if (((OTPSTRAP_RAW[15] >> (j - 32)) & 0x1) == 1)
			otpstrap[j].protected = 1;
	}
}

static int otp_prog_data_b(uint32_t dw_offset, uint32_t bit_offset, uint32_t value)
{
	return _otp_prog(dw_offset, bit_offset, value, ASPEED_OTP_PROG_DATA);
}

static int otp_prog_conf_b(uint32_t dw_offset, uint32_t bit_offset, uint32_t value)
{
	return _otp_prog(dw_offset, bit_offset, value, ASPEED_OTP_PROG_CONF);
}

static int otp_prog_strap_b(int bit_offset, int value)
{
	struct otpstrap_status otpstrap[64];
	uint32_t prog_address;
	int offset;
	int ret;

	otp_read_strap(otpstrap);

	ret = otp_strap_bit_confirm(&otpstrap[bit_offset], bit_offset, 0, value, 0);

	if (ret != OTP_SUCCESS)
		return ret;

	if (bit_offset < 32) {
		offset = bit_offset;
		prog_address = otpstrap[bit_offset].writeable_option * 2 + 16;

	} else {
		offset = (bit_offset - 32);
		prog_address = otpstrap[bit_offset].writeable_option * 2 + 17;
	}

	return otp_prog_conf_b(prog_address, offset, 1);
}

static int otp_prog_data_dw(uint32_t value, uint32_t otp_data, uint32_t ignore, uint32_t prog_address)
{
	uint32_t data_masked;
	uint32_t buf_masked;
	int j, bit_value;
	int ret;

	data_masked = otp_data & ~ignore;
	buf_masked  = value & ~ignore;
	if (data_masked == buf_masked)
		return OTP_SUCCESS;

	for (j = 0; j < 32; j++) {
		if (prog_address % 2 == 0) {
			if (((data_masked >> j) & 0x1) == 1 && ((buf_masked >> j) & 0x1) == 0)
				return OTP_FAILURE;
		} else {
			if (((data_masked >> j) & 0x1) == 0 && ((buf_masked >> j) & 0x1) == 1)
				return OTP_FAILURE;
		}
	}
	for (j = 0; j < 32; j++) {
		if ((ignore >> j) & 0x1)
			continue;
		bit_value = (value >> j) & 0x1;
		if (prog_address % 2 == 0) {
			if (!bit_value)
				continue;
		} else {
			if (bit_value)
				continue;
		}
		ret = otp_prog_data_b(prog_address, j, bit_value);
		if (ret)
			return ret;
	}
	return OTP_SUCCESS;
}

static int otp_print_conf(uint32_t offset, int dw_count)
{
	int i, j;
	uint32_t ret[32];

	if (otp_read_conf_buf(offset, dw_count, ret))
		return OTP_FAILURE;

	for (i = offset, j = 0; j < dw_count; i++, j++)
		printf("OTPCFG0x%X: 0x%08X\n", i, ret[j]);
	printf("\n");
	return OTP_SUCCESS;
}

static int otp_print_data(uint32_t offset, int dw_count)
{
	int i, j;
	uint32_t ret[2048];

	if (otp_read_data_buf(offset, dw_count, ret))
		return OTP_FAILURE;

	for (i = offset, j = 0; j < dw_count; i++, j++) {
		if (i % 4 == 0)
			printf("%03X: %08X ", i * 4, ret[j]);
		else
			printf("%08X ", ret[j]);
		if ((j + 1) % 4 == 0)
			printf("\n");
	}

	printf("\n");
	return OTP_SUCCESS;
}

static int otp_print_strap(int offset, int count)
{
	int i, j;
	int remains;
	struct otpstrap_status otpstrap[64];

	otp_read_strap(otpstrap);

	if (info_cb.version == OTP_A0)
		remains = 7;
	else
		remains = 6;
	printf("BIT(hex)  Value  Option           Status\n");
	printf("______________________________________________________________________________\n");

	for (i = offset; i < offset + count; i++) {
		printf("0x%-8X", i);
		printf("%-7d", otpstrap[i].value);
		for (j = 0; j < remains; j++)
			printf("%d ", otpstrap[i].option_array[j]);
		printf("   ");
		if (otpstrap[i].protected == 1) {
			printf("protected and not writable");
		} else {
			printf("not protected ");
			if (otpstrap[i].remain_times == 0)
				printf("and no remaining times to write.");
			else
				printf("and still can write %d times", otpstrap[i].remain_times);
		}
		printf("\n");
	}

	return OTP_SUCCESS;
}

static void otp_print_revid(uint32_t *rid)
{
	int bit_offset;
	int i, j;

	printf("     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n");
	printf("___________________________________________________\n");
	for (i = 0; i < 64; i++) {
		if (i < 32) {
			j = 0;
			bit_offset = i;
		} else {
			j = 1;
			bit_offset = i - 32;
		}
		if (i % 16 == 0)
			printf("%2x | ", i);
		printf("%d  ", (rid[j] >> bit_offset) & 0x1);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}

static int otp_print_scu_image(struct otp_image_layout *image_layout)
{
	const struct scu_info *scu_info = info_cb.scu_info;
	u32 *OTPSCU = (u32 *)image_layout->scu_pro;
	u32 *OTPSCU_IGNORE = (u32 *)image_layout->scu_pro_ignore;
	int i;
	u32 scu_offset;
	u32 dw_offset;
	u32 bit_offset;
	u32 mask;
	u32 otp_value;
	u32 otp_ignore;

	printf("SCU     BIT          reg_protect     Description\n");
	printf("____________________________________________________________________\n");
	for (i = 0; i < info_cb.scu_info_len; i++) {
		mask = BIT(scu_info[i].length) - 1;

		if (scu_info[i].bit_offset > 31) {
			scu_offset = 0x510;
			dw_offset = 1;
			bit_offset = scu_info[i].bit_offset - 32;
		} else {
			scu_offset = 0x500;
			dw_offset = 0;
			bit_offset = scu_info[i].bit_offset;
		}

		otp_value = (OTPSCU[dw_offset] >> bit_offset) & mask;
		otp_ignore = (OTPSCU_IGNORE[dw_offset] >> bit_offset) & mask;

		if (otp_ignore == mask)
			continue;
		else if (otp_ignore != 0)
			return OTP_FAILURE;

		if (otp_value != 0 && otp_value != mask)
			return OTP_FAILURE;

		printf("0x%-6X", scu_offset);
		if (scu_info[i].length == 1)
			printf("0x%-11X", bit_offset);
		else
			printf("0x%-2X:0x%-4x", bit_offset, bit_offset + scu_info[i].length - 1);
		printf("0x%-14X", otp_value);
		printf("%s\n", scu_info[i].information);
	}
	return OTP_SUCCESS;
}

static void otp_print_scu_info(void)
{
	const struct scu_info *scu_info = info_cb.scu_info;
	u32 OTPCFG[2];
	u32 scu_offset;
	u32 bit_offset;
	u32 reg_p;
	u32 length;
	int i, j;

	otp_read_conf(28, &OTPCFG[0]);
	otp_read_conf(29, &OTPCFG[1]);
	printf("SCU     BIT   reg_protect     Description\n");
	printf("____________________________________________________________________\n");
	for (i = 0; i < info_cb.scu_info_len; i++) {
		length = scu_info[i].length;
		for (j = 0; j < length; j++) {
			if (scu_info[i].bit_offset + j < 32) {
				scu_offset = 0x500;
				bit_offset = scu_info[i].bit_offset + j;
				reg_p = (OTPCFG[0] >> bit_offset) & 0x1;
			} else {
				scu_offset = 0x510;
				bit_offset = scu_info[i].bit_offset + j - 32;
				reg_p = (OTPCFG[1] >> bit_offset) & 0x1;
			}
			printf("0x%-6X", scu_offset);
			printf("0x%-4X", bit_offset);
			printf("0x%-13X", reg_p);
			if (length == 1) {
				printf(" %s\n", scu_info[i].information);
				continue;
			}

			if (j == 0)
				printf("/%s\n", scu_info[i].information);
			else if (j == length - 1)
				printf("\\ \"\n");
			else
				printf("| \"\n");
		}
	}
}

static int otp_print_conf_image(struct otp_image_layout *image_layout)
{
	const struct otpconf_info *conf_info = info_cb.conf_info;
	uint32_t *OTPCFG = (uint32_t *)image_layout->conf;
	uint32_t *OTPCFG_IGNORE = (uint32_t *)image_layout->conf_ignore;
	uint32_t mask;
	uint32_t dw_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	uint32_t otp_ignore;
	int fail = 0;
	int mask_err;
	int rid_num = 0;
	char valid_bit[20];
	int fz;
	int i;
	int j;

	printf("DW    BIT        Value       Description\n");
	printf("__________________________________________________________________________\n");
	for (i = 0; i < info_cb.conf_info_len; i++) {
		mask_err = 0;
		dw_offset = conf_info[i].dw_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[dw_offset] >> bit_offset) & mask;
		otp_ignore = (OTPCFG_IGNORE[dw_offset] >> bit_offset) & mask;

		if (conf_info[i].value == OTP_REG_VALID_BIT) {
			if (((otp_value + otp_ignore) & mask) != mask) {
				fail = 1;
				mask_err = 1;
			}
		} else {
			if (otp_ignore == mask) {
				continue;
			} else if (otp_ignore != 0) {
				fail = 1;
				mask_err = 1;
			}
		}

		if (otp_value != conf_info[i].value &&
		    conf_info[i].value != OTP_REG_RESERVED &&
		    conf_info[i].value != OTP_REG_VALUE &&
		    conf_info[i].value != OTP_REG_VALID_BIT)
			continue;
		printf("0x%-4X", dw_offset);

		if (conf_info[i].length == 1) {
			printf("0x%-9X", conf_info[i].bit_offset);
		} else {
			printf("0x%-2X:0x%-4X",
			       conf_info[i].bit_offset + conf_info[i].length - 1,
			       conf_info[i].bit_offset);
		}
		printf("0x%-10x", otp_value);

		if (mask_err) {
			printf("Ignore mask error\n");
			continue;
		}
		if (conf_info[i].value == OTP_REG_RESERVED) {
			printf("Reserved\n");
		} else if (conf_info[i].value == OTP_REG_VALUE) {
			printf(conf_info[i].information, otp_value);
			printf("\n");
		} else if (conf_info[i].value == OTP_REG_VALID_BIT) {
			if (otp_value != 0) {
				for (j = 0; j < 7; j++) {
					if (otp_value & (1 << j))
						valid_bit[j * 2] = '1';
					else
						valid_bit[j * 2] = '0';
					valid_bit[j * 2 + 1] = ' ';
				}
				valid_bit[15] = 0;
			} else {
				strcpy(valid_bit, "0 0 0 0 0 0 0 0\0");
			}
			printf(conf_info[i].information, valid_bit);
			printf("\n");
		} else {
			printf("%s\n", conf_info[i].information);
		}
	}

	if (OTPCFG[0xa] != 0 || OTPCFG[0xb] != 0) {
		if (OTPCFG_IGNORE[0xa] != 0 && OTPCFG_IGNORE[0xb] != 0) {
			printf("OTP revision ID is invalid.\n");
			fail = 1;
		} else {
			fz = 0;
			for (i = 0; i < 64; i++) {
				if (get_dw_bit(&OTPCFG[0xa], i) == 0) {
					if (!fz)
						fz = 1;
				} else {
					rid_num++;
					if (fz) {
						printf("OTP revision ID is invalid.\n");
						fail = 1;
						break;
					}
				}
			}
		}
		if (!fail)
			printf("OTP revision ID: 0x%x\n", rid_num);
		else
			printf("OTP revision ID\n");

		otp_print_revid(&OTPCFG[0xa]);
	}

	if (fail)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

static int otp_print_conf_info(int input_offset)
{
	const struct otpconf_info *conf_info = info_cb.conf_info;
	uint32_t OTPCFG[16];
	uint32_t mask;
	uint32_t dw_offset;
	uint32_t bit_offset;
	uint32_t otp_value;
	char valid_bit[20];
	int i;
	int j;

	otp_read_conf_buf(0, 16, OTPCFG);

	printf("DW    BIT        Value       Description\n");
	printf("__________________________________________________________________________\n");
	for (i = 0; i < info_cb.conf_info_len; i++) {
		if (input_offset != -1 && input_offset != conf_info[i].dw_offset)
			continue;
		dw_offset = conf_info[i].dw_offset;
		bit_offset = conf_info[i].bit_offset;
		mask = BIT(conf_info[i].length) - 1;
		otp_value = (OTPCFG[dw_offset] >> bit_offset) & mask;

		if (otp_value != conf_info[i].value &&
		    conf_info[i].value != OTP_REG_RESERVED &&
		    conf_info[i].value != OTP_REG_VALUE &&
		    conf_info[i].value != OTP_REG_VALID_BIT)
			continue;
		printf("0x%-4X", dw_offset);

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
		} else if (conf_info[i].value == OTP_REG_VALID_BIT) {
			if (otp_value != 0) {
				for (j = 0; j < 7; j++) {
					if (otp_value & (1 << j))
						valid_bit[j * 2] = '1';
					else
						valid_bit[j * 2] = '0';
					valid_bit[j * 2 + 1] = ' ';
				}
				valid_bit[15] = 0;
			} else {
				strcpy(valid_bit, "0 0 0 0 0 0 0 0\0");
			}
			printf(conf_info[i].information, valid_bit);
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
	uint32_t *OTPSTRAP;
	uint32_t *OTPSTRAP_PRO;
	uint32_t *OTPSTRAP_IGNORE;
	int i;
	int fail = 0;
	uint32_t bit_offset;
	uint32_t dw_offset;
	uint32_t mask;
	uint32_t otp_value;
	uint32_t otp_protect;
	uint32_t otp_ignore;

	OTPSTRAP = (uint32_t *)image_layout->strap;
	OTPSTRAP_PRO = (uint32_t *)image_layout->strap_pro;
	OTPSTRAP_IGNORE = (uint32_t *)image_layout->strap_ignore;

	printf("BIT(hex)   Value       Protect     Description\n");
	printf("__________________________________________________________________________________________\n");

	for (i = 0; i < info_cb.strap_info_len; i++) {
		fail = 0;
		if (strap_info[i].bit_offset > 31) {
			dw_offset = 1;
			bit_offset = strap_info[i].bit_offset - 32;
		} else {
			dw_offset = 0;
			bit_offset = strap_info[i].bit_offset;
		}

		mask = BIT(strap_info[i].length) - 1;
		otp_value = (OTPSTRAP[dw_offset] >> bit_offset) & mask;
		otp_protect = (OTPSTRAP_PRO[dw_offset] >> bit_offset) & mask;
		otp_ignore = (OTPSTRAP_IGNORE[dw_offset] >> bit_offset) & mask;

		if (otp_ignore == mask)
			continue;
		else if (otp_ignore != 0)
			fail = 1;

		if (otp_value != strap_info[i].value &&
		    strap_info[i].value != OTP_REG_RESERVED)
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

		if (fail) {
			printf("Ignore mask error\n");
		} else {
			if (strap_info[i].value != OTP_REG_RESERVED)
				printf("%s\n", strap_info[i].information);
			else
				printf("Reserved\n");
		}
	}

	if (fail)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

static int otp_print_strap_info(int view)
{
	const struct otpstrap_info *strap_info = info_cb.strap_info;
	struct otpstrap_status strap_status[64];
	int i, j;
	int fail = 0;
	uint32_t bit_offset;
	uint32_t length;
	uint32_t otp_value;
	uint32_t otp_protect;

	otp_read_strap(strap_status);

	if (view) {
		printf("BIT(hex) Value  Remains  Protect   Description\n");
		printf("___________________________________________________________________________________________________\n");
	} else {
		printf("BIT(hex)   Value       Description\n");
		printf("________________________________________________________________________________\n");
	}
	for (i = 0; i < info_cb.strap_info_len; i++) {
		otp_value = 0;
		bit_offset = strap_info[i].bit_offset;
		length = strap_info[i].length;
		for (j = 0; j < length; j++) {
			otp_value |= strap_status[bit_offset + j].value << j;
			otp_protect |= strap_status[bit_offset + j].protected << j;
		}
		if (otp_value != strap_info[i].value &&
		    strap_info[i].value != OTP_REG_RESERVED)
			continue;
		if (view) {
			for (j = 0; j < length; j++) {
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
		} else {
			if (length == 1) {
				printf("0x%-9X", strap_info[i].bit_offset);
			} else {
				printf("0x%-2X:0x%-4X",
				       bit_offset + length - 1, bit_offset);
			}

			printf("0x%-10X", otp_value);

			if (strap_info[i].value != OTP_REG_RESERVED)
				printf("%s\n", strap_info[i].information);
			else
				printf("Reserved\n");
		}
	}

	if (fail)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

static void _otp_print_key(u32 *data)
{
	int i, j;
	int key_id, key_offset, last, key_type, key_length, exp_length;
	struct otpkey_type key_info;
	const struct otpkey_type *key_info_array = info_cb.key_info;
	int len = 0;
	u8 *byte_buf;
	int empty;

	byte_buf = (u8 *)data;

	empty = 1;
	for (i = 0; i < 16; i++) {
		if (i % 2) {
			if (data[i] != 0xffffffff)
				empty = 0;
		} else {
			if (data[i] != 0)
				empty = 0;
		}
	}
	if (empty) {
		printf("OTP data header is empty\n");
		return;
	}

	for (i = 0; i < 16; i++) {
		key_id = data[i] & 0x7;
		key_offset = data[i] & 0x1ff8;
		last = (data[i] >> 13) & 1;
		key_type = (data[i] >> 14) & 0xf;
		key_length = (data[i] >> 18) & 0x3;
		exp_length = (data[i] >> 20) & 0xfff;

		key_info.value = -1;
		for (j = 0; j < info_cb.key_info_len; j++) {
			if (key_type == key_info_array[j].value) {
				key_info = key_info_array[j];
				break;
			}
		}
		if (key_info.value == -1)
			break;

		printf("\nKey[%d]:\n", i);
		printf("Key Type: ");
		printf("%s\n", key_info.information);

		if (key_info.key_type == OTP_KEY_TYPE_HMAC) {
			printf("HMAC SHA Type: ");
			switch (key_length) {
			case 0:
				printf("HMAC(SHA224)\n");
				break;
			case 1:
				printf("HMAC(SHA256)\n");
				break;
			case 2:
				printf("HMAC(SHA384)\n");
				break;
			case 3:
				printf("HMAC(SHA512)\n");
				break;
			}
		} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PRIV ||
			   key_info.key_type == OTP_KEY_TYPE_RSA_PUB) {
			printf("RSA SHA Type: ");
			switch (key_length) {
			case 0:
				printf("RSA1024\n");
				len = 0x100;
				break;
			case 1:
				printf("RSA2048\n");
				len = 0x200;
				break;
			case 2:
				printf("RSA3072\n");
				len = 0x300;
				break;
			case 3:
				printf("RSA4096\n");
				len = 0x400;
				break;
			}
			printf("RSA exponent bit length: %d\n", exp_length);
		}
		if (key_info.need_id)
			printf("Key Number ID: %d\n", key_id);
		printf("Key Value:\n");
		if (key_info.key_type == OTP_KEY_TYPE_HMAC) {
			buf_print(&byte_buf[key_offset], 0x40);
		} else if (key_info.key_type == OTP_KEY_TYPE_AES) {
			printf("AES Key:\n");
			buf_print(&byte_buf[key_offset], 0x20);
			if (info_cb.version == OTP_A0) {
				printf("AES IV:\n");
				buf_print(&byte_buf[key_offset + 0x20], 0x10);
			}

		} else if (key_info.key_type == OTP_KEY_TYPE_VAULT) {
			if (info_cb.version == OTP_A0) {
				printf("AES Key:\n");
				buf_print(&byte_buf[key_offset], 0x20);
				printf("AES IV:\n");
				buf_print(&byte_buf[key_offset + 0x20], 0x10);
			} else {
				printf("AES Key 1:\n");
				buf_print(&byte_buf[key_offset], 0x20);
				printf("AES Key 2:\n");
				buf_print(&byte_buf[key_offset + 0x20], 0x20);
			}
		} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PRIV) {
			printf("RSA mod:\n");
			buf_print(&byte_buf[key_offset], len / 2);
			printf("RSA exp:\n");
			buf_print(&byte_buf[key_offset + (len / 2)], len / 2);
		} else if (key_info.key_type == OTP_KEY_TYPE_RSA_PUB) {
			printf("RSA mod:\n");
			buf_print(&byte_buf[key_offset], len / 2);
			printf("RSA exp:\n");
			buf_print((u8 *)"\x01\x00\x01", 3);
		}
		if (last)
			break;
	}
}

static int otp_print_data_image(struct otp_image_layout *image_layout)
{
	u32 *buf;

	buf = (u32 *)image_layout->data;
	_otp_print_key(buf);

	return OTP_SUCCESS;
}

static void otp_print_key_info(void)
{
	u32 data[2048];

	otp_read_data_buf(0, 2048, data);

	_otp_print_key(data);
}

static int otp_prog_data(struct otp_image_layout *image_layout, u32 *data)
{
	int i;
	int ret;
	uint32_t *buf;
	uint32_t *buf_ignore;

	uint32_t data_masked;
	uint32_t buf_masked;

	buf = (uint32_t *)image_layout->data;
	buf_ignore = (uint32_t *)image_layout->data_ignore;

	printf("Start Programing...\n");

	// programing ecc region first
	for (i = 1792; i < 2046; i++) {
		data_masked = data[i]  & ~buf_ignore[i];
		buf_masked  = buf[i] & ~buf_ignore[i];
		if (data_masked == buf_masked)
			continue;
		ret = otp_prog_data_dw(buf[i], data[i], buf_ignore[i], i);
		if (ret != OTP_SUCCESS) {
			printf("address: %08x, data: %08x, buffer: %08x mask: %08x\n",
			       i, data[i], buf[i], buf_ignore[i]);
			return ret;
		}
	}

	for (i = 0; i < 1792; i++) {
		data_masked = data[i]  & ~buf_ignore[i];
		buf_masked  = buf[i] & ~buf_ignore[i];
		if (data_masked == buf_masked)
			continue;
		ret = otp_prog_data_dw(buf[i], data[i], buf_ignore[i], i);
		if (ret != OTP_SUCCESS) {
			printf("address: %08x, data: %08x, buffer: %08x mask: %08x\n",
			       i, data[i], buf[i], buf_ignore[i]);
			return ret;
		}
	}
	return OTP_SUCCESS;
}

static int otp_prog_strap(struct otp_image_layout *image_layout, struct otpstrap_status *otpstrap)
{
	uint32_t *strap;
	uint32_t *strap_ignore;
	uint32_t *strap_pro;
	uint32_t prog_address;
	int i;
	int bit, pbit, ibit, offset;
	int fail = 0;
	int ret;
	int prog_flag = 0;

	strap = (uint32_t *)image_layout->strap;
	strap_pro = (uint32_t *)image_layout->strap_pro;
	strap_ignore = (uint32_t *)image_layout->strap_ignore;

	for (i = 0; i < 64; i++) {
		if (i < 32) {
			offset = i;
			bit = (strap[0] >> offset) & 0x1;
			ibit = (strap_ignore[0] >> offset) & 0x1;
			pbit = (strap_pro[0] >> offset) & 0x1;
			prog_address = otpstrap[i].writeable_option * 2 + 16;

		} else {
			offset = (i - 32);
			bit = (strap[1] >> offset) & 0x1;
			ibit = (strap_ignore[1] >> offset) & 0x1;
			pbit = (strap_pro[1] >> offset) & 0x1;
			prog_address = otpstrap[i].writeable_option * 2 + 17;
		}

		if (ibit == 1)
			continue;
		if (bit == otpstrap[i].value)
			prog_flag = 0;
		else
			prog_flag = 1;

		if (otpstrap[i].protected == 1 && prog_flag) {
			fail = 1;
			continue;
		}
		if (otpstrap[i].remain_times == 0 && prog_flag) {
			fail = 1;
			continue;
		}
		if (prog_flag) {
			ret = otp_prog_conf_b(prog_address, offset, 1);
			if (ret)
				return OTP_FAILURE;
		}

		if (pbit != 0) {
			if (i < 32)
				prog_address = 30;
			else
				prog_address = 31;

			ret = otp_prog_conf_b(prog_address, offset, 1);
			if (ret)
				return OTP_FAILURE;
		}
	}
	if (fail == 1)
		return OTP_FAILURE;
	else
		return OTP_SUCCESS;
}

static int otp_prog_conf(struct otp_image_layout *image_layout, u32 *otp_conf)
{
	int i, j;
	int pass = 0;
	uint32_t *conf = (uint32_t *)image_layout->conf;
	uint32_t *conf_ignore = (uint32_t *)image_layout->conf_ignore;
	uint32_t data_masked;
	uint32_t buf_masked;

	printf("Start Programing...\n");
	pass = 1;
	for (i = 0; i < 16; i++) {
		data_masked = otp_conf[i]  & ~conf_ignore[i];
		buf_masked  = conf[i] & ~conf_ignore[i];
		if (data_masked == buf_masked)
			continue;
		for (j = 0; j < 32; j++) {
			if ((conf_ignore[i] >> j) & 0x1)
				continue;
			if (!((buf_masked >> j) & 0x1))
				continue;
			if (otp_prog_conf_b(i, j, 1)) {
				pass = 0;
				break;
			}
		}
		if (pass == 0) {
			printf("address: %08x, otp_conf: %08x, input_conf: %08x, mask: %08x\n",
			       i, otp_conf[i], conf[i], conf_ignore[i]);
			break;
		}
	}

	if (!pass)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

static int otp_prog_scu_protect(struct otp_image_layout *image_layout, u32 *otp_scu_pro)
{
	int i, j;
	int pass = 0;
	u32 *scupro = (u32 *)image_layout->scu_pro;
	u32 *scupro_ignore = (u32 *)image_layout->scu_pro_ignore;
	u32 data_masked;
	u32 buf_masked;

	printf("Start Programing...\n");
	pass = 1;
	for (i = 0; i < 2; i++) {
		data_masked = otp_scu_pro[i]  & ~scupro_ignore[i];
		buf_masked  = scupro[i] & ~scupro_ignore[i];
		if (data_masked == buf_masked)
			continue;
		for (j = 0; j < 32; j++) {
			if ((scupro_ignore[i] >> j) & 0x1)
				continue;
			if (!((buf_masked >> j) & 0x1))
				continue;
			if (otp_prog_conf_b(i, j, 1)) {
				pass = 0;
				break;
			}
		}
		if (pass == 0) {
			printf("OTPCFG0x%x: 0x%08x, input: 0x%08x, mask: 0x%08x\n",
			       i + 28, otp_scu_pro[i], scupro[i], scupro_ignore[i]);
			break;
		}
	}

	if (!pass)
		return OTP_FAILURE;

	return OTP_SUCCESS;
}

static int otp_check_data_image(struct otp_image_layout *image_layout, u32 *data)
{
	int data_dw;
	u32 data_masked;
	u32 buf_masked;
	u32 *buf = (u32 *)image_layout->data;
	u32 *buf_ignore = (u32 *)image_layout->data_ignore;
	int i;

	data_dw = image_layout->data_length / 4;
	// ignore last two dw, the last two dw is used for slt otp write check.
	for (i = 0; i < data_dw - 2; i++) {
		data_masked = data[i]  & ~buf_ignore[i];
		buf_masked  = buf[i] & ~buf_ignore[i];
		if (data_masked == buf_masked)
			continue;
		if (i % 2 == 0) {
			if ((data_masked | buf_masked) == buf_masked) {
				continue;
			} else {
				printf("Input image can't program into OTP, please check.\n");
				printf("OTP_ADDR[0x%x] = 0x%x\n", i, data[i]);
				printf("Input   [0x%x] = 0x%x\n", i, buf[i]);
				printf("Mask    [0x%x] = 0x%x\n", i, ~buf_ignore[i]);
				return OTP_FAILURE;
			}
		} else {
			if ((data_masked & buf_masked) == buf_masked) {
				continue;
			} else {
				printf("Input image can't program into OTP, please check.\n");
				printf("OTP_ADDR[0x%x] = 0x%x\n", i, data[i]);
				printf("Input   [0x%x] = 0x%x\n", i, buf[i]);
				printf("Mask    [0x%x] = 0x%x\n", i, ~buf_ignore[i]);
				return OTP_FAILURE;
			}
		}
	}
	return OTP_SUCCESS;
}

static int otp_check_strap_image(struct otp_image_layout *image_layout, struct otpstrap_status *otpstrap)
{
	int i;
	u32 *strap;
	u32 *strap_ignore;
	u32 *strap_pro;
	int bit, pbit, ibit;
	int fail = 0;
	int ret;

	strap = (u32 *)image_layout->strap;
	strap_pro = (u32 *)image_layout->strap_pro;
	strap_ignore = (u32 *)image_layout->strap_ignore;

	for (i = 0; i < 64; i++) {
		if (i < 32) {
			bit = (strap[0] >> i) & 0x1;
			ibit = (strap_ignore[0] >> i) & 0x1;
			pbit = (strap_pro[0] >> i) & 0x1;
		} else {
			bit = (strap[1] >> (i - 32)) & 0x1;
			ibit = (strap_ignore[1] >> (i - 32)) & 0x1;
			pbit = (strap_pro[1] >> (i - 32)) & 0x1;
		}

		ret = otp_strap_bit_confirm(&otpstrap[i], i, ibit, bit, pbit);

		if (ret == OTP_FAILURE)
			fail = 1;
	}
	if (fail == 1) {
		printf("Input image can't program into OTP, please check.\n");
		return OTP_FAILURE;
	}
	return OTP_SUCCESS;
}

static int otp_check_conf_image(struct otp_image_layout *image_layout, u32 *otp_conf)
{
	u32 *conf = (u32 *)image_layout->conf;
	u32 *conf_ignore = (u32 *)image_layout->conf_ignore;
	u32 data_masked;
	u32 buf_masked;
	int i;

	for (i = 0; i < 16; i++) {
		data_masked = otp_conf[i]  & ~conf_ignore[i];
		buf_masked  = conf[i] & ~conf_ignore[i];
		if (data_masked == buf_masked)
			continue;
		if ((data_masked | buf_masked) == buf_masked) {
			continue;
		} else {
			printf("Input image can't program into OTP, please check.\n");
			printf("OTPCFG[0x%X] = 0x%x\n", i, otp_conf[i]);
			printf("Input [0x%X] = 0x%x\n", i, conf[i]);
			printf("Mask  [0x%X] = 0x%x\n", i, ~conf_ignore[i]);
			return OTP_FAILURE;
		}
	}
	return OTP_SUCCESS;
}

static int otp_check_scu_image(struct otp_image_layout *image_layout, u32 *otp_scu_pro)
{
	u32 *scupro = (u32 *)image_layout->scu_pro;
	u32 *scupro_ignore = (u32 *)image_layout->scu_pro_ignore;
	u32 data_masked;
	u32 buf_masked;
	int i;

	for (i = 0; i < 2; i++) {
		data_masked = otp_scu_pro[i]  & ~scupro_ignore[i];
		buf_masked  = scupro[i] & ~scupro_ignore[i];
		if (data_masked == buf_masked)
			continue;
		if ((data_masked | buf_masked) == buf_masked) {
			continue;
		} else {
			printf("Input image can't program into OTP, please check.\n");
			printf("OTPCFG[0x%X] = 0x%x\n", 28 + i, otp_scu_pro[i]);
			printf("Input [0x%X] = 0x%x\n", 28 + i, scupro[i]);
			printf("Mask  [0x%X] = 0x%x\n", 28 + i, ~scupro_ignore[i]);
			return OTP_FAILURE;
		}
	}
	return OTP_SUCCESS;
}

static int otp_verify_image(uint8_t *src_buf, uint32_t length, uint8_t *digest_buf)
{
	SHA256_CTX ctx;
	u8 digest_ret[CHECKSUM_LEN];

	sha256_init(&ctx);
	sha256_update(&ctx, src_buf, length);
	sha256_final(&ctx, digest_ret);

	if (!memcmp(digest_buf, digest_ret, CHECKSUM_LEN))
		return OTP_SUCCESS;
	else
		return OTP_FAILURE;
}

static int otp_prog_image(uint8_t *buf, int nconfirm)
{
	int ret;
	int image_soc_ver = 0;
	struct otp_header *otp_header;
	struct otp_image_layout image_layout;
	int image_size;
	uint8_t *checksum;
	int i;
	u32 data[2048];
	u32 conf[16];
	u32 scu_pro[2];
	struct otpstrap_status otpstrap[64];

	otp_header = (struct otp_header *)buf;

	image_size = OTP_IMAGE_SIZE(otp_header->image_info);

	checksum = buf + otp_header->checksum_offset;

	if (strcmp(OTP_MAGIC, (char *)otp_header->otp_magic) != 0) {
		printf("Image is invalid\n");
		return OTP_FAILURE;
	}

	image_layout.data_length = (int)(OTP_REGION_SIZE(otp_header->data_info) / 2);
	image_layout.data = buf + OTP_REGION_OFFSET(otp_header->data_info);
	image_layout.data_ignore = image_layout.data + image_layout.data_length;

	image_layout.conf_length = (int)(OTP_REGION_SIZE(otp_header->conf_info) / 2);
	image_layout.conf = buf + OTP_REGION_OFFSET(otp_header->conf_info);
	image_layout.conf_ignore = image_layout.conf + image_layout.conf_length;

	image_layout.strap = buf + OTP_REGION_OFFSET(otp_header->strap_info);

	image_layout.strap_length = (int)(OTP_REGION_SIZE(otp_header->strap_info) / 3);
	image_layout.strap_pro = image_layout.strap + image_layout.strap_length;
	image_layout.strap_ignore = image_layout.strap + 2 * image_layout.strap_length;

	image_layout.scu_pro = buf + OTP_REGION_OFFSET(otp_header->scu_protect_info);
	image_layout.scu_pro_length = (int)(OTP_REGION_SIZE(otp_header->scu_protect_info) / 2);
	image_layout.scu_pro_ignore = image_layout.scu_pro + image_layout.scu_pro_length;

	if (otp_header->soc_ver == SOC_AST2600A0) {
		image_soc_ver = OTP_A0;
	} else if (otp_header->soc_ver == SOC_AST2600A1) {
		image_soc_ver = OTP_A1;
	} else if (otp_header->soc_ver == SOC_AST2600A2) {
		image_soc_ver = OTP_A2;
	} else if (otp_header->soc_ver == SOC_AST2600A3) {
		image_soc_ver = OTP_A3;
	} else {
		puts("Image SOC Version is not supported\n");
		return OTP_FAILURE;
	}

	if (image_soc_ver != info_cb.version) {
		puts("Version is not match\n");
		return OTP_FAILURE;
	}

	if (otp_header->otptool_ver != OTPTOOL_VERSION(1, 0, 0)) {
		puts("OTP image is not generated by otptool v1.0.0\n");
		return OTP_FAILURE;
	}

	if (otp_verify_image(buf, image_size, checksum)) {
		puts("checksum is invalid\n");
		return OTP_FAILURE;
	}

	if (info_cb.pro_sts.mem_lock) {
		printf("OTP memory is locked\n");
		return OTP_FAILURE;
	}

	ret = 0;
	if (otp_header->image_info & OTP_INC_DATA) {
		if (info_cb.pro_sts.pro_data) {
			printf("OTP data region is protected\n");
			ret = -1;
		}
		if (info_cb.pro_sts.pro_sec) {
			printf("OTP secure region is protected\n");
			ret = -1;
		}
		printf("Read OTP Data Region:\n");

		otp_read_data_buf(0, 2048, data);

		printf("Check writable...\n");
		if (otp_check_data_image(&image_layout, data) == OTP_FAILURE)
			ret = -1;
	}
	if (otp_header->image_info & OTP_INC_CONF) {
		if (info_cb.pro_sts.pro_conf) {
			printf("OTP config region is protected\n");
			ret = -1;
		}
		printf("Read OTP Config Region:\n");
		for (i = 0; i < 16 ; i++)
			otp_read_conf(i, &conf[i]);

		printf("Check writable...\n");
		if (otp_check_conf_image(&image_layout, conf) == OTP_FAILURE)
			ret = -1;
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		if (info_cb.pro_sts.pro_strap) {
			printf("OTP strap region is protected\n");
			ret = -1;
		}
		printf("Read OTP Strap Region:\n");
		otp_read_strap(otpstrap);

		printf("Check writable...\n");
		if (otp_check_strap_image(&image_layout, otpstrap) == OTP_FAILURE)
			ret = -1;
	}
	if (otp_header->image_info & OTP_INC_SCU_PRO) {
		if (info_cb.pro_sts.pro_strap) {
			printf("OTP strap region is protected\n");
			ret = -1;
		}
		printf("Read SCU Protect Region:\n");
		otp_read_conf(28, &scu_pro[0]);
		otp_read_conf(29, &scu_pro[1]);

		printf("Check writable...\n");
		if (otp_check_scu_image(&image_layout, scu_pro) == OTP_FAILURE)
			ret = -1;
	}
	if (ret == -1)
		return OTP_FAILURE;

	if (!nconfirm) {
		if (otp_header->image_info & OTP_INC_DATA) {
			printf("\nOTP data region :\n");
			if (otp_print_data_image(&image_layout) < 0) {
				printf("OTP data error, please check.\n");
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
		if (otp_header->image_info & OTP_INC_CONF) {
			printf("\nOTP configuration region :\n");
			if (otp_print_conf_image(&image_layout) < 0) {
				printf("OTP config error, please check.\n");
				return OTP_FAILURE;
			}
		}

		if (otp_header->image_info & OTP_INC_SCU_PRO) {
			printf("\nOTP scu protect region :\n");
			if (otp_print_scu_image(&image_layout) < 0) {
				printf("OTP scu protect error, please check.\n");
				return OTP_FAILURE;
			}
		}

		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	if (otp_header->image_info & OTP_INC_DATA) {
		printf("programing data region ...\n");
		ret = otp_prog_data(&image_layout, data);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_STRAP) {
		printf("programing strap region ...\n");
		ret = otp_prog_strap(&image_layout, otpstrap);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_SCU_PRO) {
		printf("programing scu protect region ...\n");
		ret = otp_prog_scu_protect(&image_layout, scu_pro);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		printf("Done\n");
	}
	if (otp_header->image_info & OTP_INC_CONF) {
		printf("programing configuration region ...\n");
		ret = otp_prog_conf(&image_layout, conf);
		if (ret != 0) {
			printf("Error\n");
			return ret;
		}
		printf("Done\n");
	}

	return OTP_SUCCESS;
}

static int otp_prog_bit(int mode, int otp_dw_offset, int bit_offset, int value, int nconfirm)
{
	uint32_t read;
	struct otpstrap_status otpstrap[64];
	int otp_bit;
	int ret = 0;

	switch (mode) {
	case OTP_REGION_CONF:
		otp_read_conf(otp_dw_offset, &read);
		otp_bit = (read >> bit_offset) & 0x1;
		if (otp_bit == value) {
			printf("OTPCFG0x%X[0x%X] = %d\n", otp_dw_offset, bit_offset, value);
			printf("No need to program\n");
			return OTP_SUCCESS;
		}
		if (otp_bit == 1 && value == 0) {
			printf("OTPCFG0x%X[0x%X] = 1\n", otp_dw_offset, bit_offset);
			printf("OTP is programed, which can't be clean\n");
			return OTP_FAILURE;
		}
		printf("Program OTPCFG0x%X[0x%X] to 1\n", otp_dw_offset, bit_offset);
		break;
	case OTP_REGION_DATA:
		otp_read_data(otp_dw_offset, &read);
		otp_bit = (read >> bit_offset) & 0x1;
		if (otp_dw_offset % 2 == 0) {
			if (otp_bit == 1 && value == 0) {
				printf("OTPDATA0x%X[0x%X] = 1\n", otp_dw_offset, bit_offset);
				printf("OTP is programed, which can't be cleared\n");
				return OTP_FAILURE;
			}
		} else {
			if (otp_bit == 0 && value == 1) {
				printf("OTPDATA0x%X[0x%X] = 1\n", otp_dw_offset, bit_offset);
				printf("OTP is programed, which can't be written\n");
				return OTP_FAILURE;
			}
		}
		if (otp_bit == value) {
			printf("OTPDATA0x%X[0x%X] = %d\n", otp_dw_offset, bit_offset, value);
			printf("No need to program\n");
			return OTP_SUCCESS;
		}

		printf("Program OTPDATA0x%X[0x%X] to 1\n", otp_dw_offset, bit_offset);
		break;
	case OTP_REGION_STRAP:
		otp_read_strap(otpstrap);
		otp_print_strap(bit_offset, 1);
		ret = otp_strap_bit_confirm(&otpstrap[bit_offset], bit_offset, 0, value, 0);
		if (ret == OTP_FAILURE)
			return OTP_FAILURE;
		else if (ret == OTP_PROG_SKIP)
			return OTP_SUCCESS;
		break;
	}

	if (!nconfirm) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	switch (mode) {
	case OTP_REGION_STRAP:
		ret = otp_prog_strap_b(bit_offset, value);
		break;
	case OTP_REGION_CONF:
		ret = otp_prog_conf_b(otp_dw_offset, bit_offset, value);
		break;
	case OTP_REGION_DATA:
		ret = otp_prog_data_b(otp_dw_offset, bit_offset, value);
		break;
	}
	if (ret == OTP_SUCCESS) {
		printf("SUCCESS\n");
		return OTP_SUCCESS;
	}
	printf("OTP cannot be programed\n");
	printf("FAILED\n");
	return OTP_FAILURE;
}

static int otp_update_rid(uint32_t update_num, int force)
{
	uint32_t otp_rid[2];
	u32 sw_rid[2];
	int rid_num = 0;
	int sw_rid_num = 0;
	int bit_offset;
	int dw_offset;
	int i;
	int ret;

	if (otp_read_conf_buf(0xa, 2, otp_rid))
		return OTP_FAILURE;

	if (sw_revid(sw_rid))
		return OTP_FAILURE;

	rid_num = get_rid_num(otp_rid);
	sw_rid_num = get_rid_num(sw_rid);

	if (sw_rid_num < 0) {
		printf("SW revision id is invalid, please check.\n");
		return OTP_FAILURE;
	}

	if (update_num > sw_rid_num) {
		printf("current SW revision ID: 0x%x\n", sw_rid_num);
		printf("update number could not bigger than current SW revision id\n");
		return OTP_FAILURE;
	}

	if (rid_num < 0) {
		printf("Current OTP revision ID cannot handle by this command,\n"
		       "please use 'otp pb' command to update it manually\n");
		otp_print_revid(otp_rid);
		return OTP_FAILURE;
	}

	printf("current OTP revision ID: 0x%x\n", rid_num);
	otp_print_revid(otp_rid);
	printf("input update number: 0x%X\n", update_num);

	if (rid_num > update_num) {
		printf("OTP rev_id is bigger than 0x%X\n", update_num);
		printf("Skip\n");
		return OTP_FAILURE;
	} else if (rid_num == update_num) {
		printf("OTP rev_id is same as input\n");
		printf("Skip\n");
		return OTP_FAILURE;
	}

	for (i = rid_num; i < update_num; i++) {
		if (i < 32) {
			dw_offset = 0xa;
			bit_offset = i;
		} else {
			dw_offset = 0xb;
			bit_offset = i - 32;
		}
		printf("OTPCFG0x%X[0x%X]", dw_offset, bit_offset);
		if (i + 1 != update_num)
			printf(", ");
	}

	printf(" will be programmed\n");
	if (force == 0) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	ret = 0;
	for (i = rid_num; i < update_num; i++) {
		if (i < 32) {
			dw_offset = 0xa;
			bit_offset = i;
		} else {
			dw_offset = 0xb;
			bit_offset = i - 32;
		}
		if (otp_prog_conf_b(dw_offset, bit_offset, 1)) {
			printf("OTPCFG0x%X[0x%X] programming failed\n", dw_offset, bit_offset);
			ret = OTP_FAILURE;
			break;
		}
	}

	otp_read_conf_buf(0xa, 2, otp_rid);
	rid_num = get_rid_num(otp_rid);
	if (rid_num >= 0)
		printf("OTP revision ID: 0x%x\n", rid_num);
	else
		printf("OTP revision ID\n");
	otp_print_revid(otp_rid);
	if (!ret)
		printf("SUCCESS\n");
	else
		printf("FAILED\n");
	return ret;
}

static int otp_retire_key(u32 retire_id, int force)
{
	u32 otpcfg4;
	u32 krb;
	u32 krb_b;
	u32 krb_or;
	u32 current_id;

	otp_read_conf(4, &otpcfg4);
	sec_key_num(&current_id);
	krb = otpcfg4 & 0xff;
	krb_b = (otpcfg4 >> 16) & 0xff;
	krb_or = krb | krb_b;

	printf("current Key ID: 0x%x\n", current_id);
	printf("input retire ID: 0x%x\n", retire_id);
	printf("OTPCFG0x4 = 0x%X\n", otpcfg4);

	if (info_cb.pro_sts.pro_key_ret) {
		printf("OTPCFG0x4 is protected\n");
		return OTP_FAILURE;
	}

	if (retire_id >= current_id) {
		printf("Retire key id is equal or bigger than current boot key\n");
		return OTP_FAILURE;
	}

	if (krb_or & (1 << retire_id)) {
		printf("Key 0x%X already retired\n", retire_id);
		return OTP_SUCCESS;
	}

	printf("OTPCFG0x4[0x%X] will be programmed\n", retire_id);
	if (force == 0) {
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	if (otp_prog_conf_b(4, retire_id, 1) == OTP_FAILURE) {
		printf("OTPCFG0x4[0x%X] programming failed\n", retire_id);
		printf("try to program backup OTPCFG0x4[0x%X]\n", retire_id + 16);
		if (otp_prog_conf_b(4, retire_id + 16, 1) == OTP_FAILURE)
			printf("OTPCFG0x4[0x%X] programming failed", retire_id + 16);
	}

	otp_read_conf(4, &otpcfg4);
	krb = otpcfg4 & 0xff;
	krb_b = (otpcfg4 >> 16) & 0xff;
	krb_or = krb | krb_b;
	if (krb_or & (1 << retire_id)) {
		printf("SUCCESS\n");
		return OTP_SUCCESS;
	}
	printf("FAILED\n");
	return OTP_FAILURE;
}

static int do_otpread(int argc, char *const argv[])
{
	uint32_t offset, count;
	int ret;

	if (argc == 4) {
		offset = strtoul(argv[2], NULL, 16);
		count = strtoul(argv[3], NULL, 16);
	} else if (argc == 3) {
		offset = strtoul(argv[2], NULL, 16);
		count = 1;
	} else {
		return OTP_USAGE;
	}

	if (!strcmp(argv[1], "conf")) {
		if (offset + count > 32)
			return OTP_USAGE;
		ret = otp_print_conf(offset, count);
	} else if (!strcmp(argv[1], "data")) {
		if (offset + count > 2048)
			return OTP_USAGE;
		ret = otp_print_data(offset, count);
	} else if (!strcmp(argv[1], "strap")) {
		if (offset + count > 64)
			return OTP_USAGE;
		ret = otp_print_strap(offset, count);
	} else {
		return OTP_USAGE;
	}

	return ret;
}

static int do_otpprog(int argc, char *const argv[])
{
	FILE *fd;
	int ret;
	int force = 0;
	char *path;
	uint8_t *buf;
	long fsize;

	if (argc == 3) {
		if (strcmp(argv[1], "o"))
			return OTP_USAGE;
		path = argv[2];
		force = 1;
	} else if (argc == 2) {
		path = argv[1];
		force = 0;
	} else {
		return OTP_USAGE;
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

	return otp_prog_image(buf, force);
}

static int do_otppb(int argc, char *const argv[])
{
	int mode = 0;
	int nconfirm = 0;
	int otp_addr = 0;
	int bit_offset;
	int value;
	int ret;
	u32 otp_strap_pro;

	if (argc != 4 && argc != 5 && argc != 6)
		return OTP_USAGE;

	/* Drop the pb cmd */
	argc--;
	argv++;

	if (!strcmp(argv[0], "conf"))
		mode = OTP_REGION_CONF;
	else if (!strcmp(argv[0], "strap"))
		mode = OTP_REGION_STRAP;
	else if (!strcmp(argv[0], "data"))
		mode = OTP_REGION_DATA;
	else
		return OTP_USAGE;

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
		if (argc != 2)
			return OTP_USAGE;
		bit_offset = strtoul(argv[0], NULL, 16);
		value = strtoul(argv[1], NULL, 16);
		if (bit_offset >= 64 || (value != 0 && value != 1))
			return OTP_USAGE;
	} else {
		if (argc != 3)
			return OTP_USAGE;
		otp_addr = strtoul(argv[0], NULL, 16);
		bit_offset = strtoul(argv[1], NULL, 16);
		value = strtoul(argv[2], NULL, 16);
		if (bit_offset >= 32 || (value != 0 && value != 1))
			return OTP_USAGE;
		if (mode == OTP_REGION_DATA) {
			if (otp_addr >= 0x800)
				return OTP_USAGE;
		} else {
			if (otp_addr >= 0x20)
				return OTP_USAGE;
		}
	}
	if (value != 0 && value != 1)
		return OTP_USAGE;

	ret = 0;
	if (info_cb.pro_sts.mem_lock) {
		printf("OTP memory is locked\n");
		return OTP_USAGE;
	}
	if (mode == OTP_REGION_DATA) {
		if (info_cb.pro_sts.sec_size == 0) {
			if (info_cb.pro_sts.pro_data) {
				printf("OTP data region is protected\n");
				ret = -1;
			}
		} else if (otp_addr < info_cb.pro_sts.sec_size && otp_addr >= 16) {
			printf("OTP secure region is not readable, skip it to prevent unpredictable result\n");
			ret = -1;
		} else if (otp_addr < info_cb.pro_sts.sec_size) {
			// header region(0x0~0x40) is still readable even secure region is set.
			if (info_cb.pro_sts.pro_sec) {
				printf("OTP secure region is protected\n");
				ret = -1;
			}
		} else if (info_cb.pro_sts.pro_data) {
			printf("OTP data region is protected\n");
			ret = -1;
		}
	} else if (mode == OTP_REGION_CONF) {
		if (otp_addr != 4 && otp_addr != 10 && otp_addr != 11 && otp_addr < 16) {
			if (info_cb.pro_sts.pro_conf) {
				printf("OTP config region is protected\n");
				ret = -1;
			}
		} else if (otp_addr == 10 || otp_addr == 11) {
			u32 otp_rid[2];
			u32 sw_rid[2];
			u64 *otp_rid64 = (u64 *)otp_rid;
			u64 *sw_rid64 = (u64 *)sw_rid;

			otp_read_conf(10, &otp_rid[0]);
			otp_read_conf(11, &otp_rid[1]);
			if (sw_revid(sw_rid))
				return OTP_FAILURE;

			if (otp_addr == 10)
				otp_rid[0] |= 1 << bit_offset;
			else
				otp_rid[1] |= 1 << bit_offset;

			if (*otp_rid64 > *sw_rid64) {
				printf("update number could not bigger than current SW revision id\n");
				ret = -1;
			}
		} else if (otp_addr == 4) {
			if (info_cb.pro_sts.pro_key_ret) {
				printf("OTPCFG4 is protected\n");
				ret = -1;
			} else {
				if ((bit_offset >= 0 && bit_offset <= 7) ||
				    (bit_offset >= 16 && bit_offset <= 23)) {
					u32 key_num;
					u32 retire;

					sec_key_num(&key_num);
					if (bit_offset >= 16)
						retire = bit_offset - 16;
					else
						retire = bit_offset;
					if (retire >= key_num) {
						printf("Retire key id is equal or bigger than current boot key\n");
						ret = -1;
					}
				}
			}
		} else if (otp_addr >= 16 && otp_addr <= 31) {
			if (info_cb.pro_sts.pro_strap) {
				printf("OTP strap region is protected\n");
				ret = -1;
			} else if ((otp_addr < 30 && info_cb.version == OTP_A0) ||
				   (otp_addr < 28 && info_cb.version != OTP_A0)) {
				if (otp_addr % 2 == 0)
					otp_read_conf(30, &otp_strap_pro);
				else
					otp_read_conf(31, &otp_strap_pro);
				if (otp_strap_pro >> bit_offset & 0x1) {
					printf("OTPCFG0x%X[0x%X] is protected\n", otp_addr, bit_offset);
					ret = -1;
				}
			}
		}
	} else if (mode == OTP_REGION_STRAP) {
		// per bit protection will check in otp_strap_bit_confirm
		if (info_cb.pro_sts.pro_strap) {
			printf("OTP strap region is protected\n");
			ret = -1;
		}
	}

	if (ret == -1)
		return OTP_FAILURE;

	return otp_prog_bit(mode, otp_addr, bit_offset, value, nconfirm);
}

static int do_otpinfo(int argc, char *const argv[])
{
	int view = 0;
	int input;

	if (argc != 2 && argc != 3)
		return OTP_USAGE;

	if (!strcmp(argv[1], "conf")) {
		if (argc == 3) {
			input = strtoul(argv[2], NULL, 16);
			otp_print_conf_info(input);
		} else {
			otp_print_conf_info(-1);
		}
	} else if (!strcmp(argv[1], "strap")) {
		if (argc == 3) {
			if (!strcmp(argv[2], "v")) {
				view = 1;
				/* Drop the view option */
				argc--;
				argv++;
			} else {
				return OTP_USAGE;
			}
		}
		otp_print_strap_info(view);
	} else if (!strcmp(argv[1], "scu")) {
		otp_print_scu_info();
	}  else if (!strcmp(argv[1], "key")) {
		otp_print_key_info();
	} else {
		return OTP_USAGE;
	}

	return OTP_SUCCESS;
}

static int do_otpprotect(int argc, char *const argv[])
{
	int input;
	int bit_offset;
	int prog_address;
	int ret;
	char force = 0;
	uint32_t read;

	if (argc == 3) {
		if (strcmp(argv[1], "o"))
			return OTP_USAGE;
		input = strtoul(argv[2], NULL, 16);
		force = 0;
	} else if (argc == 2) {
		input = strtoul(argv[1], NULL, 16);
		force = 1;
	} else {
		return OTP_USAGE;
	}

	if (input < 32) {
		bit_offset = input;
		prog_address = 0xe0c;
	} else if (input < 64) {
		bit_offset = input - 32;
		prog_address = 0xe0e;
	} else {
		return OTP_USAGE;
	}

	if (info_cb.pro_sts.pro_strap) {
		printf("OTP strap region is protected\n");
		return OTP_FAILURE;
	}

	if (!force) {
		printf("OTPSTRAP[0x%X] will be protected\n", input);
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	otp_read_conf(prog_address, &read);
	if (((read >> bit_offset) & 1) == 1) {
		printf("OTPSTRAP[0x%X] already protected\n", input);
		return OTP_SUCCESS;
	}

	ret = otp_prog_conf_b(prog_address, bit_offset, 1);

	if (ret == OTP_SUCCESS)
		printf("OTPSTRAP[0x%X] is protected\n", input);
	else
		printf("Protect OTPSTRAP[0x%X] fail\n", input);

	return ret;
}

static int do_otp_scuprotect(int argc, char *const argv[])
{
	u32 scu_offset;
	u32 bit_offset;
	u32 conf_offset;
	u32 prog_address;
	char force;
	int ret;
	uint32_t read;

	if (argc != 4 && argc != 3)
		return OTP_USAGE;

	if (!strcmp(argv[1], "o")) {
		scu_offset = strtoul(argv[2], NULL, 16);
		bit_offset = strtoul(argv[3], NULL, 16);
		force = 1;
	} else {
		scu_offset = strtoul(argv[1], NULL, 16);
		bit_offset = strtoul(argv[2], NULL, 16);
		force = 0;
	}
	if (scu_offset == 0x500) {
		prog_address = 0xe08;
		conf_offset = 28;
	} else if (scu_offset == 0x510) {
		prog_address = 0xe0a;
		conf_offset = 29;
	} else {
		return OTP_USAGE;
	}
	if (bit_offset < 0 || bit_offset > 31)
		return OTP_USAGE;

	if (info_cb.pro_sts.pro_strap) {
		printf("OTP strap region is protected\n");
		return OTP_USAGE;
	}

	if (!force) {
		printf("OTPCONF0x%X[0x%X] will be programmed\n", conf_offset, bit_offset);
		printf("SCU0x%X[0x%X] will be protected\n", scu_offset, bit_offset);
		printf("type \"YES\" (no quotes) to continue:\n");
		if (!confirm_yesno()) {
			printf(" Aborting\n");
			return OTP_FAILURE;
		}
	}

	otp_read_conf(prog_address, &read);
	if (((read >> bit_offset) & 1) == 1) {
		printf("OTPCONF0x%X[0x%X] already programmed\n", conf_offset, bit_offset);
		return OTP_SUCCESS;
	}

	ret = otp_prog_conf_b(prog_address, bit_offset, 1);

	if (ret) {
		printf("Program OTPCONF0x%X[0x%X] fail\n", conf_offset, bit_offset);
		return OTP_FAILURE;
	}

	printf("OTPCONF0x%X[0x%X] programmed success\n", conf_offset, bit_offset);
	return OTP_SUCCESS;
}

static int do_otpver(char *ver_name)
{
	printf("SOC OTP version: %s\n", ver_name);
	printf("OTP tool version: %s\n", OTP_VER);
	printf("OTP info version: %s\n", OTP_INFO_VER);

	return OTP_SUCCESS;
}

static int do_otpupdate(int argc, char *const argv[])
{
	uint32_t update_num;
	int force = 0;

	if (argc == 3) {
		if (strcmp(argv[1], "o"))
			return OTP_USAGE;
		force = 1;
		update_num = strtoul(argv[2], NULL, 16);
	} else if (argc == 2) {
		update_num = strtoul(argv[1], NULL, 16);
	} else {
		return OTP_USAGE;
	}

	if (update_num > 64)
		return OTP_USAGE;

	return otp_update_rid(update_num, force);
}

static int do_otprid(int argc, char *const argv[])
{
	uint32_t otp_rid[2];
	u32 sw_rid[2];
	int rid_num = 0;
	int sw_rid_num = 0;
	int ret;

	if (argc != 1)
		return OTP_USAGE;

	if (otp_read_conf_buf(0xa, 2, otp_rid))
		return OTP_FAILURE;

	if (sw_revid(sw_rid))
		return OTP_FAILURE;

	rid_num = get_rid_num(otp_rid);
	sw_rid_num = get_rid_num(sw_rid);

	if (sw_rid_num < 0) {
		printf("SW revision id is invalid, please check.\n");
		printf("SEC68:0x%x\n", sw_rid[0]);
		printf("SEC6C:0x%x\n", sw_rid[1]);
	} else {
		printf("current SW revision ID: 0x%x\n", sw_rid_num);
	}
	if (rid_num >= 0) {
		printf("current OTP revision ID: 0x%x\n", rid_num);
		ret = OTP_SUCCESS;
	} else {
		printf("Current OTP revision ID cannot handle by 'otp update',\n"
		       "please use 'otp pb' command to update it manually\n"
		       "current OTP revision ID\n");
		ret = OTP_FAILURE;
	}
	otp_print_revid(otp_rid);

	return ret;
}

static int do_otpretire(int argc, char *const argv[])
{
	u32 retire_id;
	int force = 0;
	int ret;

	if (argc == 3) {
		if (strcmp(argv[1], "o"))
			return OTP_USAGE;
		force = 1;
		retire_id = strtoul(argv[2], NULL, 16);
	} else if (argc == 2) {
		retire_id = strtoul(argv[1], NULL, 16);
	} else {
		return OTP_USAGE;
	}

	if (retire_id > 7)
		return OTP_USAGE;
	ret = otp_retire_key(retire_id, force);

	if (ret)
		return OTP_USAGE;
	return OTP_SUCCESS;
}

static void usage(void)
{
	printf("otp version\n"
	       "otp read conf|data <otp_dw_offset> <dw_count>\n"
	       "otp read strap <strap_bit_offset> <bit_count>\n"
	       "otp info strap [v]\n"
	       "otp info conf [otp_dw_offset]\n"
	       "otp info scu\n"
	       "otp prog [o] <image_path>\n"
	       "otp pb conf|data [o] <otp_dw_offset> <bit_offset> <value>\n"
	       "otp pb strap [o] <bit_offset> <value>\n"
	       "otp protect [o] <bit_offset>\n"
	       "otp scuprotect [o] <bit_offset>\n"
	       "otp update [o] <revision_id>\n"
	       "otp rid\n"
	       "otp retire [o] <key_id>\n");
}

int main(int argc, char *argv[])
{
	char *sub_cmd;
	uint32_t ver;
	int ret;
	char ver_name[15];
	u32 otp_conf0;
	struct otp_pro_sts *pro_sts;

	if (argc < 2 || argc > 7) {
		usage();
		exit(EXIT_FAILURE);
	}

	info_cb.otp_fd = open("/dev/aspeed-otp", O_RDWR);
	if (info_cb.otp_fd == -1) {
		printf("Can't open /dev/aspeed-otp, please install driver!!\n");
		exit(EXIT_FAILURE);
	}

	sub_cmd = argv[1];

	/* Drop the otp command */
	argc--;
	argv++;

	ver = chip_version();
	ret = 0;
	switch (ver) {
	case OTP_A0:
		info_cb.version = OTP_A0;
		info_cb.conf_info = a0_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a0_conf_info);
		info_cb.strap_info = a0_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a0_strap_info);
		info_cb.key_info = a0_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a0_key_type);
		sprintf(ver_name, "A0");
		break;
	case OTP_A1:
		info_cb.version = OTP_A1;
		info_cb.conf_info = a1_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a1_conf_info);
		info_cb.strap_info = a1_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a1_strap_info);
		info_cb.key_info = a1_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a1_key_type);
		info_cb.scu_info = a1_scu_info;
		info_cb.scu_info_len = ARRAY_SIZE(a1_scu_info);
		sprintf(ver_name, "A1");
		break;
	case OTP_A2:
		info_cb.version = OTP_A2;
		info_cb.conf_info = a2_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a2_conf_info);
		info_cb.strap_info = a1_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a1_strap_info);
		info_cb.key_info = a2_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a2_key_type);
		info_cb.scu_info = a1_scu_info;
		info_cb.scu_info_len = ARRAY_SIZE(a1_scu_info);
		sprintf(ver_name, "A2");
		break;
	case OTP_A3:
		info_cb.version = OTP_A3;
		info_cb.conf_info = a3_conf_info;
		info_cb.conf_info_len = ARRAY_SIZE(a3_conf_info);
		info_cb.strap_info = a1_strap_info;
		info_cb.strap_info_len = ARRAY_SIZE(a1_strap_info);
		info_cb.key_info = a3_key_type;
		info_cb.key_info_len = ARRAY_SIZE(a3_key_type);
		info_cb.scu_info = a1_scu_info;
		info_cb.scu_info_len = ARRAY_SIZE(a1_scu_info);
		sprintf(ver_name, "A3");
		break;
	default:
		sprintf(ver_name, "unrecognized");
		ret = EXIT_FAILURE;
	}

	if (!strcmp(sub_cmd, "version")) {
		do_otpver(ver_name);
		return EXIT_SUCCESS;
	}

	if (ret) {
		printf("SOC is not supported\n");
		return ret;
	}

	otp_read_conf(0, &otp_conf0);
	pro_sts = &info_cb.pro_sts;

	pro_sts->mem_lock = (otp_conf0 >> 31) & 0x1;
	pro_sts->pro_key_ret = (otp_conf0 >> 29) & 0x1;
	pro_sts->pro_strap = (otp_conf0 >> 25) & 0x1;
	pro_sts->pro_conf = (otp_conf0 >> 24) & 0x1;
	pro_sts->pro_data = (otp_conf0 >> 23) & 0x1;
	pro_sts->pro_sec = (otp_conf0 >> 22) & 0x1;
	pro_sts->sec_size = ((otp_conf0 >> 16) & 0x3f) << 5;

	if (!strcmp(sub_cmd, "read"))
		ret = do_otpread(argc, argv);
	else if (!strcmp(sub_cmd, "info"))
		ret = do_otpinfo(argc, argv);
	else if (!strcmp(sub_cmd, "pb"))
		ret = do_otppb(argc, argv);
	else if (!strcmp(sub_cmd, "protect"))
		ret = do_otpprotect(argc, argv);
	else if (!strcmp(sub_cmd, "scuprotect"))
		ret = do_otp_scuprotect(argc, argv);
	else if (!strcmp(sub_cmd, "prog"))
		ret = do_otpprog(argc, argv);
	else if (!strcmp(sub_cmd, "update"))
		ret = do_otpupdate(argc, argv);
	else if (!strcmp(sub_cmd, "rid"))
		ret = do_otprid(argc, argv);
	else if (!strcmp(sub_cmd, "retire"))
		ret = do_otpretire(argc, argv);
	else
		ret = OTP_USAGE;

	if (ret == OTP_USAGE) {
		usage();
		return EXIT_FAILURE;
	} else if (ret == OTP_FAILURE) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}
