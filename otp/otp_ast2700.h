/* SPDX-License-Identifier: GPL-2.0 */

#ifndef OTP_AST2700_H
#define OTP_AST2700_H

#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

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
#define ID0_AST2750A1			0x06010003
#define ID1_AST2750A1			0x06010003
#define ID0_AST2700A1			0x06010103
#define ID1_AST2700A1			0x06010103

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
#define OTP_STRAP_REGION_SIZE		(STRAP_REGION_END_ADDR - STRAP_REGION_START_ADDR)
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
};

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

int confirm_yesno(void);
void buf_print(uint8_t *buf, int len);

int otp_read_rom(uint32_t offset, uint16_t *data);
int otp_read_rbp(uint32_t offset, uint16_t *data);
int otp_read_conf(uint32_t offset, uint16_t *data);
int otp_read_strap(uint32_t offset, uint16_t *data);
int otp_read_strap_ext(uint32_t offset, uint16_t *data);
int otp_read_strap_ext_vld(uint32_t offset, uint16_t *data);
int otp_read_udata(uint32_t offset, uint16_t *data);
int otp_read_sdata(uint32_t offset, uint16_t *data);
int otp_read_sdata_multi(uint32_t offset, uint16_t *data, int num);
int otp_read_cptra(uint32_t offset, uint16_t *data);
int otp_read_swpuf(uint32_t offset, uint16_t *data);

int otp_prog(uint32_t offset, uint16_t data);
int otp_prog_multi(uint32_t offset, uint16_t *data, int num);
int otp_prog_data(int mode, int otp_w_offset, int bit_offset,
		  int value, int nconfirm, bool debug);

int otp_verify_image(uint8_t *src_buf, uint32_t length, uint8_t *digest_buf);
int otp_prog_image_region(struct otp_image_layout *image_layout, enum otp_region region_type);
int otp_prog_strap_image(struct otp_image_layout *image_layout,
			 struct otpstrap_status *otpstrap);
int otp_prog_strap_ext_image(struct otp_image_layout *image_layout);

extern struct otp_info_cb info_cb;

#endif /* OTP_AST2700_H */
