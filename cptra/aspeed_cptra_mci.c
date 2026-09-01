// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2026 Aspeed Technology Inc.
 *
 * AST2705 Caliptra-SS MCI (Manageability Controller Interface) mailbox test.
 *
 * Every command (fw_version, subsystem_info, sha, ecdsa, lms, ml-dsa,
 * cmk-managed key ops) goes through /dev/aspeed-cptra-mci -- either
 * CPTRA_MCI_IOC_MBOX_EXECUTE for mailbox protocol commands, or
 * CPTRA_MCI_IOC_REG_READ for the handful of plain (non-mailbox-protocol)
 * status registers subsystem_info reads (see
 * linux/drivers/soc/aspeed/aspeed-cptra-mci-mbox.c in the kernel tree).
 * Request/response struct layout, checksums and command semantics all
 * still live here in userspace -- the kernel only forwards an already-
 * packed request to aspeed_cptra_mci_mbox_execute()/aspeed_cptra_mci_reg_
 * read() and copies the raw response back. This process never maps
 * /dev/mem or touches a hardware register directly.
 *
 * The AST2700 (BootMCU-based) test is built from the separate aspeed_cptra.c
 * -- this file is AST2705-only. Both compile to the same "aspeed_cptra"
 * output name; exactly one is ever built per configuration.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BIT(n)		(1U << (n))

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

/*
 * /dev/aspeed-cptra-mci ioctls: no shared uapi header (same convention as
 * this SoC's legacy /dev/mboxN -- see MBOX_IOCTL_SEND/RECV below and
 * aspeed-mbox.c's ASPEED_MBOX_IOCTL_*). These must match the identical
 * definitions in linux/drivers/soc/aspeed/aspeed-cptra-mci-mbox.c exactly.
 */
struct cptra_mci_ioc_mbox_execute {
	uint32_t cmd;
	uint32_t req_len;
	uint32_t resp_buf_len;
	uint32_t resp_len;
	uint64_t req_ptr;
	uint64_t resp_ptr;
};

struct cptra_mci_ioc_reg_read {
	uint32_t page;
	uint32_t offset;
	uint32_t value;
};

#define CPTRA_MCI_IOC_MAGIC		'M'
#define CPTRA_MCI_IOC_MBOX_EXECUTE	_IOWR(CPTRA_MCI_IOC_MAGIC, 0x01, \
					     struct cptra_mci_ioc_mbox_execute)
#define CPTRA_MCI_IOC_REG_READ		_IOWR(CPTRA_MCI_IOC_MAGIC, 0x02, \
					     struct cptra_mci_ioc_reg_read)

/* ================= Caliptra-SS MCI mailbox: register layout ================= */

#define CPTRA_MCI_MBOX_SRAM_SIZE		0x4000
#define CPTRA_MCI_MBOX_MAX_INPUT_SIZE		4096

/* CommandId ("common/mcu-mbox/src/messages.rs", caliptra-mcu-sw) */
enum cptra_mci_mbox_cmd {
	CPTRA_MCI_MBCMD_FIRMWARE_VERSION	= 0x4D465756, /* "MFWV" */
	CPTRA_MCI_MBCMD_SHA_INIT		= 0x4D435349, /* "MCSI" */
	CPTRA_MCI_MBCMD_SHA_UPDATE		= 0x4D435355, /* "MCSU" */
	CPTRA_MCI_MBCMD_SHA_FINAL		= 0x4D435346, /* "MCSF" */
	CPTRA_MCI_MBCMD_ECDSA384_SIG_VERIFY	= 0x4D454356, /* "MECV" */
	CPTRA_MCI_MBCMD_LMS_SIG_VERIFY		= 0x4D4C4D56, /* "MLMV" */
	CPTRA_MCI_MBCMD_MLDSA87_SIG_VERIFY	= 0x4D4D5356, /* "MMSV" */
	CPTRA_MCI_MBCMD_IMPORT			= 0x4D43494D, /* "MCIM" */
	CPTRA_MCI_MBCMD_DELETE			= 0x4D43444C, /* "MCDL" */
	CPTRA_MCI_MBCMD_ECDSA_CMK_PUBLIC_KEY	= 0x4D434550, /* "MCEP" */
	CPTRA_MCI_MBCMD_ECDSA_CMK_SIGN		= 0x4D434553, /* "MCES" */
	CPTRA_MCI_MBCMD_ECDSA_CMK_VERIFY	= 0x4D434556, /* "MCEV" */
	CPTRA_MCI_MBCMD_MLDSA_CMK_PUBLIC_KEY	= 0x4D4D4C50, /* "MMLP" */
	CPTRA_MCI_MBCMD_MLDSA_CMK_SIGN		= 0x4D4D4C53, /* "MMLS" */
	CPTRA_MCI_MBCMD_MLDSA_CMK_VERIFY	= 0x4D4D4C56, /* "MMLV" */
	CPTRA_MCI_MBCMD_DEVICE_CAPABILITIES	= 0x4D434150, /* "MCAP" */
	CPTRA_MCI_MBCMD_GET_LOG			= 0x4D474C47, /* "MGLG" */
	CPTRA_MCI_MBCMD_CLEAR_LOG		= 0x4D434C47, /* "MCLG" */
	CPTRA_MCI_MBCMD_GET_AUTH_CMD_CHALLENGE	= 0x4D414343, /* "MACC" */
	CPTRA_MCI_MBCMD_EXPORT_ATTESTED_CSR	= 0x4D454143, /* "MEAC" */
	CPTRA_MCI_MBCMD_CM_STATUS		= 0x4D435354, /* "MCST" */
	CPTRA_MCI_MBCMD_RANDOM_STIR		= 0x4D435253, /* "MCRS" */
	CPTRA_MCI_MBCMD_RANDOM_GENERATE		= 0x4D435247, /* "MCRG" */
	CPTRA_MCI_MBCMD_ECDH_GENERATE		= 0x4D434547, /* "MCEG" */
	CPTRA_MCI_MBCMD_ECDH_FINISH		= 0x4D434546, /* "MCEF" */
	CPTRA_MCI_MBCMD_HMAC			= 0x4D43484D, /* "MCHM" */
	CPTRA_MCI_MBCMD_HMAC_KDF_COUNTER	= 0x4D434B43, /* "MCKC" */
	CPTRA_MCI_MBCMD_HKDF_EXTRACT		= 0x4D434B54, /* "MCKT" */
	CPTRA_MCI_MBCMD_HKDF_EXPAND		= 0x4D434B50, /* "MCKP" */
	CPTRA_MCI_MBCMD_AES_ENCRYPT_INIT	= 0x4D434349, /* "MCCI" */
	CPTRA_MCI_MBCMD_AES_ENCRYPT_UPDATE	= 0x4D434355, /* "MCCU" */
	CPTRA_MCI_MBCMD_AES_DECRYPT_INIT	= 0x4D43414A, /* "MCAJ" */
	CPTRA_MCI_MBCMD_AES_DECRYPT_UPDATE	= 0x4D434155, /* "MCAU" */
	CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_INIT	= 0x4D434749, /* "MCGI" */
	CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_UPDATE	= 0x4D434755, /* "MCGU" */
	CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_FINAL	= 0x4D434746, /* "MCGF" */
	CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_INIT	= 0x4D434449, /* "MCDI" */
	CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_UPDATE	= 0x4D434455, /* "MCDU" */
	CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_FINAL	= 0x4D434446, /* "MCDF" */
};

struct cptra_mci_mbox_req_hdr {
	uint32_t chksum;
};

struct cptra_mci_mbox_resp_hdr {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_mci_mbox_resp_hdr_var {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint32_t data_len;
};

enum cptra_mci_fw_index {
	CPTRA_MCI_FW_INDEX_CALIPTRA_CORE = 0,
	CPTRA_MCI_FW_INDEX_MCU_RUNTIME,
	CPTRA_MCI_FW_INDEX_SOC,
};

#define CPTRA_MCI_MAX_FW_VERSION_STR_LEN	32

struct cptra_mci_fw_version_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t index;
};

struct cptra_mci_fw_version_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t version[CPTRA_MCI_MAX_FW_VERSION_STR_LEN];
};

#define CPTRA_MCI_ECC384_SCALAR_SIZE		48

#define CPTRA_MCI_SHA_CONTEXT_SIZE		200
#define CPTRA_MCI_SHA384_DIGEST_SIZE		48
#define CPTRA_MCI_SHA512_DIGEST_SIZE		64

enum cptra_mci_sha_algo {
	CPTRA_MCI_SHA_ALGO_SHA384 = 1,
	CPTRA_MCI_SHA_ALGO_SHA512 = 2,
};

struct cptra_mci_sha_init_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t hash_algorithm;
	uint32_t input_size;
};

struct cptra_mci_sha_data_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE];
	uint32_t input_size;
};

struct cptra_mci_sha_ctx_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE];
};

struct cptra_mci_sha_final_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t hash[CPTRA_MCI_SHA512_DIGEST_SIZE];
};

struct cptra_mci_ecdsa384_sig_verify_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t pub_key_x[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t pub_key_y[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t signature_r[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t signature_s[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t hash[CPTRA_MCI_ECC384_SCALAR_SIZE];
};

struct cptra_mci_ecdsa384_sig_verify_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

#define CPTRA_MCI_LMS_PUBKEY_ID_SIZE		16
#define CPTRA_MCI_LMS_PUBKEY_DIGEST_SIZE	24
#define CPTRA_MCI_LMS_OTS_SIGNATURE_SIZE	1252
#define CPTRA_MCI_LMS_TREE_PATH_SIZE		360
#define CPTRA_MCI_LMS_HASH_SIZE			48

#define CPTRA_MCI_LMS_TREE_TYPE_FIXED		12
#define CPTRA_MCI_LMS_OTS_TYPE_FIXED		7

struct cptra_mci_lms_verify_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t pub_key_tree_type;
	uint32_t pub_key_ots_type;
	uint8_t pub_key_id[CPTRA_MCI_LMS_PUBKEY_ID_SIZE];
	uint8_t pub_key_digest[CPTRA_MCI_LMS_PUBKEY_DIGEST_SIZE];
	uint32_t signature_q;
	uint8_t signature_ots[CPTRA_MCI_LMS_OTS_SIGNATURE_SIZE];
	uint32_t signature_tree_type;
	uint8_t signature_tree_path[CPTRA_MCI_LMS_TREE_PATH_SIZE];
	uint8_t hash[CPTRA_MCI_LMS_HASH_SIZE];
};

struct cptra_mci_lms_verify_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

#define CPTRA_MCI_MLDSA87_PUBKEY_SIZE		2592
#define CPTRA_MCI_MLDSA87_SIGNATURE_SIZE	4628

struct cptra_mci_mldsa87_sig_verify_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t pub_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE];
	uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE];
	uint32_t message_size;
};

struct cptra_mci_mldsa87_sig_verify_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

#define CPTRA_MCI_CMK_SIZE			128

struct cptra_mci_cmk {
	uint8_t value[CPTRA_MCI_CMK_SIZE];
};

enum cptra_mci_key_usage {
	CPTRA_MCI_KEY_USAGE_HMAC = 1,
	CPTRA_MCI_KEY_USAGE_AES = 2,
	CPTRA_MCI_KEY_USAGE_ECDSA = 3,
	CPTRA_MCI_KEY_USAGE_MLDSA = 4,
	CPTRA_MCI_KEY_USAGE_MLKEM = 5,
};

struct cptra_mci_import_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t key_usage;
	uint32_t input_size;
};

struct cptra_mci_import_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	struct cptra_mci_cmk cmk;
};

struct cptra_mci_delete_req {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
};

struct cptra_mci_delete_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

struct cptra_mci_ecdsa_pubkey_req {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
};

struct cptra_mci_ecdsa_pubkey_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t qx[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t qy[CPTRA_MCI_ECC384_SCALAR_SIZE];
};

struct cptra_mci_ecdsa_sign_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint32_t message_size;
};

struct cptra_mci_ecdsa_sign_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t s[CPTRA_MCI_ECC384_SCALAR_SIZE];
};

struct cptra_mci_mldsa_pubkey_req {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
};

struct cptra_mci_mldsa_pubkey_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t public_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE];
};

struct cptra_mci_mldsa_sign_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint32_t message_size;
};

struct cptra_mci_mldsa_sign_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE];
};

struct cptra_mci_ecdsa_verify_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t s[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint32_t message_size;
};

struct cptra_mci_ecdsa_verify_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

struct cptra_mci_mldsa_verify_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE];
	uint32_t message_size;
};

struct cptra_mci_mldsa_verify_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

#define CPTRA_MCI_DEVICE_CAPS_SIZE		32

struct cptra_mci_device_caps_req {
	struct cptra_mci_mbox_req_hdr hdr;
};

struct cptra_mci_device_caps_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t caps[CPTRA_MCI_DEVICE_CAPS_SIZE];
};

#define CPTRA_MCI_MAX_RESP_DATA_SIZE		4096

enum cptra_mci_log_type {
	CPTRA_MCI_LOG_TYPE_DEBUG = 0,
	CPTRA_MCI_LOG_TYPE_ATTESTATION = 1,
};

struct cptra_mci_get_log_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t log_type;
};

struct cptra_mci_get_log_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t data[CPTRA_MCI_MAX_RESP_DATA_SIZE];
};

struct cptra_mci_clear_log_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t log_type;
};

struct cptra_mci_clear_log_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

#define CPTRA_MCI_AUTH_CHALLENGE_SIZE		32

struct cptra_mci_auth_cmd_challenge_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t flags;
	uint32_t reserved;
};

struct cptra_mci_auth_cmd_challenge_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint32_t reserved;
	uint8_t challenge[CPTRA_MCI_AUTH_CHALLENGE_SIZE];
};

#define CPTRA_MCI_CSR_NONCE_SIZE		32

enum cptra_mci_csr_device_key_id {
	CPTRA_MCI_CSR_KEY_LDEVID = 1,
	CPTRA_MCI_CSR_KEY_FMC_ALIAS = 2,
	CPTRA_MCI_CSR_KEY_RT_ALIAS = 3,
};

enum cptra_mci_csr_algorithm {
	CPTRA_MCI_CSR_ALGO_ECC384 = 1,
	CPTRA_MCI_CSR_ALGO_MLDSA87 = 2,
};

struct cptra_mci_export_csr_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t device_key_id;
	uint32_t algorithm;
	uint8_t nonce[CPTRA_MCI_CSR_NONCE_SIZE];
};

struct cptra_mci_export_csr_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t data[CPTRA_MCI_MAX_RESP_DATA_SIZE];
};

struct cptra_mci_cm_status_req {
	struct cptra_mci_mbox_req_hdr hdr;
};

struct cptra_mci_cm_status_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint32_t used_usage_storage;
	uint32_t total_usage_storage;
};

struct cptra_mci_random_stir_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t input_size;
};

struct cptra_mci_random_stir_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
};

struct cptra_mci_random_generate_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t size;
};

struct cptra_mci_random_generate_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t data[CPTRA_MCI_MBOX_MAX_INPUT_SIZE];
};

#define CPTRA_MCI_ECDH_CONTEXT_SIZE		76
#define CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE	96

struct cptra_mci_ecdh_generate_req {
	struct cptra_mci_mbox_req_hdr hdr;
};

struct cptra_mci_ecdh_generate_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_ECDH_CONTEXT_SIZE];
	uint8_t exchange_data[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE];
};

struct cptra_mci_ecdh_finish_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t context[CPTRA_MCI_ECDH_CONTEXT_SIZE];
	uint32_t key_usage;
	uint8_t incoming_exchange_data[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE];
};

struct cptra_mci_ecdh_finish_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	struct cptra_mci_cmk output;
};

#define CPTRA_MCI_HMAC_MAX_SIZE			64

struct cptra_mci_hmac_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint32_t hash_algorithm;
	uint32_t data_size;
};

struct cptra_mci_hmac_resp {
	struct cptra_mci_mbox_resp_hdr_var hdr;
	uint8_t mac[CPTRA_MCI_HMAC_MAX_SIZE];
};

struct cptra_mci_hmac_kdf_counter_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk kin;
	uint32_t hash_algorithm;
	uint32_t key_usage;
	uint32_t key_size;
	uint32_t label_size;
};

struct cptra_mci_hmac_kdf_counter_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	struct cptra_mci_cmk kout;
};

struct cptra_mci_hkdf_extract_req {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t hash_algorithm;
	struct cptra_mci_cmk salt;
	struct cptra_mci_cmk ikm;
};

struct cptra_mci_hkdf_extract_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	struct cptra_mci_cmk prk;
};

struct cptra_mci_hkdf_expand_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk prk;
	uint32_t hash_algorithm;
	uint32_t key_usage;
	uint32_t key_size;
	uint32_t info_size;
};

struct cptra_mci_hkdf_expand_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	struct cptra_mci_cmk okm;
};

#define CPTRA_MCI_AES_CONTEXT_SIZE		156
#define CPTRA_MCI_AES_IV_SIZE			16
#define CPTRA_MCI_AES_MAX_OUTPUT_SIZE		4096

enum cptra_mci_aes_mode {
	CPTRA_MCI_AES_MODE_CBC = 1,
	CPTRA_MCI_AES_MODE_CTR = 2,
};

struct cptra_mci_aes_encrypt_init_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint32_t mode;
	uint32_t plaintext_size;
};

struct cptra_mci_aes_init_resp_hdr {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE];
	uint8_t iv[CPTRA_MCI_AES_IV_SIZE];
	uint32_t output_size;
};

struct cptra_mci_aes_init_resp {
	struct cptra_mci_aes_init_resp_hdr hdr;
	uint8_t output[CPTRA_MCI_AES_MAX_OUTPUT_SIZE];
};

/* Shared by AES_ENCRYPT_UPDATE and AES_DECRYPT_UPDATE. */
struct cptra_mci_aes_update_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE];
	uint32_t size;
};

struct cptra_mci_aes_resp_hdr {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE];
	uint32_t output_size;
};

/*
 * Also the response shape for AES_DECRYPT_INIT: the hardware's decrypt-init
 * response omits encrypt-init's extra iv field entirely rather than just
 * leaving it zeroed, so every field after context lands 16 bytes earlier on
 * the wire than the encrypt-init struct would predict -- do not reuse
 * cptra_mci_aes_init_resp for AES_DECRYPT_INIT.
 */
struct cptra_mci_aes_resp {
	struct cptra_mci_aes_resp_hdr hdr;
	uint8_t output[CPTRA_MCI_AES_MAX_OUTPUT_SIZE];
};

struct cptra_mci_aes_decrypt_init_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	struct cptra_mci_cmk cmk;
	uint32_t mode;
	uint8_t iv[CPTRA_MCI_AES_IV_SIZE];
	uint32_t ciphertext_size;
};

#define CPTRA_MCI_AES_GCM_CONTEXT_SIZE		128
#define CPTRA_MCI_AES_GCM_IV_SIZE		12
#define CPTRA_MCI_AES_GCM_TAG_SIZE		16
#define CPTRA_MCI_AES_GCM_MAX_OUTPUT_SIZE	4112

struct cptra_mci_aes_gcm_encrypt_init_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t flags;
	struct cptra_mci_cmk cmk;
	uint32_t aad_size;
};

struct cptra_mci_aes_gcm_init_resp {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE];
	uint8_t iv[CPTRA_MCI_AES_GCM_IV_SIZE];
};

/* Shared by AES_GCM_ENCRYPT_UPDATE, AES_GCM_ENCRYPT_FINAL and AES_GCM_DECRYPT_UPDATE. */
struct cptra_mci_aes_gcm_data_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE];
	uint32_t size;
};

struct cptra_mci_aes_gcm_update_resp_hdr {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE];
	uint32_t output_size;
};

struct cptra_mci_aes_gcm_update_resp {
	struct cptra_mci_aes_gcm_update_resp_hdr hdr;
	uint8_t output[CPTRA_MCI_AES_GCM_MAX_OUTPUT_SIZE];
};

struct cptra_mci_aes_gcm_encrypt_final_resp_hdr {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint8_t tag[CPTRA_MCI_AES_GCM_TAG_SIZE];
	uint32_t output_size;
};

struct cptra_mci_aes_gcm_encrypt_final_resp {
	struct cptra_mci_aes_gcm_encrypt_final_resp_hdr hdr;
	uint8_t output[CPTRA_MCI_AES_GCM_MAX_OUTPUT_SIZE];
};

struct cptra_mci_aes_gcm_decrypt_init_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint32_t flags;
	struct cptra_mci_cmk cmk;
	uint8_t iv[CPTRA_MCI_AES_GCM_IV_SIZE];
	uint32_t aad_size;
};

struct cptra_mci_aes_gcm_decrypt_final_hdr {
	struct cptra_mci_mbox_req_hdr hdr;
	uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE];
	uint32_t tag_len;
	uint8_t tag[CPTRA_MCI_AES_GCM_TAG_SIZE];
	uint32_t ciphertext_size;
};

struct cptra_mci_aes_gcm_decrypt_final_resp_hdr {
	struct cptra_mci_mbox_resp_hdr hdr;
	uint32_t tag_verified;
	uint32_t output_size;
};

struct cptra_mci_aes_gcm_decrypt_final_resp {
	struct cptra_mci_aes_gcm_decrypt_final_resp_hdr hdr;
	uint8_t output[CPTRA_MCI_AES_GCM_MAX_OUTPUT_SIZE];
};

/*
 * Direct (non-mailbox-protocol) MCI subsystem status registers, reachable
 * through the same paged SCU1 window, one block per 64KB-aligned page.
 */
#define CPTRA_MCI_REG_PAGE			0x2100	/* mci_reg, 0x21000000 >> 16 */

#define CPTRA_MCI_REG_MCU_IFU_AXI_USER			0x0020
#define CPTRA_MCI_REG_MCU_LSU_AXI_USER			0x0024
#define CPTRA_MCI_REG_MCU_SRAM_CONFIG_AXI_USER		0x0028
#define CPTRA_MCI_REG_MCI_SOC_CONFIG_AXI_USER		0x002c
#define CPTRA_MCI_REG_RESET_REASON			0x0038
#define   CPTRA_MCI_REG_RESET_REASON_FW_HITLESS_UPD_RESET	BIT(0)
#define   CPTRA_MCI_REG_RESET_REASON_FW_BOOT_UPD_RESET		BIT(1)
#define   CPTRA_MCI_REG_RESET_REASON_WARM_RESET		BIT(2)
#define CPTRA_MCI_REG_SECURITY_STATE			0x0040
#define   CPTRA_MCI_REG_SECURITY_STATE_DEVICE_LIFECYCLE_MASK	0x3
#define   CPTRA_MCI_REG_SECURITY_STATE_DEBUG_LOCKED		BIT(2)
#define   CPTRA_MCI_REG_SECURITY_STATE_SCAN_MODE		BIT(3)

enum cptra_mci_device_lifecycle {
	CPTRA_MCI_DEVICE_UNPROVISIONED = 0,
	CPTRA_MCI_DEVICE_MANUFACTURING = 1,
	CPTRA_MCI_DEVICE_PRODUCTION = 3,
};

#define CPTRA_MCI_REG_MBOX_AXI_USER_COUNT		5
#define CPTRA_MCI_REG_MBOX0_VALID_AXI_USER(n)		(0x0180 + 4 * (n))
#define CPTRA_MCI_REG_MBOX0_AXI_USER_LOCK(n)		(0x01a0 + 4 * (n))
#define CPTRA_MCI_REG_MBOX1_VALID_AXI_USER(n)		(0x01c0 + 4 * (n))
#define CPTRA_MCI_REG_MBOX1_AXI_USER_LOCK(n)		(0x01e0 + 4 * (n))

#define CPTRA_MCI_REG_SS_DEBUG_INTENT			0x0418
#define CPTRA_MCI_REG_SS_CONFIG_DONE_STICKY		0x0440
#define CPTRA_MCI_REG_SS_CONFIG_DONE			0x0444

#define CPTRA_MCI_SOC_IFC_PAGE				0xa003	/* soc_ifc_reg, 0xa0030000 >> 16 */

#define CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON		0x0040
#define   CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON_FW_UPD_RESET	BIT(0)
#define   CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON_WARM_RESET	BIT(1)
#define CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE		0x0044
#define   CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_DEVICE_LIFECYCLE_MASK	0x3
#define   CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_DEBUG_LOCKED		BIT(2)
#define   CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_SCAN_MODE		BIT(3)
#define CPTRA_MCI_SOC_IFC_MBOX_AXI_USER_COUNT		5
#define CPTRA_MCI_SOC_IFC_CPTRA_MBOX_VALID_AXI_USER(n)	(0x0048 + 4 * (n))
#define CPTRA_MCI_SOC_IFC_CPTRA_MBOX_AXI_USER_LOCK(n)	(0x005c + 4 * (n))
#define CPTRA_MCI_SOC_IFC_CPTRA_TRNG_VALID_AXI_USER	0x0070
#define CPTRA_MCI_SOC_IFC_CPTRA_TRNG_AXI_USER_LOCK	0x0074
#define CPTRA_MCI_SOC_IFC_CPTRA_FUSE_VALID_AXI_USER	0x0108

/* ================= mailbox ioctl transport ================= */

#define CPTRA_MCI_DEV_PATH	"/dev/aspeed-cptra-mci"

static int gbl_mci_fd = -1;
static int gbl_verbose;
static int gbl_quiet;

#define dbg_printf(fmt, args...)	do { if (gbl_verbose) printf(fmt, ##args); } while (0)
/* Non-failure output; suppressed under -q so only FAIL/failed lines remain. */
#define info_printf(fmt, args...)	do { if (!gbl_quiet) printf(fmt, ##args); } while (0)

static int mci_dev_open(void)
{
	gbl_mci_fd = open(CPTRA_MCI_DEV_PATH, O_RDWR);
	if (gbl_mci_fd < 0) {
		perror("open " CPTRA_MCI_DEV_PATH);
		return -1;
	}

	return 0;
}

static void mci_dev_close(void)
{
	if (gbl_mci_fd >= 0)
		close(gbl_mci_fd);
}

static uint32_t mci_checksum_ext(uint32_t checksum, const void *data, uint32_t len)
{
	const uint8_t *p8 = (const uint8_t *)data;
	uint32_t i;

	for (i = 0; i < len; i++)
		checksum -= p8[i];

	return checksum;
}

static uint32_t mci_checksum(uint32_t cmd, const void *data, uint32_t len)
{
	uint32_t checksum = mci_checksum_ext(0, &cmd, sizeof(cmd));

	return mci_checksum_ext(checksum, data, len);
}

struct mci_iov {
	const void *base;
	uint32_t len;
};

/*
 * Concatenates iov into one flat buffer (the kernel's ioctl passthrough
 * takes a single already-packed request, not a scatter-gather list) and
 * hands it to CPTRA_MCI_IOC_MBOX_EXECUTE. The kernel forwards it verbatim
 * to aspeed_cptra_mci_mbox_execute() -- all of the page-select/lock/execute
 * protocol now happens there, not in this process.
 */
static int mci_execute_iov(uint32_t cmd, const struct mci_iov *iov, int iovcnt,
			   void *resp, uint32_t resp_buf_len, uint32_t *resp_len)
{
	struct cptra_mci_ioc_mbox_execute uarg = { 0 };
	uint8_t *req_buf;
	uint32_t req_len, off;
	int ret, i;

	req_len = 0;
	for (i = 0; i < iovcnt; i++)
		req_len += iov[i].len;

	if (req_len > CPTRA_MCI_MBOX_SRAM_SIZE || resp_buf_len > CPTRA_MCI_MBOX_SRAM_SIZE)
		return -EINVAL;

	req_buf = (uint8_t *)malloc(req_len ? req_len : 1);
	if (!req_buf)
		return -ENOMEM;

	off = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].len)
			memcpy(req_buf + off, iov[i].base, iov[i].len);
		off += iov[i].len;
	}

	uarg.cmd = cmd;
	uarg.req_len = req_len;
	uarg.resp_buf_len = resp_buf_len;
	uarg.req_ptr = (uint64_t)(uintptr_t)req_buf;
	uarg.resp_ptr = (uint64_t)(uintptr_t)resp;

	ret = ioctl(gbl_mci_fd, CPTRA_MCI_IOC_MBOX_EXECUTE, &uarg);

	free(req_buf);

	if (ret < 0) {
		dbg_printf("CPTRA_MCI_IOC_MBOX_EXECUTE cmd 0x%x failed: %s\n", cmd,
			   strerror(errno));
		return -errno;
	}

	if (resp_len)
		*resp_len = uarg.resp_len;

	return 0;
}

static int mci_execute(uint32_t cmd, const void *req, uint32_t req_len,
		       void *resp, uint32_t resp_buf_len, uint32_t *resp_len)
{
	struct mci_iov iov = { .base = req, .len = req_len };

	return mci_execute_iov(cmd, &iov, 1, resp, resp_buf_len, resp_len);
}

static int mci_execute_sg(uint32_t cmd, const void *hdr, uint32_t hdr_len,
			  const void *data, uint32_t data_len,
			  void *resp, uint32_t resp_buf_len, uint32_t *resp_len)
{
	struct mci_iov iov[2] = {
		{ .base = hdr, .len = hdr_len },
		{ .base = data, .len = data_len },
	};

	return mci_execute_iov(cmd, iov, 2, resp, resp_buf_len, resp_len);
}

/* ================= direct status register read (subsystem_info) ================= */

/*
 * subsystem_info reads plain, non-mailbox-protocol status registers via
 * CPTRA_MCI_IOC_REG_READ -- same device, same ioctl()-only rule as every
 * other test, just a different ioctl number than CPTRA_MCI_IOC_MBOX_EXECUTE.
 */
static int mci_reg_read(uint32_t page, uint32_t offset, uint32_t *value)
{
	struct cptra_mci_ioc_reg_read uarg = { .page = page, .offset = offset };
	int ret;

	ret = ioctl(gbl_mci_fd, CPTRA_MCI_IOC_REG_READ, &uarg);
	if (ret < 0) {
		dbg_printf("CPTRA_MCI_IOC_REG_READ page=0x%x offset=0x%x failed: %s\n",
			   page, offset, strerror(errno));
		return -errno;
	}

	*value = uarg.value;

	return 0;
}

/* ================= command wrappers ================= */

static int mci_get_firmware_version(enum cptra_mci_fw_index index, char *version, size_t len)
{
	struct cptra_mci_fw_version_req req = { .index = index };
	struct cptra_mci_fw_version_resp resp = { 0 };
	uint32_t resp_len, vlen;
	int ret;

	if (len == 0)
		return -EINVAL;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_FIRMWARE_VERSION, &req.index,
				      sizeof(req.index));

	ret = mci_execute(CPTRA_MCI_MBCMD_FIRMWARE_VERSION, &req, sizeof(req),
			  &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;

	if (resp_len < sizeof(resp.hdr))
		return -EIO;

	vlen = resp.hdr.data_len < sizeof(resp.version) ? resp.hdr.data_len : sizeof(resp.version);
	if (vlen > len - 1)
		vlen = (uint32_t)(len - 1);

	if (resp_len < sizeof(resp.hdr) + vlen)
		return -EIO;

	memset(version, 0, len);
	memcpy(version, resp.version, vlen);

	return 0;
}

static int mci_sha_init(uint32_t algo, uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE])
{
	struct cptra_mci_sha_init_hdr req = { .hash_algorithm = algo, .input_size = 0 };
	struct cptra_mci_sha_ctx_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_SHA_INIT, &req.hash_algorithm,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_SHA_INIT, &req, sizeof(req), &resp, sizeof(resp),
			  &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(context, resp.context, CPTRA_MCI_SHA_CONTEXT_SIZE);

	return 0;
}

static int mci_sha_update(uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE], const uint8_t *data,
			  uint32_t len)
{
	struct cptra_mci_sha_data_hdr req = { .input_size = len };
	struct cptra_mci_sha_ctx_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_SHA_UPDATE, req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, data, len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_SHA_UPDATE, &req, sizeof(req), data, len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(context, resp.context, sizeof(resp.context));

	return 0;
}

static int mci_sha_final(uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE], uint32_t dgst_len,
			 uint8_t *out)
{
	struct cptra_mci_sha_data_hdr req = { .input_size = 0 };
	struct cptra_mci_sha_final_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_SHA_FINAL, req.context, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, NULL, 0);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_SHA_FINAL, &req, sizeof(req), NULL, 0,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;

	if (resp_len < sizeof(resp.hdr) + dgst_len)
		return -EIO;

	memcpy(out, resp.hash, dgst_len);

	return 0;
}

static int mci_sha_digest(uint32_t algo, const uint8_t *msg, uint32_t msg_len,
			  uint32_t dgst_len, uint8_t *out)
{
	uint8_t context[CPTRA_MCI_SHA_CONTEXT_SIZE];
	int ret;

	ret = mci_sha_init(algo, context);
	if (ret)
		return ret;

	if (msg_len) {
		ret = mci_sha_update(context, msg, msg_len);
		if (ret)
			return ret;
	}

	return mci_sha_final(context, dgst_len, out);
}

static int mci_ecdsa384_verify(const uint8_t qx[CPTRA_MCI_ECC384_SCALAR_SIZE],
			       const uint8_t qy[CPTRA_MCI_ECC384_SCALAR_SIZE],
			       const uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE],
			       const uint8_t s[CPTRA_MCI_ECC384_SCALAR_SIZE],
			       const uint8_t hash[CPTRA_MCI_ECC384_SCALAR_SIZE])
{
	struct cptra_mci_ecdsa384_sig_verify_req req = { 0 };
	struct cptra_mci_ecdsa384_sig_verify_resp resp = { 0 };
	uint32_t resp_len;

	memcpy(req.pub_key_x, qx, sizeof(req.pub_key_x));
	memcpy(req.pub_key_y, qy, sizeof(req.pub_key_y));
	memcpy(req.signature_r, r, sizeof(req.signature_r));
	memcpy(req.signature_s, s, sizeof(req.signature_s));
	memcpy(req.hash, hash, sizeof(req.hash));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_ECDSA384_SIG_VERIFY, req.pub_key_x,
				      sizeof(req) - sizeof(req.hdr));

	return mci_execute(CPTRA_MCI_MBCMD_ECDSA384_SIG_VERIFY, &req, sizeof(req),
			   &resp, sizeof(resp), &resp_len);
}

static int mci_lms_verify(uint32_t pub_key_tree_type, uint32_t pub_key_ots_type,
			  const uint8_t pub_key_id[CPTRA_MCI_LMS_PUBKEY_ID_SIZE],
			  const uint8_t pub_key_digest[CPTRA_MCI_LMS_PUBKEY_DIGEST_SIZE],
			  uint32_t signature_q,
			  const uint8_t signature_ots[CPTRA_MCI_LMS_OTS_SIGNATURE_SIZE],
			  uint32_t signature_tree_type,
			  const uint8_t signature_tree_path[CPTRA_MCI_LMS_TREE_PATH_SIZE],
			  const uint8_t hash[CPTRA_MCI_LMS_HASH_SIZE])
{
	struct cptra_mci_lms_verify_req *req;
	struct cptra_mci_lms_verify_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	if (pub_key_tree_type != CPTRA_MCI_LMS_TREE_TYPE_FIXED ||
	    pub_key_ots_type != CPTRA_MCI_LMS_OTS_TYPE_FIXED)
		return -EINVAL;

	req = (struct cptra_mci_lms_verify_req *)malloc(sizeof(*req));
	if (!req)
		return -ENOMEM;

	req->pub_key_tree_type = pub_key_tree_type;
	req->pub_key_ots_type = pub_key_ots_type;
	memcpy(req->pub_key_id, pub_key_id, sizeof(req->pub_key_id));
	memcpy(req->pub_key_digest, pub_key_digest, sizeof(req->pub_key_digest));
	req->signature_q = signature_q;
	memcpy(req->signature_ots, signature_ots, sizeof(req->signature_ots));
	req->signature_tree_type = signature_tree_type;
	memcpy(req->signature_tree_path, signature_tree_path, sizeof(req->signature_tree_path));
	memcpy(req->hash, hash, sizeof(req->hash));

	req->hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_LMS_SIG_VERIFY, &req->pub_key_tree_type,
				       sizeof(*req) - sizeof(req->hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_LMS_SIG_VERIFY, req, sizeof(*req),
			  &resp, sizeof(resp), &resp_len);

	free(req);

	return ret;
}

static int mci_mldsa87_verify(const uint8_t pub_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE],
			      const uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE],
			      const uint8_t *message, size_t message_len)
{
	struct cptra_mci_mldsa87_sig_verify_hdr *req;
	struct cptra_mci_mldsa87_sig_verify_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (message_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	req = (struct cptra_mci_mldsa87_sig_verify_hdr *)malloc(sizeof(*req));
	if (!req)
		return -ENOMEM;

	memcpy(req->pub_key, pub_key, sizeof(req->pub_key));
	memcpy(req->signature, signature, sizeof(req->signature));
	req->message_size = (uint32_t)message_len;

	csum = mci_checksum(CPTRA_MCI_MBCMD_MLDSA87_SIG_VERIFY, req->pub_key,
			    sizeof(*req) - sizeof(req->hdr));
	req->hdr.chksum = mci_checksum_ext(csum, message, (uint32_t)message_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_MLDSA87_SIG_VERIFY, req, sizeof(*req),
			     message, (uint32_t)message_len, &resp, sizeof(resp), &resp_len);

	free(req);

	return ret;
}

/*
 * Caliptra-SS's MC_IMPORT validation accepts exactly one or two input_size
 * values per key_usage: Aes/Mldsa -> 32, Ecdsa -> 48, Hmac -> 48 or 64,
 * Mlkem -> 64.
 */
static int mci_import_key_size_valid(enum cptra_mci_key_usage key_usage, size_t key_len)
{
	switch (key_usage) {
	case CPTRA_MCI_KEY_USAGE_AES:
	case CPTRA_MCI_KEY_USAGE_MLDSA:
		return key_len == 32;
	case CPTRA_MCI_KEY_USAGE_ECDSA:
		return key_len == 48;
	case CPTRA_MCI_KEY_USAGE_HMAC:
		return key_len == 48 || key_len == 64;
	case CPTRA_MCI_KEY_USAGE_MLKEM:
		return key_len == 64;
	default:
		return 0;
	}
}

static int mci_import_key(enum cptra_mci_key_usage key_usage, const uint8_t *key, size_t key_len,
			  uint8_t cmk[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_import_hdr req = {
		.key_usage = key_usage,
		.input_size = (uint32_t)key_len,
	};
	struct cptra_mci_import_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (!mci_import_key_size_valid(key_usage, key_len))
		return -EINVAL;

	csum = mci_checksum(CPTRA_MCI_MBCMD_IMPORT, &req.key_usage, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, key, (uint32_t)key_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_IMPORT, &req, sizeof(req), key, (uint32_t)key_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;

	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(cmk, resp.cmk.value, sizeof(resp.cmk.value));

	return 0;
}

static int mci_delete_key(const uint8_t cmk[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_delete_req req = { 0 };
	struct cptra_mci_delete_resp resp = { 0 };
	uint32_t resp_len;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_DELETE, &req.cmk, sizeof(req) - sizeof(req.hdr));

	return mci_execute(CPTRA_MCI_MBCMD_DELETE, &req, sizeof(req), &resp, sizeof(resp), &resp_len);
}

static int mci_ecdsa_cmk_public_key(const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				    uint8_t qx[CPTRA_MCI_ECC384_SCALAR_SIZE],
				    uint8_t qy[CPTRA_MCI_ECC384_SCALAR_SIZE])
{
	struct cptra_mci_ecdsa_pubkey_req req = { 0 };
	struct cptra_mci_ecdsa_pubkey_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_ECDSA_CMK_PUBLIC_KEY, &req.cmk,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_ECDSA_CMK_PUBLIC_KEY, &req, sizeof(req),
			  &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(qx, resp.qx, sizeof(resp.qx));
	memcpy(qy, resp.qy, sizeof(resp.qy));

	return 0;
}

static int mci_ecdsa_cmk_sign(const uint8_t cmk[CPTRA_MCI_CMK_SIZE], const uint8_t *message,
			      size_t message_len, uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE],
			      uint8_t s[CPTRA_MCI_ECC384_SCALAR_SIZE])
{
	struct cptra_mci_ecdsa_sign_hdr req = { .message_size = (uint32_t)message_len };
	struct cptra_mci_ecdsa_sign_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (message_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_ECDSA_CMK_SIGN, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, message, (uint32_t)message_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_ECDSA_CMK_SIGN, &req, sizeof(req),
			     message, (uint32_t)message_len, &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(r, resp.r, sizeof(resp.r));
	memcpy(s, resp.s, sizeof(resp.s));

	return 0;
}

static int mci_mldsa_cmk_public_key(const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				    uint8_t public_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE])
{
	struct cptra_mci_mldsa_pubkey_req req = { 0 };
	struct cptra_mci_mldsa_pubkey_resp *resp;
	uint32_t resp_len;
	int ret;

	resp = (struct cptra_mci_mldsa_pubkey_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_MLDSA_CMK_PUBLIC_KEY, &req.cmk,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_MLDSA_CMK_PUBLIC_KEY, &req, sizeof(req),
			  resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(*resp)) {
		ret = -EIO;
		goto out;
	}

	memcpy(public_key, resp->public_key, sizeof(resp->public_key));

out:
	free(resp);

	return ret;
}

static int mci_mldsa_cmk_sign(const uint8_t cmk[CPTRA_MCI_CMK_SIZE], const uint8_t *message,
			      size_t message_len, uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE])
{
	struct cptra_mci_mldsa_sign_hdr req = { .message_size = (uint32_t)message_len };
	struct cptra_mci_mldsa_sign_resp *resp;
	uint32_t resp_len, csum;
	int ret;

	if (message_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_mldsa_sign_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_MLDSA_CMK_SIGN, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, message, (uint32_t)message_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_MLDSA_CMK_SIGN, &req, sizeof(req),
			     message, (uint32_t)message_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(*resp)) {
		ret = -EIO;
		goto out;
	}

	memcpy(signature, resp->signature, sizeof(resp->signature));

out:
	free(resp);

	return ret;
}

static int mci_ecdsa_cmk_verify(const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				const uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE],
				const uint8_t s[CPTRA_MCI_ECC384_SCALAR_SIZE],
				const uint8_t *message, size_t message_len)
{
	struct cptra_mci_ecdsa_verify_hdr req = { .message_size = (uint32_t)message_len };
	struct cptra_mci_ecdsa_verify_resp resp = { 0 };
	uint32_t resp_len, csum;

	if (message_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));
	memcpy(req.r, r, sizeof(req.r));
	memcpy(req.s, s, sizeof(req.s));

	csum = mci_checksum(CPTRA_MCI_MBCMD_ECDSA_CMK_VERIFY, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, message, (uint32_t)message_len);

	return mci_execute_sg(CPTRA_MCI_MBCMD_ECDSA_CMK_VERIFY, &req, sizeof(req),
			      message, (uint32_t)message_len, &resp, sizeof(resp), &resp_len);
}

static int mci_mldsa_cmk_verify(const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				const uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE],
				const uint8_t *message, size_t message_len)
{
	struct cptra_mci_mldsa_verify_hdr *req;
	struct cptra_mci_mldsa_verify_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (message_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	req = (struct cptra_mci_mldsa_verify_hdr *)malloc(sizeof(*req));
	if (!req)
		return -ENOMEM;

	memcpy(req->cmk.value, cmk, sizeof(req->cmk.value));
	memcpy(req->signature, signature, sizeof(req->signature));
	req->message_size = (uint32_t)message_len;

	csum = mci_checksum(CPTRA_MCI_MBCMD_MLDSA_CMK_VERIFY, &req->cmk, sizeof(*req) - sizeof(req->hdr));
	req->hdr.chksum = mci_checksum_ext(csum, message, (uint32_t)message_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_MLDSA_CMK_VERIFY, req, sizeof(*req),
			     message, (uint32_t)message_len, &resp, sizeof(resp), &resp_len);

	free(req);

	return ret;
}

static int mci_get_device_capabilities(uint8_t caps[CPTRA_MCI_DEVICE_CAPS_SIZE])
{
	struct cptra_mci_device_caps_req req = { 0 };
	struct cptra_mci_device_caps_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_DEVICE_CAPABILITIES, NULL, 0);

	ret = mci_execute(CPTRA_MCI_MBCMD_DEVICE_CAPABILITIES, &req, sizeof(req),
			  &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(caps, resp.caps, sizeof(resp.caps));

	return 0;
}

static int mci_get_log(enum cptra_mci_log_type log_type, uint8_t *buf, uint32_t buf_len,
		       uint32_t *data_len)
{
	struct cptra_mci_get_log_req req = { .log_type = log_type };
	struct cptra_mci_get_log_resp *resp;
	uint32_t resp_len, copy_len;
	int ret;

	resp = (struct cptra_mci_get_log_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_GET_LOG, &req.log_type, sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_GET_LOG, &req, sizeof(req), resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	copy_len = resp->hdr.data_len < sizeof(resp->data) ? resp->hdr.data_len : sizeof(resp->data);
	copy_len = copy_len < buf_len ? copy_len : buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(buf, resp->data, copy_len);
	*data_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_clear_log(enum cptra_mci_log_type log_type)
{
	struct cptra_mci_clear_log_req req = { .log_type = log_type };
	struct cptra_mci_clear_log_resp resp = { 0 };
	uint32_t resp_len;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_CLEAR_LOG, &req.log_type, sizeof(req) - sizeof(req.hdr));

	return mci_execute(CPTRA_MCI_MBCMD_CLEAR_LOG, &req, sizeof(req), &resp, sizeof(resp), &resp_len);
}

static int mci_get_auth_cmd_challenge(uint32_t flags, uint8_t challenge[CPTRA_MCI_AUTH_CHALLENGE_SIZE])
{
	struct cptra_mci_auth_cmd_challenge_req req = { .flags = flags };
	struct cptra_mci_auth_cmd_challenge_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_GET_AUTH_CMD_CHALLENGE, &req.flags,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_GET_AUTH_CMD_CHALLENGE, &req, sizeof(req),
			  &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(challenge, resp.challenge, sizeof(resp.challenge));

	return 0;
}

static int mci_export_attested_csr(uint32_t device_key_id, uint32_t algorithm,
				   const uint8_t nonce[CPTRA_MCI_CSR_NONCE_SIZE],
				   uint8_t *buf, uint32_t buf_len, uint32_t *data_len)
{
	struct cptra_mci_export_csr_req req = { .device_key_id = device_key_id, .algorithm = algorithm };
	struct cptra_mci_export_csr_resp *resp;
	uint32_t resp_len, copy_len;
	int ret;

	memcpy(req.nonce, nonce, sizeof(req.nonce));

	resp = (struct cptra_mci_export_csr_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_EXPORT_ATTESTED_CSR, &req.device_key_id,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_EXPORT_ATTESTED_CSR, &req, sizeof(req),
			  resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	copy_len = resp->hdr.data_len < sizeof(resp->data) ? resp->hdr.data_len : sizeof(resp->data);
	copy_len = copy_len < buf_len ? copy_len : buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(buf, resp->data, copy_len);
	*data_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_cm_status(uint32_t *used_usage_storage, uint32_t *total_usage_storage)
{
	struct cptra_mci_cm_status_req req = { 0 };
	struct cptra_mci_cm_status_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_CM_STATUS, NULL, 0);

	ret = mci_execute(CPTRA_MCI_MBCMD_CM_STATUS, &req, sizeof(req), &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	*used_usage_storage = resp.used_usage_storage;
	*total_usage_storage = resp.total_usage_storage;

	return 0;
}

static int mci_random_stir(const uint8_t *input, uint32_t input_len)
{
	struct cptra_mci_random_stir_hdr req = { .input_size = input_len };
	struct cptra_mci_random_stir_resp resp = { 0 };
	uint32_t resp_len, csum;

	if (input_len == 0 || input_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	csum = mci_checksum(CPTRA_MCI_MBCMD_RANDOM_STIR, &req.input_size, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, input, input_len);

	return mci_execute_sg(CPTRA_MCI_MBCMD_RANDOM_STIR, &req, sizeof(req), input, input_len,
			      &resp, sizeof(resp), &resp_len);
}

static int mci_random_generate(uint32_t size, uint8_t *buf, uint32_t *data_len)
{
	struct cptra_mci_random_generate_req req = { .size = size };
	struct cptra_mci_random_generate_resp *resp;
	uint32_t resp_len, copy_len;
	int ret;

	if (size == 0 || size > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_random_generate_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_RANDOM_GENERATE, &req.size,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_RANDOM_GENERATE, &req, sizeof(req), resp, sizeof(*resp),
			  &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	copy_len = resp->hdr.data_len < size ? resp->hdr.data_len : size;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(buf, resp->data, copy_len);
	*data_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_ecdh_generate(uint8_t context[CPTRA_MCI_ECDH_CONTEXT_SIZE],
			     uint8_t exchange_data[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE])
{
	struct cptra_mci_ecdh_generate_req req = { 0 };
	struct cptra_mci_ecdh_generate_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_ECDH_GENERATE, NULL, 0);

	ret = mci_execute(CPTRA_MCI_MBCMD_ECDH_GENERATE, &req, sizeof(req), &resp, sizeof(resp),
			  &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(context, resp.context, sizeof(resp.context));
	memcpy(exchange_data, resp.exchange_data, sizeof(resp.exchange_data));

	return 0;
}

static int mci_ecdh_finish(const uint8_t context[CPTRA_MCI_ECDH_CONTEXT_SIZE], uint32_t key_usage,
			   const uint8_t incoming_exchange_data[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE],
			   uint8_t cmk_out[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_ecdh_finish_req req = { .key_usage = key_usage };
	struct cptra_mci_ecdh_finish_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	memcpy(req.context, context, sizeof(req.context));
	memcpy(req.incoming_exchange_data, incoming_exchange_data, sizeof(req.incoming_exchange_data));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_ECDH_FINISH, &req.context,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_ECDH_FINISH, &req, sizeof(req), &resp, sizeof(resp),
			  &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(cmk_out, resp.output.value, sizeof(resp.output.value));

	return 0;
}

static int mci_hmac(const uint8_t cmk[CPTRA_MCI_CMK_SIZE], uint32_t hash_algorithm,
		    const uint8_t *data, uint32_t data_len,
		    uint8_t mac[CPTRA_MCI_HMAC_MAX_SIZE], uint32_t *mac_len)
{
	struct cptra_mci_hmac_hdr req = { .hash_algorithm = hash_algorithm, .data_size = data_len };
	struct cptra_mci_hmac_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (data_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_HMAC, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, data, data_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_HMAC, &req, sizeof(req), data, data_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp.hdr))
		return -EIO;

	*mac_len = resp.hdr.data_len < sizeof(resp.mac) ? resp.hdr.data_len : sizeof(resp.mac);
	if (resp_len < sizeof(resp.hdr) + *mac_len)
		return -EIO;
	memcpy(mac, resp.mac, *mac_len);

	return 0;
}

static int mci_hmac_kdf_counter(const uint8_t kin[CPTRA_MCI_CMK_SIZE], uint32_t hash_algorithm,
				uint32_t key_usage, uint32_t key_size,
				const uint8_t *label, uint32_t label_len,
				uint8_t kout[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_hmac_kdf_counter_hdr req = {
		.hash_algorithm = hash_algorithm,
		.key_usage = key_usage,
		.key_size = key_size,
		.label_size = label_len,
	};
	struct cptra_mci_hmac_kdf_counter_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (label_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.kin.value, kin, sizeof(req.kin.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_HMAC_KDF_COUNTER, &req.kin, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, label, label_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_HMAC_KDF_COUNTER, &req, sizeof(req), label, label_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(kout, resp.kout.value, sizeof(resp.kout.value));

	return 0;
}

static int mci_hkdf_extract(uint32_t hash_algorithm, const uint8_t salt[CPTRA_MCI_CMK_SIZE],
			    const uint8_t ikm[CPTRA_MCI_CMK_SIZE], uint8_t prk[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_hkdf_extract_req req = { .hash_algorithm = hash_algorithm };
	struct cptra_mci_hkdf_extract_resp resp = { 0 };
	uint32_t resp_len;
	int ret;

	memcpy(req.salt.value, salt, sizeof(req.salt.value));
	memcpy(req.ikm.value, ikm, sizeof(req.ikm.value));

	req.hdr.chksum = mci_checksum(CPTRA_MCI_MBCMD_HKDF_EXTRACT, &req.hash_algorithm,
				      sizeof(req) - sizeof(req.hdr));

	ret = mci_execute(CPTRA_MCI_MBCMD_HKDF_EXTRACT, &req, sizeof(req), &resp, sizeof(resp),
			  &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(prk, resp.prk.value, sizeof(resp.prk.value));

	return 0;
}

static int mci_hkdf_expand(const uint8_t prk[CPTRA_MCI_CMK_SIZE], uint32_t hash_algorithm,
			   uint32_t key_usage, uint32_t key_size,
			   const uint8_t *info, uint32_t info_len, uint8_t okm[CPTRA_MCI_CMK_SIZE])
{
	struct cptra_mci_hkdf_expand_hdr req = {
		.hash_algorithm = hash_algorithm,
		.key_usage = key_usage,
		.key_size = key_size,
		.info_size = info_len,
	};
	struct cptra_mci_hkdf_expand_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (info_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.prk.value, prk, sizeof(req.prk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_HKDF_EXPAND, &req.prk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, info, info_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_HKDF_EXPAND, &req, sizeof(req), info, info_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(okm, resp.okm.value, sizeof(resp.okm.value));

	return 0;
}

static int mci_aes_encrypt_init(const uint8_t cmk[CPTRA_MCI_CMK_SIZE], uint32_t mode,
				const uint8_t *plaintext, uint32_t plaintext_len,
				uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE],
				uint8_t iv[CPTRA_MCI_AES_IV_SIZE],
				uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_encrypt_init_hdr req = { .mode = mode, .plaintext_size = plaintext_len };
	struct cptra_mci_aes_init_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (plaintext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_init_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_ENCRYPT_INIT, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, plaintext, plaintext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_ENCRYPT_INIT, &req, sizeof(req),
			     plaintext, plaintext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	memcpy(iv, resp->hdr.iv, sizeof(resp->hdr.iv));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_encrypt_update(uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE],
				  const uint8_t *plaintext, uint32_t plaintext_len,
				  uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_update_hdr req = { .size = plaintext_len };
	struct cptra_mci_aes_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (plaintext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_ENCRYPT_UPDATE, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, plaintext, plaintext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_ENCRYPT_UPDATE, &req, sizeof(req),
			     plaintext, plaintext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_decrypt_init(const uint8_t cmk[CPTRA_MCI_CMK_SIZE], uint32_t mode,
				const uint8_t iv[CPTRA_MCI_AES_IV_SIZE],
				const uint8_t *ciphertext, uint32_t ciphertext_len,
				uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE],
				uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_decrypt_init_hdr req = { .mode = mode, .ciphertext_size = ciphertext_len };
	struct cptra_mci_aes_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (ciphertext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));
	memcpy(req.iv, iv, sizeof(req.iv));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_DECRYPT_INIT, &req.cmk, sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, ciphertext, ciphertext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_DECRYPT_INIT, &req, sizeof(req),
			     ciphertext, ciphertext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_decrypt_update(uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE],
				  const uint8_t *ciphertext, uint32_t ciphertext_len,
				  uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_update_hdr req = { .size = ciphertext_len };
	struct cptra_mci_aes_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (ciphertext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_DECRYPT_UPDATE, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, ciphertext, ciphertext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_DECRYPT_UPDATE, &req, sizeof(req),
			     ciphertext, ciphertext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_gcm_encrypt_init(uint32_t flags, const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				    const uint8_t *aad, uint32_t aad_len,
				    uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE],
				    uint8_t iv[CPTRA_MCI_AES_GCM_IV_SIZE])
{
	struct cptra_mci_aes_gcm_encrypt_init_hdr req = { .flags = flags, .aad_size = aad_len };
	struct cptra_mci_aes_gcm_init_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (aad_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_INIT, &req.flags,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, aad, aad_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_INIT, &req, sizeof(req), aad, aad_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(context, resp.context, sizeof(resp.context));
	memcpy(iv, resp.iv, sizeof(resp.iv));

	return 0;
}

static int mci_aes_gcm_encrypt_update(uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE],
				      const uint8_t *plaintext, uint32_t plaintext_len,
				      uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_gcm_data_hdr req = { .size = plaintext_len };
	struct cptra_mci_aes_gcm_update_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (plaintext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_gcm_update_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_UPDATE, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, plaintext, plaintext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_UPDATE, &req, sizeof(req),
			     plaintext, plaintext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_gcm_encrypt_final(const uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE],
				     const uint8_t *plaintext, uint32_t plaintext_len,
				     uint8_t tag[CPTRA_MCI_AES_GCM_TAG_SIZE],
				     uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_gcm_data_hdr req = { .size = plaintext_len };
	struct cptra_mci_aes_gcm_encrypt_final_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (plaintext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_gcm_encrypt_final_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_FINAL, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, plaintext, plaintext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_ENCRYPT_FINAL, &req, sizeof(req),
			     plaintext, plaintext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(tag, resp->hdr.tag, sizeof(resp->hdr.tag));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

static int mci_aes_gcm_decrypt_init(uint32_t flags, const uint8_t cmk[CPTRA_MCI_CMK_SIZE],
				    const uint8_t iv[CPTRA_MCI_AES_GCM_IV_SIZE],
				    const uint8_t *aad, uint32_t aad_len,
				    uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE])
{
	struct cptra_mci_aes_gcm_decrypt_init_hdr req = { .flags = flags, .aad_size = aad_len };
	struct cptra_mci_aes_gcm_init_resp resp = { 0 };
	uint32_t resp_len, csum;
	int ret;

	if (aad_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	memcpy(req.cmk.value, cmk, sizeof(req.cmk.value));
	memcpy(req.iv, iv, sizeof(req.iv));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_INIT, &req.flags,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, aad, aad_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_INIT, &req, sizeof(req), aad, aad_len,
			     &resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	if (resp_len < sizeof(resp))
		return -EIO;

	memcpy(context, resp.context, sizeof(resp.context));

	return 0;
}

static int mci_aes_gcm_decrypt_update(uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE],
				      const uint8_t *ciphertext, uint32_t ciphertext_len,
				      uint8_t *out, uint32_t out_buf_len, uint32_t *out_len)
{
	struct cptra_mci_aes_gcm_data_hdr req = { .size = ciphertext_len };
	struct cptra_mci_aes_gcm_update_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (ciphertext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_gcm_update_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_UPDATE, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, ciphertext, ciphertext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_UPDATE, &req, sizeof(req),
			     ciphertext, ciphertext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	memcpy(context, resp->hdr.context, sizeof(resp->hdr.context));
	copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
	if (resp_len < sizeof(resp->hdr) + copy_len) {
		ret = -EIO;
		goto out;
	}
	memcpy(out, resp->output, copy_len);
	*out_len = copy_len;

out:
	free(resp);

	return ret;
}

/*
 * Returns 0 with *tag_verified=1 on a verified tag (out/out_len filled),
 * or 0 with *tag_verified=0 if the hardware explicitly rejected the tag
 * (no plaintext released) -- only a transport/protocol error returns < 0.
 */
static int mci_aes_gcm_decrypt_final(const uint8_t context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE],
				     const uint8_t tag[CPTRA_MCI_AES_GCM_TAG_SIZE],
				     const uint8_t *ciphertext, uint32_t ciphertext_len,
				     uint8_t *out, uint32_t out_buf_len, uint32_t *out_len,
				     int *tag_verified)
{
	struct cptra_mci_aes_gcm_decrypt_final_hdr req = {
		.tag_len = CPTRA_MCI_AES_GCM_TAG_SIZE,
		.ciphertext_size = ciphertext_len,
	};
	struct cptra_mci_aes_gcm_decrypt_final_resp *resp;
	uint32_t resp_len, csum, copy_len;
	int ret;

	if (ciphertext_len > CPTRA_MCI_MBOX_MAX_INPUT_SIZE)
		return -EINVAL;

	resp = (struct cptra_mci_aes_gcm_decrypt_final_resp *)malloc(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	memcpy(req.context, context, sizeof(req.context));
	memcpy(req.tag, tag, sizeof(req.tag));

	csum = mci_checksum(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_FINAL, &req.context,
			    sizeof(req) - sizeof(req.hdr));
	req.hdr.chksum = mci_checksum_ext(csum, ciphertext, ciphertext_len);

	ret = mci_execute_sg(CPTRA_MCI_MBCMD_AES_GCM_DECRYPT_FINAL, &req, sizeof(req),
			     ciphertext, ciphertext_len, resp, sizeof(*resp), &resp_len);
	if (ret)
		goto out;
	if (resp_len < sizeof(resp->hdr)) {
		ret = -EIO;
		goto out;
	}

	*tag_verified = resp->hdr.tag_verified != 0;
	if (*tag_verified) {
		copy_len = resp->hdr.output_size < out_buf_len ? resp->hdr.output_size : out_buf_len;
		if (resp_len < sizeof(resp->hdr) + copy_len) {
			ret = -EIO;
			goto out;
		}
		memcpy(out, resp->output, copy_len);
		*out_len = copy_len;
	}

out:
	free(resp);

	return ret;
}

/* ================= known-answer test vectors (from u-boot cptra_mci cmd) ================= */

static const uint8_t mci_sha384_abc_digest[CPTRA_MCI_SHA384_DIGEST_SIZE] = {
	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
	0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
	0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
	0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
};

static const uint8_t mci_sha512_abc_digest[CPTRA_MCI_SHA512_DIGEST_SIZE] = {
	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49,
	0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
	0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a,
	0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
	0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
	0xa5, 0x4c, 0xa4, 0x9f,
};

/*
 * ECDSA384 known-answer vectors: pubkey captured once from real hardware
 * from the all-zero-seed Cmk (see mci_test_ecdsa()).
 */
static const uint8_t mci_ecdsa_test_pubkey_x[CPTRA_MCI_ECC384_SCALAR_SIZE] = {
	0xd7, 0xdd, 0x94, 0xe0, 0xbf, 0xfc, 0x4c, 0xad, 0xe9, 0x90, 0x2b, 0x7f, 0xdb, 0x15, 0x42,
	0x60, 0xd5, 0xec, 0x5d, 0xfd, 0x57, 0x95, 0x0e, 0x83, 0x59, 0x01, 0x5a, 0x30, 0x2c, 0x8b,
	0xf7, 0xbb, 0xa7, 0xe5, 0xf6, 0xdf, 0xfc, 0x16, 0x85, 0x16, 0x2b, 0xdd, 0x35, 0xf9, 0xf5,
	0xc1, 0xb0, 0xff,
};

static const uint8_t mci_ecdsa_test_pubkey_y[CPTRA_MCI_ECC384_SCALAR_SIZE] = {
	0xbb, 0x9c, 0x3a, 0x2f, 0x06, 0x1e, 0x8d, 0x70, 0x14, 0x27, 0x8d, 0xd5, 0x1e, 0x66, 0xa9,
	0x18, 0xa6, 0xb6, 0xf9, 0xf1, 0xc1, 0x93, 0x73, 0x12, 0xd4, 0xe7, 0xa9, 0x21, 0xb1, 0x8e,
	0xf0, 0xf4, 0x1f, 0xdd, 0x40, 0x1d, 0x9e, 0x77, 0x18, 0x50, 0x9f, 0x87, 0x31, 0xe9, 0xee,
	0xc9, 0xc3, 0x1d,
};

/*
 * LMS known-answer vector: message/pubkey/signature pair 2/1 from caliptra-sw's
 * runtime_integration_tests/test_lms.rs; hash is SHA-384 of that message,
 * pinned here since the mailbox command takes a pre-hashed digest.
 */
static const uint8_t mci_lms_test_pubkey_id[CPTRA_MCI_LMS_PUBKEY_ID_SIZE] = {
	0x9e, 0x15, 0xd8, 0x11, 0x5f, 0x82, 0xec, 0x66, 0xc6, 0x4c, 0x9e, 0x7f, 0x10, 0x11, 0xe7,
	0xfd,
};

static const uint8_t mci_lms_test_pubkey_digest[CPTRA_MCI_LMS_PUBKEY_DIGEST_SIZE] = {
	0x4b, 0x18, 0x29, 0x4d, 0x66, 0x1d, 0xab, 0x4c, 0x40, 0x8d, 0xac, 0x0b, 0xff, 0x33, 0x89,
	0x1b, 0xcc, 0x54, 0x5e, 0xec, 0xa9, 0x53, 0x7a, 0xef,
};

#define CPTRA_MCI_LMS_TEST_SIGNATURE_Q	32153

static const uint8_t mci_lms_test_signature_ots[CPTRA_MCI_LMS_OTS_SIGNATURE_SIZE] = {
	0x00, 0x00, 0x00, 0x07, 0x59, 0x39, 0xba, 0xdc, 0xb2, 0xf4, 0x4a, 0x6a, 0xba, 0x06, 0x48,
	0x6a, 0x54, 0x26, 0x06, 0x15, 0x53, 0xf5, 0x4a, 0xf4, 0xf6, 0xfe, 0x54, 0xd2, 0xbc, 0xcb,
	0x95, 0x67, 0xc0, 0x50, 0x74, 0xa9, 0x83, 0x3e, 0xfe, 0xcd, 0x7b, 0xf0, 0x36, 0x3f, 0xb4,
	0xbd, 0x21, 0xbb, 0xad, 0x25, 0xb3, 0x2d, 0x7b, 0x23, 0x1d, 0xb9, 0xe6, 0xcc, 0x77, 0x0e,
	0xd0, 0xfc, 0x54, 0xc4, 0x38, 0x7f, 0x5a, 0x07, 0x7d, 0xf8, 0xee, 0x93, 0xf8, 0x60, 0xc7,
	0xaa, 0xfa, 0x02, 0xdd, 0x73, 0x99, 0x93, 0x19, 0x8f, 0x9d, 0xd9, 0x2b, 0xb8, 0xf1, 0x4b,
	0xad, 0x2e, 0x74, 0x18, 0x25, 0x4a, 0x3b, 0xcc, 0x04, 0x37, 0x6a, 0x59, 0x91, 0xa2, 0x55,
	0x58, 0x3d, 0x11, 0xa7, 0x8d, 0xad, 0xca, 0xd0, 0xee, 0x6b, 0x95, 0x34, 0x72, 0xa1, 0xdb,
	0x77, 0x54, 0x84, 0xd0, 0x10, 0xba, 0x31, 0xe3, 0xc4, 0xab, 0x7c, 0x61, 0xb5, 0x07, 0x3f,
	0xe8, 0x82, 0x7d, 0x65, 0xb0, 0x01, 0xd1, 0x3e, 0xc4, 0x27, 0xf2, 0x9a, 0x07, 0x3a, 0xd8,
	0x94, 0x0b, 0x1d, 0x9f, 0x4e, 0xc7, 0xd3, 0xe5, 0x72, 0x56, 0xdc, 0x50, 0x42, 0xeb, 0xa1,
	0x3a, 0x9a, 0x51, 0xa6, 0x90, 0x7e, 0x4b, 0x74, 0xda, 0xc2, 0x9e, 0x5a, 0x93, 0x1b, 0xf4,
	0x80, 0xdd, 0x6c, 0x18, 0x81, 0xac, 0xa1, 0x5e, 0x1e, 0x8b, 0x49, 0x1f, 0x56, 0x09, 0x99,
	0x00, 0xa5, 0x31, 0xcf, 0x1d, 0x6e, 0x1f, 0x79, 0x01, 0x8b, 0xb8, 0x4a, 0xc7, 0x5f, 0x3e,
	0x14, 0x36, 0x68, 0x92, 0x82, 0xf8, 0x30, 0x81, 0xfa, 0x53, 0x6e, 0x34, 0x9b, 0x61, 0xc1,
	0x47, 0x93, 0xef, 0x64, 0xa4, 0xe4, 0xf2, 0xba, 0x56, 0xfc, 0x34, 0x0f, 0xbb, 0x25, 0x84,
	0xe6, 0x08, 0xcc, 0x6a, 0xab, 0x46, 0x8b, 0x14, 0x35, 0xf1, 0x9d, 0x0d, 0xb7, 0x91, 0x49,
	0x7f, 0xfe, 0x1c, 0xc3, 0x42, 0xbf, 0x19, 0x6e, 0x68, 0xc5, 0x1d, 0x83, 0xdf, 0x46, 0xa3,
	0x92, 0x9c, 0xd6, 0xae, 0x1b, 0x55, 0x3a, 0xbf, 0x32, 0xe8, 0x90, 0xd2, 0xa8, 0xcb, 0x92,
	0xf9, 0x63, 0xc7, 0x16, 0x28, 0x52, 0x29, 0x29, 0xb8, 0xd4, 0x15, 0xa3, 0x57, 0xb5, 0x36,
	0xe9, 0xcb, 0xcd, 0x60, 0xe4, 0x14, 0xf8, 0x3e, 0x0b, 0x45, 0x0c, 0x87, 0x71, 0x5a, 0x44,
	0xc0, 0x18, 0x57, 0x32, 0x7c, 0xfb, 0xcf, 0xc5, 0xd4, 0x61, 0x73, 0x73, 0x9f, 0x90, 0x71,
	0x2e, 0x05, 0x12, 0xac, 0x04, 0x46, 0x6c, 0x4d, 0xe8, 0xc8, 0x2a, 0x1f, 0xd1, 0x93, 0x7c,
	0x81, 0x0a, 0x30, 0x4f, 0x8f, 0x9a, 0x85, 0x94, 0x4f, 0xdf, 0xd4, 0xbd, 0xa4, 0xf7, 0xbf,
	0xdc, 0x3f, 0xa9, 0xbd, 0x7b, 0x40, 0x37, 0xb9, 0xd6, 0xe7, 0xa4, 0x29, 0xae, 0x22, 0x4a,
	0x6a, 0x63, 0x15, 0x4b, 0x41, 0x74, 0x8e, 0xb7, 0x77, 0x18, 0xd9, 0x3a, 0x68, 0x89, 0x9e,
	0x14, 0xa7, 0x21, 0xa7, 0x78, 0x6a, 0x98, 0x9e, 0x73, 0x83, 0x62, 0x95, 0x6b, 0x50, 0x11,
	0xcc, 0xad, 0xfe, 0x3b, 0x18, 0xad, 0x45, 0xb5, 0x10, 0x18, 0x29, 0x3b, 0xaf, 0x2e, 0x2d,
	0xf0, 0x2d, 0x9a, 0x8a, 0x8b, 0x2d, 0x7a, 0x12, 0xd4, 0x0e, 0x94, 0xb5, 0x6f, 0x57, 0xeb,
	0xf4, 0xab, 0x96, 0x1d, 0x47, 0xb9, 0x98, 0xe4, 0xc6, 0x4d, 0x92, 0x4d, 0x75, 0x83, 0x99,
	0x98, 0x7d, 0x4b, 0x59, 0x5b, 0x94, 0xbf, 0xf3, 0x02, 0xca, 0xf6, 0xaa, 0x2a, 0x0f, 0x64,
	0x3e, 0x1a, 0x39, 0xc8, 0x3c, 0x5b, 0x50, 0xe2, 0x8f, 0xa2, 0x89, 0xf7, 0x89, 0xe8, 0xe3,
	0xf6, 0x8a, 0x2c, 0x98, 0xe0, 0xf5, 0x2c, 0xf6, 0x45, 0xa7, 0x28, 0x93, 0xe0, 0x94, 0x68,
	0x36, 0xf3, 0xfd, 0x8a, 0xa1, 0x19, 0xc1, 0xf9, 0x7a, 0xd7, 0x0f, 0x62, 0x81, 0xff, 0x65,
	0x26, 0x01, 0x07, 0x76, 0x25, 0xd9, 0x04, 0x87, 0xcf, 0x96, 0xc9, 0xf7, 0x12, 0x1f, 0x06,
	0x63, 0x52, 0xc9, 0xe5, 0x2c, 0x7c, 0xe2, 0xa6, 0xbb, 0x4e, 0x40, 0xf8, 0x23, 0x96, 0x79,
	0xc3, 0xe1, 0x15, 0x54, 0x72, 0xeb, 0xd1, 0x2e, 0xb5, 0xc7, 0x34, 0xf0, 0xa6, 0x43, 0xea,
	0x6a, 0xba, 0x04, 0x91, 0x27, 0x70, 0xae, 0xb5, 0xf2, 0x22, 0xc3, 0x33, 0x6c, 0xac, 0x1d,
	0xa0, 0xf2, 0x78, 0x83, 0x61, 0xde, 0xb1, 0xb9, 0xcc, 0x83, 0x78, 0xbc, 0x24, 0x95, 0x98,
	0x84, 0xf2, 0x54, 0x53, 0x30, 0xd5, 0x55, 0xdd, 0x07, 0xe0, 0x6a, 0x74, 0x46, 0xda, 0xfc,
	0xc7, 0x98, 0x34, 0x14, 0x3a, 0xf3, 0x78, 0xb9, 0xc6, 0xe8, 0x4a, 0xb1, 0x3d, 0xcd, 0x1d,
	0x2b, 0x5c, 0x80, 0x30, 0x74, 0x09, 0xa3, 0x96, 0x51, 0x7e, 0xbe, 0xa6, 0x7b, 0x8b, 0x64,
	0xf7, 0xf8, 0xc2, 0xd2, 0x09, 0x12, 0x6d, 0x71, 0xa7, 0x7c, 0xe9, 0x3a, 0xc9, 0x1d, 0xd9,
	0x01, 0x3d, 0xa4, 0x5b, 0x92, 0x8e, 0xd5, 0x9a, 0x1f, 0x9c, 0xd8, 0x32, 0x46, 0xaf, 0x1a,
	0xe2, 0xc1, 0xba, 0x17, 0x49, 0x21, 0xef, 0xe9, 0x43, 0x22, 0x65, 0xc5, 0x0d, 0x84, 0x5c,
	0x19, 0x4b, 0x59, 0x04, 0xd8, 0x77, 0x42, 0x27, 0xdd, 0x46, 0x6b, 0x09, 0xf7, 0xb7, 0xe5,
	0xfd, 0xe5, 0xac, 0x72, 0x9f, 0x47, 0x8c, 0x89, 0x9c, 0x58, 0x6a, 0x3f, 0xc2, 0xab, 0xa1,
	0x56, 0xc4, 0x05, 0x41, 0x2c, 0xa1, 0x17, 0xb7, 0x42, 0x3e, 0x77, 0x9d, 0x6e, 0x6c, 0xb3,
	0xd3, 0xc5, 0x44, 0xb9, 0x58, 0xdd, 0x33, 0x51, 0xf7, 0x92, 0x9d, 0x81, 0x40, 0x64, 0x4c,
	0x01, 0x53, 0x63, 0x10, 0x92, 0xf2, 0xd0, 0x08, 0x91, 0xf2, 0x84, 0x22, 0x81, 0xf6, 0x96,
	0x63, 0xea, 0xf1, 0xb2, 0x86, 0xf1, 0x96, 0x13, 0x10, 0x10, 0x5b, 0x36, 0x25, 0x46, 0x25,
	0xfc, 0xec, 0xba, 0x68, 0x37, 0x23, 0x2d, 0x71, 0x7b, 0x91, 0xd7, 0x70, 0x54, 0x78, 0x2e,
	0x97, 0x5a, 0xdc, 0x8e, 0xb8, 0xdb, 0xf7, 0x0d, 0xf8, 0x59, 0x12, 0xc0, 0xd9, 0x6f, 0x5c,
	0x2a, 0x16, 0xf4, 0x16, 0xc3, 0x82, 0xcf, 0xaa, 0xff, 0x6f, 0xdc, 0x5a, 0x46, 0x00, 0x5c,
	0x78, 0xd1, 0xfc, 0x72, 0x6f, 0xaa, 0xe9, 0x53, 0xa9, 0xf6, 0xda, 0x5f, 0x22, 0x09, 0x29,
	0x0e, 0x8a, 0xbd, 0x65, 0x16, 0xf3, 0x74, 0xa5, 0xcf, 0xa8, 0xea, 0x9f, 0x93, 0xc0, 0xcc,
	0x60, 0xf3, 0x62, 0x78, 0xb5, 0x0f, 0x2a, 0xf4, 0x6d, 0x20, 0x60, 0x59, 0x80, 0x3c, 0xcd,
	0x7e, 0xb8, 0xe1, 0x39, 0x5a, 0x2a, 0xc7, 0xb5, 0x47, 0x3e, 0xc0, 0xc7, 0xa0, 0x0a, 0x3d,
	0xb5, 0xc0, 0xdb, 0x9d, 0x40, 0x2c, 0x5f, 0xee, 0x2e, 0x34, 0xdd, 0x1b, 0x0a, 0x04, 0xd8,
	0x35, 0xf9, 0xa7, 0xc9, 0xc1, 0x00, 0xfe, 0x0e, 0x78, 0x5d, 0x4a, 0xa9, 0x69, 0x4a, 0xbb,
	0xb5, 0xe5, 0x8a, 0xb6, 0xf9, 0xe9, 0xf1, 0xcc, 0x9c, 0xd5, 0x1b, 0x30, 0x33, 0xfa, 0x4e,
	0xbd, 0xbd, 0x1b, 0x5f, 0xa1, 0x73, 0xea, 0x70, 0xfb, 0x00, 0x59, 0x67, 0x9b, 0xf3, 0x5a,
	0x33, 0x7b, 0x9b, 0xe1, 0xe5, 0xc2, 0xb8, 0xcf, 0xcc, 0xd6, 0x88, 0x5e, 0x18, 0xda, 0x02,
	0x4d, 0x1b, 0x83, 0x04, 0xac, 0x7e, 0x83, 0xfa, 0x9f, 0xde, 0x65, 0xbc, 0x9d, 0x43, 0xb3,
	0x03, 0xba, 0x03, 0xd3, 0x08, 0xad, 0x21, 0x14, 0xeb, 0x0b, 0xc3, 0x36, 0x0d, 0xba, 0x81,
	0xca, 0x29, 0x9d, 0xb5, 0xf4, 0x68, 0xd6, 0x3b, 0xec, 0xfa, 0xc3, 0xdc, 0xf2, 0x60, 0xb6,
	0xd8, 0xb9, 0xb3, 0xc6, 0x90, 0x23, 0xc7, 0x33, 0xc2, 0xa4, 0xd2, 0x04, 0x24, 0x54, 0xb2,
	0x95, 0xf1, 0xd6, 0xc0, 0x62, 0x8d, 0x11, 0x47, 0x76, 0x75, 0x5f, 0x07, 0xeb, 0x23, 0xbe,
	0xa2, 0x08, 0x8d, 0x64, 0x83, 0xca, 0x3b, 0xc2, 0x46, 0xc9, 0xdf, 0x2f, 0x06, 0x44, 0x2a,
	0x8a, 0x8c, 0xa5, 0xd9, 0xde, 0x8f, 0x3a, 0x16, 0xcb, 0x45, 0x9b, 0xfe, 0x4a, 0xb4, 0x6c,
	0xb2, 0x8a, 0x84, 0x09, 0x2b, 0x99, 0xc8, 0x63, 0xac, 0xe7, 0x85, 0xde, 0x6d, 0x01, 0x65,
	0xfe, 0x3b, 0xea, 0x06, 0xc4, 0x4e, 0x8c, 0x71, 0x7f, 0x19, 0x5a, 0x4f, 0x70, 0xb4, 0x04,
	0x22, 0xa0, 0x62, 0xad, 0x4e, 0x7f, 0xf2, 0xff, 0x76, 0x39, 0x3a, 0x6b, 0x5f, 0x56, 0x1a,
	0x41, 0x75, 0x27, 0x3e, 0xb0, 0x76, 0xe8, 0x90, 0xa7, 0xc3, 0x38, 0x79, 0xb6, 0xb0, 0xcf,
	0x88, 0xfe, 0x25, 0xd8, 0xcd, 0xea, 0x16, 0x9c, 0xb5, 0x40, 0xdd, 0x38, 0xc0, 0x21, 0x05,
	0x79, 0x91, 0xfe, 0x8e, 0x80, 0xa8, 0x5d, 0x94, 0x74, 0x5d, 0x6a, 0xe7, 0x31, 0x7b, 0x89,
	0xba, 0xa6, 0x94, 0xd3, 0x2f, 0x11, 0xd4, 0x4a, 0x21, 0x5d, 0xcb, 0x48, 0x7f, 0xab, 0x11,
	0xa1, 0x6f, 0x4b, 0x37, 0x17, 0xf1, 0x74, 0x04, 0x3a, 0x38, 0xef, 0x45, 0xe6, 0x67, 0x3c,
	0xc3, 0x28, 0x90, 0x2d, 0x22, 0x42, 0x25, 0x65, 0xe6, 0xfa, 0x5e, 0xab, 0x3e, 0xf1, 0x24,
	0xdf, 0x75, 0xc7, 0x74, 0xe8, 0x32, 0x9d, 0x28, 0x15, 0x5d, 0x7f, 0x4f, 0xfd, 0xd1, 0xa4,
	0x85, 0xad, 0x5e, 0xec, 0x8b, 0x80, 0xa5, 0x7d, 0x77, 0xd8, 0x76, 0x0a, 0x6b, 0x12, 0xe3,
	0x5e, 0x91, 0xfe, 0xc3, 0x2d, 0xb9, 0x16, 0x8d, 0xbf, 0x9f, 0xa1, 0xaf, 0x41, 0xce, 0xb4,
	0xdf, 0x9e, 0x0e, 0x7d, 0x6c, 0x63, 0x61, 0xa1, 0x63, 0x0d, 0xb8, 0xe8, 0x36, 0x73, 0x27,
	0xda, 0x46, 0x1d, 0x80, 0xe4, 0x08, 0x5c,
};

static const uint8_t mci_lms_test_signature_tree_path[CPTRA_MCI_LMS_TREE_PATH_SIZE] = {
	0x2c, 0x72, 0xd8, 0x51, 0xbf, 0x2a, 0x1e, 0xdc, 0xda, 0x01, 0xe5, 0xf7, 0x5c, 0x9c, 0xa0,
	0x2e, 0x07, 0x7f, 0xb9, 0x6b, 0x42, 0x1f, 0x9d, 0x87, 0x4a, 0xe2, 0xd3, 0x45, 0xd5, 0xe4,
	0xed, 0x1e, 0xb6, 0xc8, 0xae, 0x7f, 0xd2, 0x39, 0xd5, 0x8c, 0xff, 0xc3, 0x01, 0xb5, 0xd2,
	0x3f, 0x0d, 0x16, 0xf2, 0x0d, 0xb1, 0x13, 0xa5, 0xc9, 0xf8, 0x75, 0xe7, 0xef, 0x43, 0x89,
	0x49, 0x6d, 0x9e, 0x4f, 0xd1, 0x62, 0xca, 0xe5, 0xbf, 0xaf, 0x92, 0x81, 0x60, 0x60, 0xa8,
	0x5a, 0xac, 0xbe, 0xbc, 0xee, 0xf3, 0xbc, 0x6c, 0x87, 0xa3, 0xcd, 0x11, 0x13, 0x75, 0xbd,
	0xa5, 0xdc, 0xc6, 0xaa, 0x92, 0xa0, 0xe4, 0xf9, 0xc4, 0x00, 0xaf, 0x8f, 0x7a, 0xcd, 0xec,
	0xc4, 0x4d, 0xd4, 0xbf, 0xf1, 0x74, 0x68, 0x54, 0xcf, 0x47, 0x82, 0xaa, 0x79, 0x2a, 0xee,
	0x7e, 0x81, 0x43, 0x2b, 0xb2, 0x2e, 0x15, 0x6f, 0x76, 0x9c, 0x71, 0x7b, 0x55, 0xb1, 0x32,
	0xd1, 0xae, 0xdb, 0x90, 0x97, 0xeb, 0x0d, 0x77, 0xd9, 0xdc, 0x55, 0xbf, 0x0a, 0x7f, 0x55,
	0x1f, 0x70, 0x24, 0x1e, 0x92, 0xdc, 0x58, 0xda, 0x38, 0x0c, 0x23, 0x45, 0x8f, 0x06, 0x93,
	0xe6, 0xb5, 0xdb, 0x76, 0x38, 0x0f, 0xeb, 0xda, 0x1c, 0xbd, 0x9d, 0xd1, 0xeb, 0x4b, 0xc2,
	0x78, 0xcc, 0x8c, 0x7c, 0xaa, 0xec, 0x3b, 0x3e, 0xbd, 0x4d, 0x48, 0xcd, 0x13, 0xf3, 0x45,
	0xe8, 0xd1, 0x49, 0x83, 0x6a, 0x96, 0xe0, 0xf5, 0xaa, 0x3f, 0x25, 0xa4, 0x17, 0x93, 0x14,
	0x3f, 0x73, 0xcd, 0xd5, 0x30, 0xa4, 0x1c, 0x0a, 0x59, 0x28, 0x86, 0x06, 0x34, 0xe6, 0x3a,
	0x7e, 0xb1, 0x6c, 0x08, 0x3e, 0x6c, 0x39, 0x71, 0x77, 0x29, 0x5b, 0x13, 0x43, 0x31, 0x90,
	0x54, 0x91, 0x9b, 0x54, 0x18, 0xc2, 0xec, 0x21, 0x9c, 0xa5, 0x19, 0x7b, 0xa3, 0x80, 0x1e,
	0xbb, 0xc6, 0xf9, 0x67, 0x48, 0xfe, 0x90, 0x45, 0x9d, 0x53, 0xba, 0x33, 0x73, 0xb2, 0x29,
	0x25, 0xc6, 0x24, 0x75, 0xf5, 0x3e, 0x77, 0xf8, 0xa7, 0xfd, 0x72, 0x3e, 0x90, 0x54, 0x68,
	0xfd, 0x5c, 0x0a, 0x17, 0xce, 0x37, 0xb3, 0x1f, 0x18, 0x9b, 0x50, 0x3a, 0x6e, 0x5a, 0x2e,
	0xb0, 0xe9, 0x34, 0x0c, 0x19, 0x8d, 0x13, 0xcf, 0xfb, 0x21, 0x1f, 0xd6, 0x38, 0xaf, 0x18,
	0xe3, 0xb9, 0x55, 0x94, 0xaf, 0x5c, 0x34, 0x29, 0x6e, 0x78, 0x47, 0x05, 0x1f, 0x52, 0x32,
	0x3a, 0xb2, 0x85, 0x1e, 0xcb, 0x6f, 0x04, 0x43, 0x4c, 0x9d, 0x2e, 0x48, 0xcc, 0xf8, 0x1f,
	0xbd, 0x69, 0x63, 0xd8, 0x03, 0xdd, 0x0a, 0xd7, 0x20, 0x0c, 0x81, 0x12, 0x12, 0x04, 0x9f,
};

static const uint8_t mci_lms_test_hash[CPTRA_MCI_LMS_HASH_SIZE] = {
	0xe2, 0x20, 0xcc, 0x1d, 0x61, 0xcf, 0xd3, 0x32, 0xf9, 0xd7, 0xd2, 0x02, 0x60, 0xa5, 0xd6,
	0x39, 0x24, 0xca, 0x3c, 0xc2, 0xe8, 0x22, 0x6f, 0x4c, 0x69, 0x74, 0xad, 0x3e, 0xb4, 0x78,
	0x60, 0x17, 0x1b, 0xd2, 0xe7, 0x63, 0x33, 0x98, 0x2b, 0x0d, 0xbe, 0xe8, 0x42, 0xe1, 0x97,
	0xa4, 0x62, 0x70,
};

/* ML-DSA-87 known-answer prefix: pubkey captured once from real hardware from the all-zero-seed Cmk. */
static const uint8_t mci_mldsa_test_expected_pubkey_prefix[64] = {
	0xe4, 0x5f, 0xfc, 0x8c, 0xc7, 0x3d, 0xb8, 0x85, 0xdc, 0x66, 0x2e, 0x62, 0xa1, 0x8c, 0xd8,
	0xe3, 0x80, 0x32, 0x97, 0x11, 0x7f, 0xa5, 0x65, 0x88, 0x14, 0xa9, 0x85, 0xb5, 0xff, 0x1d,
	0xb7, 0xb4, 0x68, 0xcf, 0xc8, 0x2b, 0xb9, 0x29, 0xf1, 0xd8, 0x6b, 0x77, 0xed, 0x14, 0xf5,
	0xae, 0x16, 0xa6, 0x53, 0x68, 0x77, 0x2c, 0xe5, 0x19, 0x12, 0x41, 0x01, 0x05, 0xe0, 0x45,
	0x69, 0x75, 0xae, 0x91,
};

/*
 * RFC 4231 section 4.2/4.3 HMAC-SHA test cases 1 and 2 (from Zephyr's
 * cptra_mci_shell.c). MC_IMPORT for Hmac usage requires the raw key
 * material to be exactly 48 (SHA384) or 64 (SHA512) bytes, so the actual
 * imported key is the RFC key zero-padded out to that fixed size -- the
 * expected MACs below were captured against that padded key on real
 * hardware, not the RFC's own published value for the raw (unpadded) key.
 */
static const uint8_t mci_hmac_test_key_1[20] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const uint8_t mci_hmac_test_data_1[8] = {
	0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65, /* "Hi There" */
};

static const uint8_t mci_hmac_test_sha384_1[CPTRA_MCI_SHA384_DIGEST_SIZE] = {
	0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90,
	0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb,
	0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2,
	0xfa, 0x9c, 0xb6,
};

static const uint8_t mci_hmac_test_sha512_1[CPTRA_MCI_SHA512_DIGEST_SIZE] = {
	0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c,
	0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1,
	0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae,
	0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
	0x3a, 0x12, 0x68, 0x54,
};

static const uint8_t mci_hmac_test_key_2[4] = {
	0x4a, 0x65, 0x66, 0x65, /* "Jefe" */
};

/* "what do ya want for nothing?" */
static const uint8_t mci_hmac_test_data_2[28] = {
	0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74,
	0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
};

static const uint8_t mci_hmac_test_sha384_2[CPTRA_MCI_SHA384_DIGEST_SIZE] = {
	0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a, 0x6b,
	0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47, 0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22,
	0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa,
	0xb2, 0x16, 0x49,
};

static const uint8_t mci_hmac_test_sha512_2[CPTRA_MCI_SHA512_DIGEST_SIZE] = {
	0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0,
	0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25,
	0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8,
	0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a,
	0x38, 0xbc, 0xe7, 0x37,
};

/*
 * HMAC-KDF-Counter mode known-answer vector (from Zephyr's cptra_mci_shell.c
 * cm_hkdf_test): derives an ML-DSA cmk from a fixed Hmac384 seed key +
 * label. The derived Cmk is an opaque, encrypted blob, so correctness is
 * checked indirectly via the resulting key's ML-DSA-87 public key.
 */
static const uint8_t mci_hkdf_counter_key_in[48] = {
	0xae, 0xb0, 0xea, 0x3a, 0x4e, 0x01, 0x3f, 0xc0, 0x87, 0x0e, 0x51, 0x5a, 0x5a, 0x94, 0x0e,
	0x30, 0xc5, 0xbc, 0xca, 0x4a, 0x2a, 0x24, 0xf0, 0xb1, 0x42, 0x07, 0xa2, 0xb4, 0x37, 0xb0,
	0x32, 0x49, 0xf6, 0xcc, 0x83, 0x31, 0xa1, 0x21, 0x92, 0xf1, 0x72, 0x66, 0x38, 0xc6, 0x01,
	0x0e, 0x82, 0xf6,
};

static const uint8_t mci_hkdf_counter_label[60] = {
	0x1c, 0xbf, 0x18, 0xdd, 0x26, 0xdd, 0x65, 0xbc, 0x18, 0xa8, 0x89, 0x92, 0xce, 0x41, 0x39,
	0xad, 0x48, 0x19, 0x55, 0xe2, 0x60, 0xa7, 0xa4, 0xe7, 0xed, 0x7d, 0xb3, 0xf0, 0x0a, 0xc0,
	0xdd, 0x72, 0xc5, 0x88, 0x71, 0x37, 0x90, 0xb4, 0xf0, 0x64, 0x45, 0xcc, 0x74, 0xa5, 0x84,
	0x8d, 0xb5, 0x19, 0xea, 0x56, 0xe7, 0xf0, 0x93, 0xb6, 0x99, 0xd2, 0x4c, 0xfa, 0x54, 0x8e,
};

static const uint8_t mci_hkdf_counter_mldsa_pk[64] = {
	0x05, 0x74, 0xa8, 0xf0, 0x63, 0x71, 0x35, 0x38, 0x59, 0xe5, 0x10, 0x3c, 0x12, 0xba, 0xa4,
	0xa5, 0x62, 0x39, 0x61, 0x37, 0x24, 0x38, 0x84, 0xde, 0xd0, 0x07, 0x4f, 0x64, 0x92, 0x60,
	0xa5, 0xa4, 0x42, 0xf2, 0x21, 0x46, 0x75, 0xe6, 0xad, 0x0e, 0x8a, 0x92, 0x80, 0x7f, 0x0d,
	0x3c, 0x4b, 0x48, 0x9a, 0x47, 0xf5, 0xcf, 0x83, 0x46, 0x98, 0xa6, 0x8d, 0x87, 0x3f, 0xf4,
	0xa6, 0xd8, 0x30, 0xaa,
};

/*
 * RFC 5869 HKDF-SHA384 Extract-and-Expand known-answer vector (from
 * Zephyr's cm_hkdf_test), same self-check approach as the counter-mode
 * vector above.
 */
static const uint8_t mci_hkdf_ee_salt[48] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f,
};

static const uint8_t mci_hkdf_ee_ikm[48] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
	0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
	0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
	0x5d, 0x5e, 0x5f,
};

static const uint8_t mci_hkdf_ee_info[10] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};

static const uint8_t mci_hkdf_ee_mldsa_pk[64] = {
	0x01, 0x8f, 0xad, 0x8f, 0x72, 0x41, 0x30, 0xf7, 0x7c, 0xdb, 0xd4, 0xfa, 0xe0, 0xc2, 0x21,
	0x1f, 0x18, 0xa6, 0x2c, 0xeb, 0x15, 0x85, 0xd2, 0x35, 0xef, 0x1e, 0x22, 0x8d, 0x8e, 0x68,
	0x18, 0x84,
	0x31, 0xaa, 0xe5, 0xc9, 0x60, 0x1f, 0x42, 0x66, 0x21, 0x8d, 0x13, 0xc3, 0xed, 0xb7, 0x0d,
	0x31, 0xec, 0xb5, 0xc9, 0xf3, 0x16, 0x83, 0x2b, 0x89, 0x1a, 0xc3, 0xe2, 0x39, 0x11, 0xa2,
	0xfa, 0x4b,
};

/* ================= tests (mirrors u-boot's `cptra_mci` command family) ================= */

static int mci_test_fw_version(void)
{
	static const enum cptra_mci_fw_index indexes[] = {
		CPTRA_MCI_FW_INDEX_CALIPTRA_CORE,
		CPTRA_MCI_FW_INDEX_MCU_RUNTIME,
		CPTRA_MCI_FW_INDEX_SOC,
	};
	char version[CPTRA_MCI_MAX_FW_VERSION_STR_LEN + 1];
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(indexes); i++) {
		ret = mci_get_firmware_version(indexes[i], version, sizeof(version));
		if (ret) {
			printf("MC_FIRMWARE_VERSION (index %d) failed: %d\n", indexes[i], ret);
			return -1;
		}
		info_printf("index %d: %s\n", indexes[i], version);
	}

	return 0;
}

static int mci_reg_print(const char *label, uint32_t page, uint32_t offset)
{
	uint32_t value = 0;
	int ret;

	ret = mci_reg_read(page, offset, &value);
	if (ret) {
		printf("  %-30s 0x%04x  read failed: %d\n", label, offset, ret);
		return ret;
	}

	info_printf("  %-30s 0x%04x = 0x%08x\n", label, offset, value);

	return 0;
}

static int mci_reg_print_array(const char *label, uint32_t page,
			       uint32_t (*offset_fn)(uint32_t n), uint32_t count)
{
	char name[40];
	uint32_t i;
	int ret;

	for (i = 0; i < count; i++) {
		snprintf(name, sizeof(name), "%s[%u]", label, i);
		ret = mci_reg_print(name, page, offset_fn(i));
		if (ret)
			return ret;
	}

	return 0;
}

static uint32_t mci_mbox0_valid_axi_user_offset(uint32_t n)
{
	return CPTRA_MCI_REG_MBOX0_VALID_AXI_USER(n);
}

static uint32_t mci_mbox0_axi_user_lock_offset(uint32_t n)
{
	return CPTRA_MCI_REG_MBOX0_AXI_USER_LOCK(n);
}

static uint32_t mci_mbox1_valid_axi_user_offset(uint32_t n)
{
	return CPTRA_MCI_REG_MBOX1_VALID_AXI_USER(n);
}

static uint32_t mci_mbox1_axi_user_lock_offset(uint32_t n)
{
	return CPTRA_MCI_REG_MBOX1_AXI_USER_LOCK(n);
}

static uint32_t mci_soc_ifc_mbox_valid_axi_user_offset(uint32_t n)
{
	return CPTRA_MCI_SOC_IFC_CPTRA_MBOX_VALID_AXI_USER(n);
}

static uint32_t mci_soc_ifc_mbox_axi_user_lock_offset(uint32_t n)
{
	return CPTRA_MCI_SOC_IFC_CPTRA_MBOX_AXI_USER_LOCK(n);
}

static const char *mci_device_lifecycle_name(uint32_t val)
{
	switch (val) {
	case CPTRA_MCI_DEVICE_UNPROVISIONED:
		return "UNPROVISIONED";
	case CPTRA_MCI_DEVICE_MANUFACTURING:
		return "MANUFACTURING";
	case CPTRA_MCI_DEVICE_PRODUCTION:
		return "PRODUCTION";
	default:
		return "RESERVED";
	}
}

static int mci_test_subsystem_info(void)
{
	uint32_t value = 0, lifecycle;
	int ret;

	info_printf("\n== mci_reg (page 0x%04x) ==\n", CPTRA_MCI_REG_PAGE);

	if (mci_reg_print("MCU_IFU_AXI_USER", CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_MCU_IFU_AXI_USER))
		return -1;
	if (mci_reg_print("MCU_LSU_AXI_USER", CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_MCU_LSU_AXI_USER))
		return -1;
	if (mci_reg_print("MCU_SRAM_CONFIG_AXI_USER", CPTRA_MCI_REG_PAGE,
			  CPTRA_MCI_REG_MCU_SRAM_CONFIG_AXI_USER))
		return -1;
	if (mci_reg_print("MCI_SOC_CONFIG_AXI_USER", CPTRA_MCI_REG_PAGE,
			  CPTRA_MCI_REG_MCI_SOC_CONFIG_AXI_USER))
		return -1;

	ret = mci_reg_read(CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_RESET_REASON, &value);
	if (ret) {
		printf("  RESET_REASON: read failed: %d\n", ret);
		return -1;
	}
	info_printf("  %-30s 0x%04x = 0x%08x\n", "RESET_REASON", CPTRA_MCI_REG_RESET_REASON, value);
	info_printf("        WARM_RESET            = %u\n",
	       !!(value & CPTRA_MCI_REG_RESET_REASON_WARM_RESET));
	info_printf("        FW_BOOT_UPD_RESET     = %u\n",
	       !!(value & CPTRA_MCI_REG_RESET_REASON_FW_BOOT_UPD_RESET));
	info_printf("        FW_HITLESS_UPD_RESET  = %u\n",
	       !!(value & CPTRA_MCI_REG_RESET_REASON_FW_HITLESS_UPD_RESET));

	ret = mci_reg_read(CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_SECURITY_STATE, &value);
	if (ret) {
		printf("  SECURITY_STATE: read failed: %d\n", ret);
		return -1;
	}
	info_printf("  %-30s 0x%04x = 0x%08x\n", "SECURITY_STATE", CPTRA_MCI_REG_SECURITY_STATE, value);
	lifecycle = value & CPTRA_MCI_REG_SECURITY_STATE_DEVICE_LIFECYCLE_MASK;
	info_printf("        device_lifecycle      = %u (%s)\n", lifecycle,
	       mci_device_lifecycle_name(lifecycle));
	info_printf("        debug_locked          = %u\n",
	       !!(value & CPTRA_MCI_REG_SECURITY_STATE_DEBUG_LOCKED));
	info_printf("        scan_mode             = %u\n",
	       !!(value & CPTRA_MCI_REG_SECURITY_STATE_SCAN_MODE));

	if (mci_reg_print_array("MBOX0_VALID_AXI_USER", CPTRA_MCI_REG_PAGE,
				mci_mbox0_valid_axi_user_offset, CPTRA_MCI_REG_MBOX_AXI_USER_COUNT))
		return -1;
	if (mci_reg_print_array("MBOX0_AXI_USER_LOCK", CPTRA_MCI_REG_PAGE,
				mci_mbox0_axi_user_lock_offset, CPTRA_MCI_REG_MBOX_AXI_USER_COUNT))
		return -1;
	if (mci_reg_print_array("MBOX1_VALID_AXI_USER", CPTRA_MCI_REG_PAGE,
				mci_mbox1_valid_axi_user_offset, CPTRA_MCI_REG_MBOX_AXI_USER_COUNT))
		return -1;
	if (mci_reg_print_array("MBOX1_AXI_USER_LOCK", CPTRA_MCI_REG_PAGE,
				mci_mbox1_axi_user_lock_offset, CPTRA_MCI_REG_MBOX_AXI_USER_COUNT))
		return -1;

	if (mci_reg_print("SS_DEBUG_INTENT", CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_SS_DEBUG_INTENT))
		return -1;
	if (mci_reg_print("SS_CONFIG_DONE_STICKY", CPTRA_MCI_REG_PAGE,
			  CPTRA_MCI_REG_SS_CONFIG_DONE_STICKY))
		return -1;
	if (mci_reg_print("SS_CONFIG_DONE", CPTRA_MCI_REG_PAGE, CPTRA_MCI_REG_SS_CONFIG_DONE))
		return -1;

	info_printf("\n== soc_ifc_reg (page 0x%04x) ==\n", CPTRA_MCI_SOC_IFC_PAGE);

	ret = mci_reg_read(CPTRA_MCI_SOC_IFC_PAGE, CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON, &value);
	if (ret) {
		printf("  CPTRA_RESET_REASON: read failed: %d\n", ret);
		return -1;
	}
	info_printf("  %-30s 0x%04x = 0x%08x\n", "CPTRA_RESET_REASON",
	       CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON, value);
	info_printf("        WARM_RESET            = %u\n",
	       !!(value & CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON_WARM_RESET));
	info_printf("        FW_UPD_RESET          = %u\n",
	       !!(value & CPTRA_MCI_SOC_IFC_CPTRA_RESET_REASON_FW_UPD_RESET));

	ret = mci_reg_read(CPTRA_MCI_SOC_IFC_PAGE, CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE, &value);
	if (ret) {
		printf("  CPTRA_SECURITY_STATE: read failed: %d\n", ret);
		return -1;
	}
	info_printf("  %-30s 0x%04x = 0x%08x\n", "CPTRA_SECURITY_STATE",
	       CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE, value);
	lifecycle = value & CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_DEVICE_LIFECYCLE_MASK;
	info_printf("        device_lifecycle      = %u (%s)\n", lifecycle,
	       mci_device_lifecycle_name(lifecycle));
	info_printf("        debug_locked          = %u\n",
	       !!(value & CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_DEBUG_LOCKED));
	info_printf("        scan_mode             = %u\n",
	       !!(value & CPTRA_MCI_SOC_IFC_CPTRA_SECURITY_STATE_SCAN_MODE));

	if (mci_reg_print_array("CPTRA_MBOX_VALID_AXI_USER", CPTRA_MCI_SOC_IFC_PAGE,
				mci_soc_ifc_mbox_valid_axi_user_offset,
				CPTRA_MCI_SOC_IFC_MBOX_AXI_USER_COUNT))
		return -1;
	if (mci_reg_print_array("CPTRA_MBOX_AXI_USER_LOCK", CPTRA_MCI_SOC_IFC_PAGE,
				mci_soc_ifc_mbox_axi_user_lock_offset,
				CPTRA_MCI_SOC_IFC_MBOX_AXI_USER_COUNT))
		return -1;
	if (mci_reg_print("CPTRA_TRNG_VALID_AXI_USER", CPTRA_MCI_SOC_IFC_PAGE,
			  CPTRA_MCI_SOC_IFC_CPTRA_TRNG_VALID_AXI_USER))
		return -1;
	if (mci_reg_print("CPTRA_TRNG_AXI_USER_LOCK", CPTRA_MCI_SOC_IFC_PAGE,
			  CPTRA_MCI_SOC_IFC_CPTRA_TRNG_AXI_USER_LOCK))
		return -1;
	if (mci_reg_print("CPTRA_FUSE_VALID_AXI_USER", CPTRA_MCI_SOC_IFC_PAGE,
			  CPTRA_MCI_SOC_IFC_CPTRA_FUSE_VALID_AXI_USER))
		return -1;

	return 0;
}

static int mci_sha_test_one(uint32_t algo, const char *label, const uint8_t *expected,
			    size_t expected_len)
{
	uint8_t digest[CPTRA_MCI_SHA512_DIGEST_SIZE];
	int ret;

	ret = mci_sha_digest(algo, (const uint8_t *)"abc", 3, (uint32_t)expected_len, digest);
	if (ret) {
		printf("%s: hash failed: %d\n", label, ret);
		return -1;
	}

	if (memcmp(digest, expected, expected_len) != 0) {
		printf("%s: \033[1;31mFAIL\033[0m (digest does not match known-answer vector)\n", label);
		return -1;
	}

	info_printf("%s: \033[1;32mPASS\033[0m\n", label);

	return 0;
}

static int mci_test_sha(void)
{
	if (mci_sha_test_one(CPTRA_MCI_SHA_ALGO_SHA384, "SHA384(\"abc\")",
			     mci_sha384_abc_digest, sizeof(mci_sha384_abc_digest)))
		return -1;

	if (mci_sha_test_one(CPTRA_MCI_SHA_ALGO_SHA512, "SHA512(\"abc\")",
			     mci_sha512_abc_digest, sizeof(mci_sha512_abc_digest)))
		return -1;

	return 0;
}

/*
 * Merged raw-pubkey signature-verify known-answer test (mirrors Zephyr's
 * cptra_mci_shell.c cmd_cptra_mci_sig_verify_test): three independent
 * blocks, ECDSA384 / ML-DSA-87 / LMS, each positive + negative case.
 *
 * ECDSA384 and ML-DSA-87 blocks: Caliptra-SS exposes no on-device signing
 * for a raw public key directly, only the Cmk-managed CM_*_CMK_SIGN --
 * self-generate a signature via that (all-zero seed), then verify through
 * the raw-pubkey MC_ECDSA384_SIG_VERIFY / MC_MLDSA87_SIG_VERIFY.
 *
 * LMS block: LMS keys are generated offline and Caliptra-SS exposes no
 * on-device LMS signing, so this borrows a real vector already known to
 * verify successfully against Caliptra-SS hardware.
 */
static int mci_test_sig_verify(void)
{
	int ret;

	/* -------- ECDSA384 -------- */
	{
		static const uint8_t seed[CPTRA_MCI_ECC384_SCALAR_SIZE] = { 0 };
		uint8_t message[CPTRA_MCI_ECC384_SCALAR_SIZE];
		uint8_t cmk[CPTRA_MCI_CMK_SIZE];
		uint8_t qx[CPTRA_MCI_ECC384_SCALAR_SIZE], qy[CPTRA_MCI_ECC384_SCALAR_SIZE];
		uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE], s[CPTRA_MCI_ECC384_SCALAR_SIZE];
		uint8_t hash[CPTRA_MCI_SHA384_DIGEST_SIZE], bad_hash[CPTRA_MCI_SHA384_DIGEST_SIZE];
		int i;

		ret = mci_import_key(CPTRA_MCI_KEY_USAGE_ECDSA, seed, sizeof(seed), cmk);
		if (ret) {
			printf("MC_IMPORT failed: %d\n", ret);
			return -1;
		}

		ret = mci_ecdsa_cmk_public_key(cmk, qx, qy);
		if (ret) {
			printf("MC_ECDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
			return -1;
		}

		if (memcmp(qx, mci_ecdsa_test_pubkey_x, sizeof(qx)) != 0 ||
		    memcmp(qy, mci_ecdsa_test_pubkey_y, sizeof(qy)) != 0) {
			printf("MC_ECDSA_CMK_PUBLIC_KEY: \033[1;31mFAIL\033[0m (public key mismatch)\n");
			return -1;
		}
		dbg_printf("MC_ECDSA_CMK_PUBLIC_KEY: \033[1;32mPASS\033[0m (matches known-answer vector)\n");

		for (i = 0; i < (int)sizeof(message); i++)
			message[i] = (uint8_t)i;

		ret = mci_ecdsa_cmk_sign(cmk, message, sizeof(message), r, s);
		if (ret) {
			printf("MC_ECDSA_CMK_SIGN failed: %d\n", ret);
			return -1;
		}

		ret = mci_sha_digest(CPTRA_MCI_SHA_ALGO_SHA384, message, sizeof(message),
				     sizeof(hash), hash);
		if (ret) {
			printf("SHA384(message) failed: %d\n", ret);
			return -1;
		}

		ret = mci_ecdsa384_verify(qx, qy, r, s, hash);
		if (ret) {
			printf("MC_ECDSA384_SIG_VERIFY positive case \033[1;31mFAIL\033[0m (expected \033[1;32mPASS\033[0m): %d\n", ret);
			return -1;
		}
		dbg_printf("MC_ECDSA384_SIG_VERIFY positive case: \033[1;32mPASS\033[0m (agrees with the Cmk-based signature)\n");

		memcpy(bad_hash, hash, sizeof(hash));
		bad_hash[0] ^= 0xff;

		ret = mci_ecdsa384_verify(qx, qy, r, s, bad_hash);
		if (ret == 0) {
			printf("MC_ECDSA384_SIG_VERIFY negative case \033[1;31mFAIL\033[0m (tampered digest accepted!)\n");
			return -1;
		}
		dbg_printf("MC_ECDSA384_SIG_VERIFY negative case: \033[1;32mPASS\033[0m (tampered digest correctly rejected)\n");

		info_printf("MC_ECDSA384: \033[1;32mPASS\033[0m\n");
	}

	/* -------- ML-DSA-87 -------- */
	{
		static const uint8_t seed[32] = { 0 };
		static uint8_t pub_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE];
		static uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE];
		uint8_t cmk[CPTRA_MCI_CMK_SIZE];
		uint8_t message[CPTRA_MCI_ECC384_SCALAR_SIZE], bad_message[CPTRA_MCI_ECC384_SCALAR_SIZE];
		int i;

		ret = mci_import_key(CPTRA_MCI_KEY_USAGE_MLDSA, seed, sizeof(seed), cmk);
		if (ret) {
			printf("MC_IMPORT failed: %d\n", ret);
			return -1;
		}

		ret = mci_mldsa_cmk_public_key(cmk, pub_key);
		if (ret) {
			printf("MC_MLDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
			return -1;
		}

		if (memcmp(pub_key, mci_mldsa_test_expected_pubkey_prefix,
			   sizeof(mci_mldsa_test_expected_pubkey_prefix)) != 0) {
			printf("MC_MLDSA_CMK_PUBLIC_KEY: \033[1;31mFAIL\033[0m (public key mismatch)\n");
			return -1;
		}
		dbg_printf("MC_MLDSA_CMK_PUBLIC_KEY: \033[1;32mPASS\033[0m (matches known-answer vector prefix)\n");

		for (i = 0; i < (int)sizeof(message); i++)
			message[i] = (uint8_t)i;

		ret = mci_mldsa_cmk_sign(cmk, message, sizeof(message), signature);
		if (ret) {
			printf("MC_MLDSA_CMK_SIGN failed: %d\n", ret);
			return -1;
		}

		ret = mci_mldsa87_verify(pub_key, signature, message, sizeof(message));
		if (ret) {
			printf("MC_MLDSA87_SIG_VERIFY positive case \033[1;31mFAIL\033[0m (expected \033[1;32mPASS\033[0m): %d\n", ret);
			return -1;
		}
		dbg_printf("MC_MLDSA87_SIG_VERIFY positive case: \033[1;32mPASS\033[0m (agrees with the Cmk-based signature)\n");

		memcpy(bad_message, message, sizeof(message));
		bad_message[0] ^= 0xff;

		ret = mci_mldsa87_verify(pub_key, signature, bad_message, sizeof(bad_message));
		if (ret == 0) {
			printf("MC_MLDSA87_SIG_VERIFY negative case \033[1;31mFAIL\033[0m (tampered message accepted!)\n");
			return -1;
		}
		dbg_printf("MC_MLDSA87_SIG_VERIFY negative case: \033[1;32mPASS\033[0m (tampered message correctly rejected)\n");

		info_printf("MC_MLDSA87: \033[1;32mPASS\033[0m\n");
	}

	/* -------- LMS -------- */
	{
		uint8_t hash[CPTRA_MCI_LMS_HASH_SIZE];

		memcpy(hash, mci_lms_test_hash, sizeof(hash));

		ret = mci_lms_verify(CPTRA_MCI_LMS_TREE_TYPE_FIXED, CPTRA_MCI_LMS_OTS_TYPE_FIXED,
				     mci_lms_test_pubkey_id, mci_lms_test_pubkey_digest,
				     CPTRA_MCI_LMS_TEST_SIGNATURE_Q, mci_lms_test_signature_ots,
				     CPTRA_MCI_LMS_TREE_TYPE_FIXED, mci_lms_test_signature_tree_path,
				     hash);
		if (ret) {
			printf("MC_LMS_SIG_VERIFY positive case \033[1;31mFAIL\033[0m (expected \033[1;32mPASS\033[0m): %d\n", ret);
			return -1;
		}
		dbg_printf("MC_LMS_SIG_VERIFY positive case: \033[1;32mPASS\033[0m\n");

		hash[0] ^= 0xff;

		ret = mci_lms_verify(CPTRA_MCI_LMS_TREE_TYPE_FIXED, CPTRA_MCI_LMS_OTS_TYPE_FIXED,
				     mci_lms_test_pubkey_id, mci_lms_test_pubkey_digest,
				     CPTRA_MCI_LMS_TEST_SIGNATURE_Q, mci_lms_test_signature_ots,
				     CPTRA_MCI_LMS_TREE_TYPE_FIXED, mci_lms_test_signature_tree_path,
				     hash);
		if (ret == 0) {
			printf("MC_LMS_SIG_VERIFY negative case \033[1;31mFAIL\033[0m (a tampered digest was accepted!)\n");
			return -1;
		}
		dbg_printf("MC_LMS_SIG_VERIFY negative case: \033[1;32mPASS\033[0m (tampered digest correctly rejected)\n");

		info_printf("MC_LMS: \033[1;32mPASS\033[0m\n");
	}

	return 0;
}

/*
 * MC_ECDSA_CMK_VERIFY known-answer test. Unlike sig_verify_test's raw-pubkey
 * MC_ECDSA384_SIG_VERIFY, this stays entirely inside the Cmk-managed API --
 * verifies against the opaque Cmk handle directly, no qx/qy ever leave the
 * device.
 */
static int mci_test_cm_ecdsa_verify(void)
{
	static const uint8_t seed[CPTRA_MCI_ECC384_SCALAR_SIZE] = { 0 };
	uint8_t message[CPTRA_MCI_ECC384_SCALAR_SIZE], bad_message[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t cmk[CPTRA_MCI_CMK_SIZE];
	uint8_t qx[CPTRA_MCI_ECC384_SCALAR_SIZE], qy[CPTRA_MCI_ECC384_SCALAR_SIZE];
	uint8_t r[CPTRA_MCI_ECC384_SCALAR_SIZE], s[CPTRA_MCI_ECC384_SCALAR_SIZE];
	int ret, i;

	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_ECDSA, seed, sizeof(seed), cmk);
	if (ret) {
		printf("MC_IMPORT failed: %d\n", ret);
		return -1;
	}

	ret = mci_ecdsa_cmk_public_key(cmk, qx, qy);
	if (ret) {
		printf("MC_ECDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
		return -1;
	}

	if (memcmp(qx, mci_ecdsa_test_pubkey_x, sizeof(qx)) != 0 ||
	    memcmp(qy, mci_ecdsa_test_pubkey_y, sizeof(qy)) != 0) {
		printf("MC_ECDSA_CMK_PUBLIC_KEY: \033[1;31mFAIL\033[0m (public key mismatch)\n");
		return -1;
	}
	dbg_printf("MC_ECDSA_CMK_PUBLIC_KEY: \033[1;32mPASS\033[0m (matches known-answer vector)\n");

	for (i = 0; i < (int)sizeof(message); i++)
		message[i] = (uint8_t)i;

	ret = mci_ecdsa_cmk_sign(cmk, message, sizeof(message), r, s);
	if (ret) {
		printf("MC_ECDSA_CMK_SIGN failed: %d\n", ret);
		return -1;
	}

	ret = mci_ecdsa_cmk_verify(cmk, r, s, message, sizeof(message));
	if (ret) {
		printf("MC_ECDSA_CMK_VERIFY positive case \033[1;31mFAIL\033[0m (expected \033[1;32mPASS\033[0m): %d\n", ret);
		return -1;
	}
	dbg_printf("MC_ECDSA_CMK_VERIFY positive case: \033[1;32mPASS\033[0m\n");

	memcpy(bad_message, message, sizeof(message));
	bad_message[0] ^= 0xff;

	ret = mci_ecdsa_cmk_verify(cmk, r, s, bad_message, sizeof(bad_message));
	if (ret == 0) {
		printf("MC_ECDSA_CMK_VERIFY negative case \033[1;31mFAIL\033[0m (tampered message accepted!)\n");
		return -1;
	}
	dbg_printf("MC_ECDSA_CMK_VERIFY negative case: \033[1;32mPASS\033[0m (tampered message correctly rejected)\n");

	return 0;
}

/* MC_MLDSA_CMK_VERIFY known-answer test -- Cmk-managed counterpart to sig_verify_test's ML-DSA block. */
static int mci_test_cm_mldsa_verify(void)
{
	static const uint8_t seed[32] = { 0 };
	static uint8_t pub_key[CPTRA_MCI_MLDSA87_PUBKEY_SIZE];
	static uint8_t signature[CPTRA_MCI_MLDSA87_SIGNATURE_SIZE];
	uint8_t cmk[CPTRA_MCI_CMK_SIZE];
	uint8_t message[CPTRA_MCI_ECC384_SCALAR_SIZE], bad_message[CPTRA_MCI_ECC384_SCALAR_SIZE];
	int ret, i;

	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_MLDSA, seed, sizeof(seed), cmk);
	if (ret) {
		printf("MC_IMPORT failed: %d\n", ret);
		return -1;
	}

	ret = mci_mldsa_cmk_public_key(cmk, pub_key);
	if (ret) {
		printf("MC_MLDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
		return -1;
	}

	if (memcmp(pub_key, mci_mldsa_test_expected_pubkey_prefix,
		   sizeof(mci_mldsa_test_expected_pubkey_prefix)) != 0) {
		printf("MC_MLDSA_CMK_PUBLIC_KEY: \033[1;31mFAIL\033[0m (public key mismatch)\n");
		return -1;
	}
	dbg_printf("MC_MLDSA_CMK_PUBLIC_KEY: \033[1;32mPASS\033[0m (matches known-answer vector prefix)\n");

	for (i = 0; i < (int)sizeof(message); i++)
		message[i] = (uint8_t)i;

	ret = mci_mldsa_cmk_sign(cmk, message, sizeof(message), signature);
	if (ret) {
		printf("MC_MLDSA_CMK_SIGN failed: %d\n", ret);
		return -1;
	}

	ret = mci_mldsa_cmk_verify(cmk, signature, message, sizeof(message));
	if (ret) {
		printf("MC_MLDSA_CMK_VERIFY positive case \033[1;31mFAIL\033[0m (expected \033[1;32mPASS\033[0m): %d\n", ret);
		return -1;
	}
	dbg_printf("MC_MLDSA_CMK_VERIFY positive case: \033[1;32mPASS\033[0m\n");

	memcpy(bad_message, message, sizeof(message));
	bad_message[0] ^= 0xff;

	ret = mci_mldsa_cmk_verify(cmk, signature, bad_message, sizeof(bad_message));
	if (ret == 0) {
		printf("MC_MLDSA_CMK_VERIFY negative case \033[1;31mFAIL\033[0m (tampered message accepted!)\n");
		return -1;
	}
	dbg_printf("MC_MLDSA_CMK_VERIFY negative case: \033[1;32mPASS\033[0m (tampered message correctly rejected)\n");

	return 0;
}

static void dbg_hexdump(const uint8_t *buf, uint32_t len, const char *label)
{
	uint32_t i;

	info_printf("%s (%u bytes)\n", label, len);
	for (i = 0; i < len; i++) {
		info_printf("%02x", buf[i]);
		if ((i & 0x1f) == 0x1f || i == len - 1)
			info_printf("\n");
	}
}

static int mci_test_device_caps(void)
{
	uint8_t caps[CPTRA_MCI_DEVICE_CAPS_SIZE];
	int ret;

	ret = mci_get_device_capabilities(caps);
	if (ret) {
		printf("MC_DEVICE_CAPABILITIES failed: %d\n", ret);
		return -1;
	}

	dbg_hexdump(caps, sizeof(caps), "device_caps:");
	info_printf("MC_DEVICE_CAPABILITIES: \033[1;32mPASS\033[0m\n");

	return 0;
}

static int mci_test_cm_status(void)
{
	uint32_t used = 0, total = 0;
	int ret;

	ret = mci_cm_status(&used, &total);
	if (ret) {
		printf("MC_CM_STATUS failed: %d\n", ret);
		return -1;
	}

	info_printf("used_usage_storage=%u total_usage_storage=%u\n", used, total);
	info_printf("MC_CM_STATUS: \033[1;32mPASS\033[0m\n");

	return 0;
}

/* Disabled in mci_tests[] below -- kept available for when MC_GET_LOG is ready. */
static int __attribute__((unused)) mci_test_get_log(void)
{
	static uint8_t buf[CPTRA_MCI_MAX_RESP_DATA_SIZE];
	uint32_t data_len = 0;
	int ret;

	ret = mci_get_log(CPTRA_MCI_LOG_TYPE_DEBUG, buf, sizeof(buf), &data_len);
	if (ret) {
		printf("MC_GET_LOG failed: %d\n", ret);
		return -1;
	}

	info_printf("log data_len=%u\n", data_len);
	dbg_hexdump(buf, data_len < 256 ? data_len : 256, "get_log (first 256B):");
	info_printf("MC_GET_LOG: \033[1;32mPASS\033[0m\n");

	return 0;
}

/* Disabled in mci_tests[] below -- kept available for when MC_CLEAR_LOG is ready. */
static int __attribute__((unused)) mci_test_clear_log(void)
{
	int ret;

	ret = mci_clear_log(CPTRA_MCI_LOG_TYPE_DEBUG);
	if (ret) {
		printf("MC_CLEAR_LOG failed: %d\n", ret);
		return -1;
	}

	info_printf("MC_CLEAR_LOG: \033[1;32mPASS\033[0m\n");

	return 0;
}

static int mci_test_auth_challenge(void)
{
	uint8_t challenge[CPTRA_MCI_AUTH_CHALLENGE_SIZE];
	int ret;

	ret = mci_get_auth_cmd_challenge(0, challenge);
	if (ret) {
		printf("MC_GET_AUTH_CMD_CHALLENGE failed: %d\n", ret);
		return -1;
	}

	dbg_hexdump(challenge, sizeof(challenge), "auth_challenge:");
	info_printf("MC_GET_AUTH_CMD_CHALLENGE: \033[1;32mPASS\033[0m\n");

	return 0;
}

/* Disabled in mci_tests[] below -- kept available for when MC_EXPORT_ATTESTED_CSR is ready. */
static int __attribute__((unused)) mci_test_export_csr(void)
{
	static uint8_t buf[CPTRA_MCI_MAX_RESP_DATA_SIZE];
	uint8_t nonce[CPTRA_MCI_CSR_NONCE_SIZE] = { 0 };
	uint32_t data_len = 0;
	int ret;

	ret = mci_export_attested_csr(CPTRA_MCI_CSR_KEY_RT_ALIAS, CPTRA_MCI_CSR_ALGO_ECC384, nonce,
				      buf, sizeof(buf), &data_len);
	if (ret) {
		printf("MC_EXPORT_ATTESTED_CSR failed: %d\n", ret);
		return -1;
	}

	info_printf("csr data_len=%u\n", data_len);
	dbg_hexdump(buf, data_len < 256 ? data_len : 256, "export_csr (first 256B):");
	info_printf("MC_EXPORT_ATTESTED_CSR: \033[1;32mPASS\033[0m\n");

	return 0;
}

/*
 * MC_RANDOM_STIR + MC_RANDOM_GENERATE statistical sanity test (see
 * caliptra-mcu-sw's cm_trng_test, also ported to zephyr-mcu-runtime's
 * cptra_mci_shell.c): stirs a fixed seed, then generates a run of
 * fixed-size chunks and checks that no chunk repeats another chunk within
 * a trailing window -- not a full NIST randomness test suite, but enough
 * to catch a stuck/degenerate CSRNG (no KAT: output is non-deterministic
 * by design).
 */
#define MCI_TRNG_TEST_CHUNK_SIZE	64
#define MCI_TRNG_TEST_WINDOW		10
#define MCI_TRNG_TEST_ITERATIONS	100

static int mci_test_trng(void)
{
	static uint8_t window[MCI_TRNG_TEST_CHUNK_SIZE * MCI_TRNG_TEST_WINDOW];
	uint8_t seed[32];
	uint32_t out_len;
	int ret, i, j;

	for (i = 0; i < (int)sizeof(seed); i++)
		seed[i] = (uint8_t)(i * 7 + 1);

	ret = mci_random_stir(seed, sizeof(seed));
	if (ret) {
		printf("MC_RANDOM_STIR failed: %d\n", ret);
		return -1;
	}
	info_printf("MC_RANDOM_STIR: \033[1;32mPASS\033[0m\n");

	for (i = 0; i < MCI_TRNG_TEST_ITERATIONS; i++) {
		int offset = (i % MCI_TRNG_TEST_WINDOW) * MCI_TRNG_TEST_CHUNK_SIZE;

		ret = mci_random_generate(MCI_TRNG_TEST_CHUNK_SIZE, &window[offset], &out_len);
		if (ret) {
			printf("MC_RANDOM_GENERATE failed at iteration %d: %d\n", i, ret);
			return -1;
		}
		if (out_len != MCI_TRNG_TEST_CHUNK_SIZE) {
			printf("MC_RANDOM_GENERATE: \033[1;31mFAIL\033[0m (iteration %d: expected %d bytes, got %u)\n",
			       i, MCI_TRNG_TEST_CHUNK_SIZE, out_len);
			return -1;
		}

		if (i < MCI_TRNG_TEST_WINDOW - 1)
			continue; /* let the TRNG warm up before checking for repeats */

		for (j = 0; j < MCI_TRNG_TEST_WINDOW - 1; j++) {
			int cmp_offset = ((i - j - 1) % MCI_TRNG_TEST_WINDOW) * MCI_TRNG_TEST_CHUNK_SIZE;

			if (memcmp(&window[offset], &window[cmp_offset], MCI_TRNG_TEST_CHUNK_SIZE) == 0) {
				printf("MC_RANDOM_GENERATE: \033[1;31mFAIL\033[0m (output at iteration %d repeats output from iteration %d)\n",
				       i, i - j - 1);
				return -1;
			}
		}
	}

	info_printf("MC_RANDOM_GENERATE: \033[1;32mPASS\033[0m (%d chunks of %d bytes, no repeats within a %d-chunk window)\n",
	       MCI_TRNG_TEST_ITERATIONS, MCI_TRNG_TEST_CHUNK_SIZE, MCI_TRNG_TEST_WINDOW);

	return 0;
}

static int mci_hmac_test_run(const char *label, uint32_t algo, size_t key_len, const uint8_t *key,
			     const uint8_t *data, size_t data_len,
			     const uint8_t *expected_mac, size_t expected_mac_len)
{
	uint8_t padded_key[64] = { 0 };
	uint8_t cmk[CPTRA_MCI_CMK_SIZE];
	uint8_t mac[CPTRA_MCI_HMAC_MAX_SIZE];
	uint32_t mac_len;
	int ret;

	memcpy(padded_key, key, key_len);

	/* The fixed Hmac import size happens to equal the digest size (48/64), which is expected_mac_len here. */
	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_HMAC, padded_key, expected_mac_len, cmk);
	if (ret) {
		printf("%s: MC_IMPORT failed: %d\n", label, ret);
		return -1;
	}

	ret = mci_hmac(cmk, algo, data, (uint32_t)data_len, mac, &mac_len);
	if (ret) {
		printf("%s: MC_HMAC failed: %d\n", label, ret);
		return -1;
	}

	if (mac_len != expected_mac_len || memcmp(mac, expected_mac, expected_mac_len) != 0) {
		printf("%s: \033[1;31mFAIL\033[0m (MAC does not match known-answer vector)\n", label);
		return -1;
	}

	dbg_printf("%s: \033[1;32mPASS\033[0m\n", label);

	return 0;
}

/* MC_HMAC known-answer test: RFC 4231 section 4.2/4.3 test cases 1 and 2, SHA384 + SHA512. */
static int mci_test_hmac(void)
{
	if (mci_hmac_test_run("RFC4231#1/SHA384", CPTRA_MCI_SHA_ALGO_SHA384,
			      sizeof(mci_hmac_test_key_1), mci_hmac_test_key_1,
			      mci_hmac_test_data_1, sizeof(mci_hmac_test_data_1),
			      mci_hmac_test_sha384_1, sizeof(mci_hmac_test_sha384_1)))
		return -1;

	if (mci_hmac_test_run("RFC4231#1/SHA512", CPTRA_MCI_SHA_ALGO_SHA512,
			      sizeof(mci_hmac_test_key_1), mci_hmac_test_key_1,
			      mci_hmac_test_data_1, sizeof(mci_hmac_test_data_1),
			      mci_hmac_test_sha512_1, sizeof(mci_hmac_test_sha512_1)))
		return -1;

	if (mci_hmac_test_run("RFC4231#2/SHA384", CPTRA_MCI_SHA_ALGO_SHA384,
			      sizeof(mci_hmac_test_key_2), mci_hmac_test_key_2,
			      mci_hmac_test_data_2, sizeof(mci_hmac_test_data_2),
			      mci_hmac_test_sha384_2, sizeof(mci_hmac_test_sha384_2)))
		return -1;

	if (mci_hmac_test_run("RFC4231#2/SHA512", CPTRA_MCI_SHA_ALGO_SHA512,
			      sizeof(mci_hmac_test_key_2), mci_hmac_test_key_2,
			      mci_hmac_test_data_2, sizeof(mci_hmac_test_data_2),
			      mci_hmac_test_sha512_2, sizeof(mci_hmac_test_sha512_2)))
		return -1;

	info_printf("MC_HMAC: \033[1;32mPASS\033[0m (all 4 RFC 4231 known-answer cases matched)\n");

	return 0;
}

/*
 * Caliptra-SS's key-derivation validation accepts exactly one key_size per
 * (key_usage, hash_algorithm) pair: Aes/Mldsa -> 32, Ecdsa -> 48,
 * Hmac+Sha384 -> 48, Hmac+Sha512 -> 64.
 */
static uint32_t mci_kdf_key_size(enum cptra_mci_key_usage usage, uint32_t algo)
{
	switch (usage) {
	case CPTRA_MCI_KEY_USAGE_AES:
	case CPTRA_MCI_KEY_USAGE_MLDSA:
		return 32;
	case CPTRA_MCI_KEY_USAGE_ECDSA:
		return 48;
	case CPTRA_MCI_KEY_USAGE_HMAC:
		return (algo == CPTRA_MCI_SHA_ALGO_SHA512) ? 64 : 48;
	default:
		return 0;
	}
}

/* MC_HMAC_KDF_COUNTER / MC_HKDF_EXTRACT+EXPAND known-answer test. */
static int mci_test_hkdf(void)
{
	static uint8_t pubkey[CPTRA_MCI_MLDSA87_PUBKEY_SIZE];
	uint8_t kin[CPTRA_MCI_CMK_SIZE], kout[CPTRA_MCI_CMK_SIZE];
	uint8_t salt[CPTRA_MCI_CMK_SIZE], ikm[CPTRA_MCI_CMK_SIZE], prk[CPTRA_MCI_CMK_SIZE];
	uint32_t key_size;
	int ret;

	key_size = mci_kdf_key_size(CPTRA_MCI_KEY_USAGE_MLDSA, CPTRA_MCI_SHA_ALGO_SHA384);

	/* HMAC-KDF-Counter mode. */
	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_HMAC, mci_hkdf_counter_key_in,
			     sizeof(mci_hkdf_counter_key_in), kin);
	if (ret) {
		printf("MC_IMPORT (kin) failed: %d\n", ret);
		return -1;
	}

	ret = mci_hmac_kdf_counter(kin, CPTRA_MCI_SHA_ALGO_SHA384, CPTRA_MCI_KEY_USAGE_MLDSA, key_size,
				   mci_hkdf_counter_label, sizeof(mci_hkdf_counter_label), kout);
	if (ret) {
		printf("MC_HMAC_KDF_COUNTER failed: %d\n", ret);
		return -1;
	}

	ret = mci_mldsa_cmk_public_key(kout, pubkey);
	if (ret) {
		printf("MC_MLDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
		return -1;
	}

	if (memcmp(pubkey, mci_hkdf_counter_mldsa_pk, sizeof(mci_hkdf_counter_mldsa_pk)) != 0) {
		printf("HMAC-KDF-Counter: \033[1;31mFAIL\033[0m (derived key does not match known-answer vector)\n");
		return -1;
	}
	dbg_printf("HMAC-KDF-Counter: \033[1;32mPASS\033[0m\n");

	/* HKDF-Extract+Expand mode. */
	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_HMAC, mci_hkdf_ee_salt, sizeof(mci_hkdf_ee_salt), salt);
	if (ret) {
		printf("MC_IMPORT (salt) failed: %d\n", ret);
		return -1;
	}

	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_HMAC, mci_hkdf_ee_ikm, sizeof(mci_hkdf_ee_ikm), ikm);
	if (ret) {
		printf("MC_IMPORT (ikm) failed: %d\n", ret);
		return -1;
	}

	ret = mci_hkdf_extract(CPTRA_MCI_SHA_ALGO_SHA384, salt, ikm, prk);
	if (ret) {
		printf("MC_HKDF_EXTRACT failed: %d\n", ret);
		return -1;
	}

	ret = mci_hkdf_expand(prk, CPTRA_MCI_SHA_ALGO_SHA384, CPTRA_MCI_KEY_USAGE_MLDSA, key_size,
			      mci_hkdf_ee_info, sizeof(mci_hkdf_ee_info), kout);
	if (ret) {
		printf("MC_HKDF_EXPAND failed: %d\n", ret);
		return -1;
	}

	ret = mci_mldsa_cmk_public_key(kout, pubkey);
	if (ret) {
		printf("MC_MLDSA_CMK_PUBLIC_KEY failed: %d\n", ret);
		return -1;
	}

	if (memcmp(pubkey, mci_hkdf_ee_mldsa_pk, sizeof(mci_hkdf_ee_mldsa_pk)) != 0) {
		printf("HKDF-Extract+Expand: \033[1;31mFAIL\033[0m (derived key does not match known-answer vector)\n");
		return -1;
	}
	dbg_printf("HKDF-Extract+Expand: \033[1;32mPASS\033[0m\n");

	info_printf("MC_HMAC_KDF_COUNTER/MC_HKDF_EXTRACT+EXPAND: \033[1;32mPASS\033[0m (both known-answer cases matched)\n");

	return 0;
}

/*
 * MC_ECDH_GENERATE/MC_ECDH_FINISH test: "Alice" and "Bob" each generate an
 * ephemeral ECDH key pair, exchange their public exchange_data, and finish
 * into a shared HMAC Cmk. Since the Cmk is opaque (never leaves the
 * device), agreement is proven indirectly: HMAC identical data with both
 * sides' Cmk and check the MACs match.
 */
static int mci_test_ecdh(void)
{
	uint8_t ctx_a[CPTRA_MCI_ECDH_CONTEXT_SIZE], ctx_b[CPTRA_MCI_ECDH_CONTEXT_SIZE];
	uint8_t exch_a[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE], exch_b[CPTRA_MCI_ECDH_EXCHANGE_DATA_SIZE];
	uint8_t cmk_a[CPTRA_MCI_CMK_SIZE], cmk_b[CPTRA_MCI_CMK_SIZE];
	uint8_t data[32], mac_a[CPTRA_MCI_HMAC_MAX_SIZE], mac_b[CPTRA_MCI_HMAC_MAX_SIZE];
	uint32_t mac_a_len, mac_b_len;
	int ret, i;

	ret = mci_ecdh_generate(ctx_a, exch_a);
	if (ret) {
		printf("MC_ECDH_GENERATE (alice) failed: %d\n", ret);
		return -1;
	}

	ret = mci_ecdh_generate(ctx_b, exch_b);
	if (ret) {
		printf("MC_ECDH_GENERATE (bob) failed: %d\n", ret);
		return -1;
	}

	ret = mci_ecdh_finish(ctx_a, CPTRA_MCI_KEY_USAGE_HMAC, exch_b, cmk_a);
	if (ret) {
		printf("MC_ECDH_FINISH (alice) failed: %d\n", ret);
		return -1;
	}

	ret = mci_ecdh_finish(ctx_b, CPTRA_MCI_KEY_USAGE_HMAC, exch_a, cmk_b);
	if (ret) {
		printf("MC_ECDH_FINISH (bob) failed: %d\n", ret);
		return -1;
	}

	for (i = 0; i < (int)sizeof(data); i++)
		data[i] = (uint8_t)i;

	ret = mci_hmac(cmk_a, CPTRA_MCI_SHA_ALGO_SHA384, data, sizeof(data), mac_a, &mac_a_len);
	if (ret) {
		printf("MC_HMAC (alice) failed: %d\n", ret);
		return -1;
	}

	ret = mci_hmac(cmk_b, CPTRA_MCI_SHA_ALGO_SHA384, data, sizeof(data), mac_b, &mac_b_len);
	if (ret) {
		printf("MC_HMAC (bob) failed: %d\n", ret);
		return -1;
	}

	if (mac_a_len != mac_b_len || memcmp(mac_a, mac_b, mac_a_len) != 0) {
		printf("MC_ECDH_GENERATE/FINISH: \033[1;31mFAIL\033[0m (alice/bob derived different shared secrets)\n");
		return -1;
	}
	info_printf("MC_ECDH_GENERATE/FINISH: \033[1;32mPASS\033[0m (alice and bob agree on the shared secret)\n");

	return 0;
}

/*
 * MC_AES_ENCRYPT_INIT/MC_AES_DECRYPT_INIT round-trip test (CTR mode, no
 * KAT: this checks self-consistency, not a specific ciphertext). Only the
 * *_INIT single-shot path is exercised here; *_UPDATE (streaming across
 * multiple calls) uses the same context/iv handshake but isn't chained by
 * this test.
 */
/*
 * CTR is a stream cipher (no block buffering), so each call's output length
 * can be trusted to equal its input length -- picked to keep this two-chunk
 * round trip unambiguous. CBC may buffer partial blocks internally, which
 * this simple test does not account for.
 */
static int mci_test_aes(void)
{
	static const uint8_t seed[32] = { 0 };
	uint8_t cmk[CPTRA_MCI_CMK_SIZE];
	uint8_t plain1[32], plain2[32];
	uint8_t cipher1[64], cipher2[64], decrypted1[64], decrypted2[64];
	uint8_t context[CPTRA_MCI_AES_CONTEXT_SIZE], iv[CPTRA_MCI_AES_IV_SIZE];
	uint32_t cipher1_len = 0, cipher2_len = 0, plain1_out_len = 0, plain2_out_len = 0;
	int ret, i;

	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_AES, seed, sizeof(seed), cmk);
	if (ret) {
		printf("MC_IMPORT failed: %d\n", ret);
		return -1;
	}

	for (i = 0; i < (int)sizeof(plain1); i++)
		plain1[i] = (uint8_t)i;
	for (i = 0; i < (int)sizeof(plain2); i++)
		plain2[i] = (uint8_t)(i + 0x40);

	ret = mci_aes_encrypt_init(cmk, CPTRA_MCI_AES_MODE_CTR, plain1, sizeof(plain1),
				   context, iv, cipher1, sizeof(cipher1), &cipher1_len);
	if (ret) {
		printf("MC_AES_ENCRYPT_INIT failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_encrypt_update(context, plain2, sizeof(plain2),
				     cipher2, sizeof(cipher2), &cipher2_len);
	if (ret) {
		printf("MC_AES_ENCRYPT_UPDATE failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_decrypt_init(cmk, CPTRA_MCI_AES_MODE_CTR, iv, cipher1, cipher1_len,
				   context, decrypted1, sizeof(decrypted1), &plain1_out_len);
	if (ret) {
		printf("MC_AES_DECRYPT_INIT failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_decrypt_update(context, cipher2, cipher2_len,
				     decrypted2, sizeof(decrypted2), &plain2_out_len);
	if (ret) {
		printf("MC_AES_DECRYPT_UPDATE failed: %d\n", ret);
		return -1;
	}

	if (plain1_out_len != sizeof(plain1) || memcmp(plain1, decrypted1, sizeof(plain1)) != 0) {
		printf("MC_AES_ENCRYPT/DECRYPT: \033[1;31mFAIL\033[0m (chunk 1 round trip mismatch)\n");
		return -1;
	}
	if (plain2_out_len != sizeof(plain2) || memcmp(plain2, decrypted2, sizeof(plain2)) != 0) {
		printf("MC_AES_ENCRYPT/DECRYPT: \033[1;31mFAIL\033[0m (chunk 2 round trip mismatch)\n");
		return -1;
	}
	info_printf("MC_AES_ENCRYPT/DECRYPT (init+update): \033[1;32mPASS\033[0m (round-tripped %zu bytes across 2 chunks)\n",
	       sizeof(plain1) + sizeof(plain2));

	ret = mci_delete_key(cmk);
	if (ret) {
		printf("MC_DELETE failed: %d\n", ret);
		return -1;
	}

	return 0;
}

/*
 * MC_AES_GCM_*_INIT/UPDATE/FINAL round-trip test: encrypt(aad="",
 * plaintext) -> ciphertext+tag, then decrypt and check tag_verified plus
 * plaintext match; separately re-run decrypt with a tampered tag and
 * confirm it's rejected. No KAT: self-consistency only.
 *
 * Mirrors Zephyr's cptra_mci_shell.c cmd_cptra_mci_aes_gcm_test data
 * chunking exactly: plaintext/ciphertext is split into two non-empty
 * chunks, one fed to *_UPDATE and the other to *_FINAL. The Caliptra-SS
 * spec allows a zero-size *_FINAL call, but the current firmware doesn't
 * handle it -- observed on real hardware to wedge the mailbox and starve
 * its WDT. Keep *_FINAL non-empty here until that's fixed on the SS side.
 */
static int mci_test_aes_gcm(void)
{
	static const uint8_t seed[32] = { 0 };
	uint8_t cmk[CPTRA_MCI_CMK_SIZE];
	uint8_t plain1[16], plain2[16];
	uint8_t cipher1[32], cipher2[32], decrypted1[32], decrypted2[32];
	uint8_t enc_context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE], dec_context[CPTRA_MCI_AES_GCM_CONTEXT_SIZE];
	uint8_t iv[CPTRA_MCI_AES_GCM_IV_SIZE], tag[CPTRA_MCI_AES_GCM_TAG_SIZE], bad_tag[CPTRA_MCI_AES_GCM_TAG_SIZE];
	uint32_t cipher1_len = 0, cipher2_len = 0, plain1_out_len = 0, plain2_out_len = 0;
	int ret, i, tag_verified;

	ret = mci_import_key(CPTRA_MCI_KEY_USAGE_AES, seed, sizeof(seed), cmk);
	if (ret) {
		printf("MC_IMPORT failed: %d\n", ret);
		return -1;
	}

	for (i = 0; i < (int)sizeof(plain1); i++)
		plain1[i] = (uint8_t)i;
	for (i = 0; i < (int)sizeof(plain2); i++)
		plain2[i] = (uint8_t)(i + 0x40);

	/* Encrypt: init (no AAD) -> update (chunk 1) -> final (chunk 2 + tag). */
	ret = mci_aes_gcm_encrypt_init(0, cmk, NULL, 0, enc_context, iv);
	if (ret) {
		printf("MC_AES_GCM_ENCRYPT_INIT failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_gcm_encrypt_update(enc_context, plain1, sizeof(plain1),
					 cipher1, sizeof(cipher1), &cipher1_len);
	if (ret) {
		printf("MC_AES_GCM_ENCRYPT_UPDATE failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_gcm_encrypt_final(enc_context, plain2, sizeof(plain2), tag,
					cipher2, sizeof(cipher2), &cipher2_len);
	if (ret) {
		printf("MC_AES_GCM_ENCRYPT_FINAL failed: %d\n", ret);
		return -1;
	}

	/* Positive case: correct tag. */
	ret = mci_aes_gcm_decrypt_init(0, cmk, iv, NULL, 0, dec_context);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_INIT failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_gcm_decrypt_update(dec_context, cipher1, cipher1_len,
					 decrypted1, sizeof(decrypted1), &plain1_out_len);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_UPDATE failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_gcm_decrypt_final(dec_context, tag, cipher2, cipher2_len,
					decrypted2, sizeof(decrypted2), &plain2_out_len, &tag_verified);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_FINAL failed: %d\n", ret);
		return -1;
	}

	if (!tag_verified ||
	    plain1_out_len != sizeof(plain1) || memcmp(plain1, decrypted1, sizeof(plain1)) != 0 ||
	    plain2_out_len != sizeof(plain2) || memcmp(plain2, decrypted2, sizeof(plain2)) != 0) {
		printf("MC_AES_GCM positive case \033[1;31mFAIL\033[0m (expected verified tag + matching plaintext)\n");
		return -1;
	}
	info_printf("MC_AES_GCM positive case: \033[1;32mPASS\033[0m (tag verified, plaintext matches)\n");

	/* Negative case: tampered tag, fresh decrypt context (context is consumed by decrypt_final). */
	ret = mci_aes_gcm_decrypt_init(0, cmk, iv, NULL, 0, dec_context);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_INIT (negative) failed: %d\n", ret);
		return -1;
	}

	ret = mci_aes_gcm_decrypt_update(dec_context, cipher1, cipher1_len,
					 decrypted1, sizeof(decrypted1), &plain1_out_len);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_UPDATE (negative) failed: %d\n", ret);
		return -1;
	}

	memcpy(bad_tag, tag, sizeof(tag));
	bad_tag[0] ^= 0xff;

	ret = mci_aes_gcm_decrypt_final(dec_context, bad_tag, cipher2, cipher2_len,
					decrypted2, sizeof(decrypted2), &plain2_out_len, &tag_verified);
	if (ret) {
		printf("MC_AES_GCM_DECRYPT_FINAL (negative) failed: %d\n", ret);
		return -1;
	}
	if (tag_verified) {
		printf("MC_AES_GCM negative case \033[1;31mFAIL\033[0m (a tampered tag was accepted!)\n");
		return -1;
	}
	info_printf("MC_AES_GCM negative case: \033[1;32mPASS\033[0m (tampered tag correctly rejected)\n");

	ret = mci_delete_key(cmk);
	if (ret) {
		printf("MC_DELETE failed: %d\n", ret);
		return -1;
	}

	return 0;
}

struct mci_test {
	const char *name;
	int (*func)(void);
};

static const struct mci_test mci_tests[] = {
	{ "fw_version",			mci_test_fw_version },
	{ "subsystem_info",		mci_test_subsystem_info },
	{ "device_caps",		mci_test_device_caps },
	{ "cm_status",			mci_test_cm_status },
	{ "sha_test",			mci_test_sha },
	{ "sig_verify_test",		mci_test_sig_verify },
	{ "cm_ecdsa_verify_test",	mci_test_cm_ecdsa_verify },
	{ "cm_mldsa_verify_test",	mci_test_cm_mldsa_verify },
	{ "hmac_test",			mci_test_hmac },
	{ "hkdf_test",			mci_test_hkdf },
	{ "ecdh_test",			mci_test_ecdh },
	{ "aes_test",			mci_test_aes },
	{ "aes_gcm_test",		mci_test_aes_gcm },
	{ "trng_test",			mci_test_trng },
	{ "auth_challenge",		mci_test_auth_challenge },
	/*
	 * get_log, clear_log, export_csr disabled: MC_GET_LOG/MC_CLEAR_LOG/
	 * MC_EXPORT_ATTESTED_CSR need updates on the Caliptra-SS side that
	 * haven't landed yet. Keep mci_test_get_log()/mci_test_clear_log()/
	 * mci_test_export_csr() in the tree so they're ready to re-enable
	 * once that lands.
	 */
};

#define MCI_STRESS_ITERATIONS	1000

/*
 * Runs func() with stdout redirected to /dev/null, so a test's normal
 * per-command PASS/debug output doesn't show up. Used by mci_stress() to
 * keep per-iteration output down to just "Iteration N/M" -- over a slow
 * serial console, suppressing every test's normal printf output is what
 * actually makes 1000 iterations run in a reasonable time.
 */
static int mci_run_quiet(int (*func)(void))
{
	int saved_stdout, devnull, ret;

	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	devnull = open("/dev/null", O_WRONLY);
	dup2(devnull, STDOUT_FILENO);
	close(devnull);

	ret = func();

	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);

	return ret;
}

/*
 * Repeats mci_tests[] MCI_STRESS_ITERATIONS times, mirroring aspeed_cptra.c's
 * stress_cptra(). subsystem_info is skipped -- it's a plain register dump,
 * not worth re-running every iteration. Per-test output is suppressed (see
 * mci_run_quiet()); only "Iteration N/M", a failing test's name, and the
 * final result print.
 */
static int mci_stress(void)
{
	int i, j, ret;

	for (i = 0; i < MCI_STRESS_ITERATIONS; i++) {
		info_printf("Iteration %d/%d\n", i + 1, MCI_STRESS_ITERATIONS);
		for (j = 0; j < (int)ARRAY_SIZE(mci_tests); j++) {
			if (strcmp(mci_tests[j].name, "subsystem_info") == 0)
				continue;

			ret = mci_run_quiet(mci_tests[j].func);
			if (ret) {
				printf("  Test %s failed: %d\n", mci_tests[j].name, ret);
				return ret;
			}
		}
	}

	info_printf("Stress test completed successfully (%d iterations).\n", MCI_STRESS_ITERATIONS);

	return 0;
}

/* ================= main ================= */

static void usage(const char *prog)
{
	size_t i;

	printf("Usage:\n");
	printf("  %s [-v] [-q] all\n", prog);
	printf("      run all tests\n");
	printf("  %s [-v] [-q] stress\n", prog);
	printf("      run all tests (except subsystem_info) for %d iterations\n", MCI_STRESS_ITERATIONS);
	printf("  %s [-v] list\n", prog);
	printf("      list all available tests\n");
	printf("  %s [-v] [-q] <test_name>\n", prog);
	printf("      run a single test; test_name one of:\n");
	for (i = 0; i < ARRAY_SIZE(mci_tests); i++)
		printf("        %s\n", mci_tests[i].name);
	printf("\t-v\t\t\t\t# verbose: dump extra debug info\n");
	printf("\t-q\t\t\t\t# quiet: print nothing but FAIL/failed lines\n");
}

int main(int argc, char *argv[])
{
	const char *cmd;
	int arg_i = 1;
	int run_all;
	int test_idx = -1;
	int total = 0, failed = 0;
	size_t i;

	while (arg_i < argc && (strcmp(argv[arg_i], "-v") == 0 || strcmp(argv[arg_i], "-q") == 0)) {
		if (strcmp(argv[arg_i], "-v") == 0)
			gbl_verbose = 1;
		else
			gbl_quiet = 1;
		arg_i++;
	}

	if (arg_i >= argc) {
		usage(argv[0]);
		return 1;
	}
	cmd = argv[arg_i];

	if (strcmp(cmd, "list") == 0) {
		for (i = 0; i < ARRAY_SIZE(mci_tests); i++)
			printf("%s\n", mci_tests[i].name);
		return 0;
	}

	if (strcmp(cmd, "stress") == 0) {
		int ret;

		if (mci_dev_open()) {
			fprintf(stderr, "failed to open %s\n", CPTRA_MCI_DEV_PATH);
			return 1;
		}

		ret = mci_stress();

		mci_dev_close();

		return ret ? 1 : 0;
	}

	run_all = strcmp(cmd, "all") == 0;
	if (!run_all) {
		for (i = 0; i < ARRAY_SIZE(mci_tests); i++) {
			if (strcmp(mci_tests[i].name, cmd) == 0) {
				test_idx = (int)i;
				break;
			}
		}
		if (test_idx < 0) {
			fprintf(stderr, "unknown command '%s'\n", cmd);
			usage(argv[0]);
			return 1;
		}
	}

	if (mci_dev_open()) {
		fprintf(stderr, "failed to open %s\n", CPTRA_MCI_DEV_PATH);
		return 1;
	}

	if (run_all) {
		for (i = 0; i < ARRAY_SIZE(mci_tests); i++) {
			info_printf("== %s ==\n", mci_tests[i].name);
			total++;
			if (mci_tests[i].func()) {
				printf("%s: \033[1;31mFAILED\033[0m\n\n", mci_tests[i].name);
				failed++;
			} else {
				info_printf("%s: \033[1;32mPASSED\033[0m\n\n", mci_tests[i].name);
			}
		}
		printf("Total: %d, Passed: %d, Failed: %d\n", total, total - failed, failed);
	} else {
		failed = mci_tests[test_idx].func() ? 1 : 0;
		if (failed)
			printf("%s: \033[1;31mFAILED\033[0m\n", mci_tests[test_idx].name);
		else
			info_printf("%s: \033[1;32mPASSED\033[0m\n", mci_tests[test_idx].name);
	}

	mci_dev_close();

	return failed ? 1 : 0;
}
