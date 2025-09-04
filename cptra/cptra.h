/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _CPTRA_H_
#define _CPTRA_H_

enum cptra_ipc_cmd {
	CPTRA_IPCCMD_ECDSA384_SIGNATURE_VERIFY = 0,
	CPTRA_IPCCMD_SHA384_DIGEST,
	CPTRA_IPCCMD_SHA384_INIT,
	CPTRA_IPCCMD_SHA384_UPDATE,
	CPTRA_IPCCMD_SHA384_FINAL,
	CPTRA_IPCCMD_LMS_SIGNATURE_VERIFY,
	CPTRA_IPCCMD_CALIPTRA_FW_LOAD,
	CPTRA_IPCCMD_STASH_MEASUREMENT,
	CPTRA_IPCCMD_QUOTE_PCRS,
	CPTRA_IPCCMD_GET_IDEV_CERT,
	CPTRA_IPCCMD_GET_IDEV_INFO,
	CPTRA_IPCCMD_POPULATE_IDEV_CERT,
	CPTRA_IPCCMD_GET_LDEV_CERT,
	CPTRA_IPCCMD_GET_FMC_ALIAS_CERT,
	CPTRA_IPCCMD_GET_RT_ALIAS_CERT,
	CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
	CPTRA_IPCCMD_DISABLE_ATTESTATION,
	CPTRA_IPCCMD_FW_INFO,
	CPTRA_IPCCMD_DPE_TAG_TCI,
	CPTRA_IPCCMD_DPE_GET_TAGGED_TCI,
	CPTRA_IPCCMD_INCREMENT_PCR_RESET_COUNTER,
	CPTRA_IPCCMD_EXTEND_PCR,
	CPTRA_IPCCMD_ADD_SUBJECT_ALT_NAME,
	CPTRA_IPCCMD_CERTIFY_KEY_EXTENDED,
	CPTRA_IPCCMD_FIPS_VERSION,
	CPTRA_IPCCMD_SHUTDOWN,
	CPTRA_IPCCMD_CAPABILITIES,
	CPTRA_IPCCMD_SET_AUTH_MANIFEST,
	CPTRA_IPCCMD_AUTHORIZE_AND_STASH,
	CPTRA_IPCCMD_GET_FMC_ALIAS_CSR,
	CPTRA_IPCCMD_SIGN_WITH_EXPORTED_ECDSA,
	CPTRA_IPCCMD_REVOKE_EXPORTED_CDI_HANDLE,
};

enum cptra_ipc_rx_type {
	CPTRA_IPC_RX_TYPE_INTERNAL = 0,
	CPTRA_IPC_RX_TYPE_EXTERNAL = 1,
};

// int cptra_ipc_enable(void);
// int cptra_ipc_trigger(enum cptra_ipc_cmd cmd, void *input, int input_size);
// int cptra_ipc_receive(enum cptra_ipc_rx_type type, void *output, int output_size);

struct cptra_stash_measurement_ia {
	uint8_t metadata[4];
	uint8_t measure[48];
	uint8_t context[48];
	uint32_t svn;
};

struct cptra_stash_measurement_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t dpe_result;
};

struct cptra_quote_pcrs_ia {
	uint8_t nonce[32];
};

typedef uint8_t PCR_Value[48];

struct cptra_quote_pcrs_oa {
	uint32_t chksum;
	uint32_t fips_status;
	PCR_Value pcrs[32];
	uint8_t nonce[32];
	uint8_t digest[48];
	uint32_t reset_ctrs[32];
	uint8_t signature_r[48];
	uint8_t signature_s[48];
};

struct cptra_extend_pcr_ia {
	uint32_t index;
	uint8_t value[48];
};

struct cptra_extend_pcr_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_increment_pcr_reset_counter_ia {
	uint32_t index;
};

struct cptra_increment_pcr_reset_counter_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_dpe_tag_tci_ia {
	uint8_t handle[16];
	uint32_t tag;
};

struct cptra_dpe_tag_tci_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_dpe_get_tagged_tci_ia {
	uint32_t tag;
};

struct cptra_dpe_get_tagged_tci_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint8_t tci_cumulative[48];
	uint8_t tci_current[48];
};

struct cptra_add_subject_alt_name_ia {
	uint32_t dmtf_device_info_size;
	uint8_t dmtf_device_info[128];
};

struct cptra_add_subject_alt_name_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_certify_key_extended_ia {
	uint8_t certify_key_req[72];
	uint32_t flags;
};

struct cptra_certify_key_extended_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint8_t certify_key_resp[2176];
};

struct cptra_disable_attestation_ia {
};

struct cptra_disable_attestation_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_get_idev_cert_ia {
	uint8_t signature_r[48];
	uint8_t signature_s[48];
	uint32_t tbs_size;
	uint8_t tbs[916];
};

struct cptra_get_idev_cert_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t cert_size;
	uint8_t cert[1024];
};

struct cptra_populate_idev_cert_ia {
	uint32_t cert_size;
	uint8_t cert[1024];
};

struct cptra_populate_idev_cert_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_get_idev_info_ia {
};

struct cptra_get_idev_info_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint8_t idev_pub_x[48];
	uint8_t idev_pub_y[48];
};

struct cptra_get_ldev_cert_ia {
};

struct cptra_get_ldev_cert_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t data_size;
	uint8_t data[1024];
};

struct cptra_get_fmc_alias_cert_ia {
};

struct cptra_get_fmc_alias_cert_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t data_size;
	uint8_t data[1024];
};

struct cptra_get_rt_alias_cert_ia {
};

struct cptra_get_rt_alias_cert_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t data_size;
	uint8_t data[1024];
};

struct cptra_fw_info_ia {
};

struct cptra_fw_info_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t pl0_pauser;
	uint32_t runtime_svn;
	uint32_t min_runtime_svn;
	uint32_t fmc_manifest_svn;
	uint32_t attestation_disabled;
	uint8_t rom_revision[20];
	uint8_t fmc_revision[20];
	uint8_t runtime_revision[20];
	uint32_t rom_sha256_digest[8];
	uint32_t fmc_sha384_digest[12];
	uint32_t runtime_sha384_digest[12];
};

struct cptra_capabilities_ia {
};

struct cptra_capabilities_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint8_t capabilities[16];
};

struct cptra_version_ia {
};

struct cptra_version_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t mode;
	uint32_t fips_rev[3];
	uint8_t name[12];
};

struct cptra_shutdown_ia {
};

struct cptra_shutdown_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

#define DPE_COMMAND_MAGIC		0x44504543	/* DPEC */
#define DPE_RESPONSE_MAGIC		0x44504552	/* DPER */

enum dpe_command {
	GET_PROFILE		= 0x01,
	INITIALIZE_CONTEXT	= 0x07,
	DERIVE_CONTEXT		= 0x08,
	CERTIFY_KEY		= 0x09,
	SIGN			= 0x0A,
	ROTATE_CONTEXT_HANDLE	= 0x0e,
	DESTROY_CONTEXT		= 0x0f,
	GET_CERTIFICATE_CHAIN	= 0x10,
};

enum dpe_profile {
	p256sha256 = 3,
	p384sha384 = 4,
};

/* TODO: DPE command */
struct dpe_cmd_header {
	uint32_t magic;
	uint32_t cmd;
	uint32_t profile;
};

struct dpe_rsp_header {
	uint32_t magic;
	uint32_t status;
	uint32_t profile;
};

struct dpe_get_profile_i {
	struct dpe_cmd_header cmd_hdr;
};

struct dpe_get_profile_o {
	struct dpe_rsp_header rsp_hdr;
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t vendor_id;
	uint32_t vendor_sku;
	uint32_t max_tci_nodes;
	uint32_t flags;
};

struct dpe_initialize_context_i {
	struct dpe_cmd_header cmd_hdr;
	uint32_t init_ctx_cmd;
};

struct dpe_new_context_o {
	struct dpe_rsp_header rsp_hdr;
	uint8_t context_handle[16];
};

/* DeriveContextFlags */
#define INTERNAL_INPUT_INFO		BIT(31)
#define INTERNAL_INPUT_DICE		BIT(30)
#define RETAIN_PARENT_CONTEXT		BIT(29)
#define MAKE_DEFAULT			BIT(28)
#define CHANGE_LOCALITY			BIT(27)
#define INPUT_ALLOW_CA			BIT(26)
#define INPUT_ALLOW_X509		BIT(25)
#define RECURSIVE			BIT(24)
#define EXPORT_CDI			BIT(23)
#define CREATE_CERTIFICATE		BIT(22)

struct dpe_derive_context_i {
	struct dpe_cmd_header cmd_hdr;
	uint8_t handle[16];
	uint8_t data[48];
	uint32_t flags;
	uint32_t tci_type;
	uint32_t target_locality;
};

struct dpe_derive_context_o {
	struct dpe_rsp_header rsp_hdr;
	uint8_t context_handle[16];
	uint8_t parent_context_handle[16];
};

struct dpe_derive_context_exported_cdi_o {
	struct dpe_rsp_header rsp_hdr;
	uint8_t context_handle[16];
	uint8_t parent_context_handle[16];
	uint8_t exported_cdi[32];
	int certificate_size;
	uint8_t new_certificate[6144];
};

struct dpe_certify_key_i {
	struct dpe_cmd_header cmd_hdr;
	uint8_t handle[16];
	uint32_t flags;
	uint32_t format;
	uint8_t label[48];
};

struct dpe_certify_key_o {
	struct dpe_rsp_header rsp_hdr;
	uint8_t context_handle[16];
	uint8_t public_key_x[48];
	uint8_t public_key_y[48];
	uint32_t cert_size;
	uint8_t cert[];
};

struct dpe_sign_i {
	struct dpe_cmd_header cmd_hdr;
	uint8_t handle[16];
	uint8_t label[48];
	uint32_t flags;
	uint8_t digest[48];
};

struct dpe_sign_o {
	struct dpe_rsp_header rsp_hdr;
	uint8_t context_handle[16];
	uint8_t signature_r[48];
	uint8_t signature_s[48];
};

struct dpe_rotate_context_handle_i {
	struct dpe_cmd_header cmd_hdr;
	uint8_t handle[16];
	uint32_t flags;
};

struct dpe_destroy_context_i {
	struct dpe_cmd_header cmd_hdr;
	uint8_t handle[16];
};

struct dpe_destroy_context_o {
	struct dpe_rsp_header rsp_hdr;
};

struct dpe_get_certificate_chain_i {
	struct dpe_cmd_header cmd_hdr;
	uint32_t offset;
	uint32_t size;
};

struct dpe_get_certificate_chain_o {
	struct dpe_rsp_header rsp_hdr;
	uint32_t size;
	uint8_t cert_chain[2048];
};

struct cptra_invoke_dpe_command_ia {
	uint32_t data_size;
	uint8_t data[256];
};

struct cptra_invoke_dpe_command_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t data_size;
	uint8_t data[2304];
};

#define CPTRA_IMC_ENTRY_COUNT			127	/* Max IMC entry count */

struct cptra_manifest_preamble {
	uint32_t manifest_marker;
	uint32_t preamble_size;
	uint32_t manifest_version;
	uint32_t manifest_flags;
	uint32_t manifest_vendor_ecc384_key[24];
	uint32_t manifest_vendor_lms_key[12];
	uint32_t manifest_vendor_ecc384_sig[24];
	uint32_t manifest_vendor_LMS_sig[405];
	uint32_t manifest_owner_ecc384_key[24];
	uint32_t manifest_owner_lms_key[12];
	uint32_t manifest_owner_ecc384_sig[24];
	uint32_t manifest_owner_LMS_sig[405];
	uint32_t metadata_vendor_ecc384_sig[24];
	uint32_t metadata_vendor_LMS_sig[405];
	uint32_t metadata_owner_ecc384_sig[24];
	uint32_t metadata_owner_LMS_sig[405];
};

struct cptra_manifest_ime {
	uint32_t fw_id;
	uint32_t flags;
	uint8_t digest[48]; /* SHA384 */
};

struct cptra_set_auth_manifest_ia {
	uint32_t manifest_size;

	struct cptra_manifest_preamble preamble;
	uint32_t metadata_entry_entry_count;
	struct cptra_manifest_ime metadata_entries[CPTRA_IMC_ENTRY_COUNT];
};

struct cptra_set_auth_manifest_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

struct cptra_authorize_and_stash_ia {
	uint8_t fw_id[4];
	uint8_t measurement[48];
	uint8_t context[48];
	uint32_t svn;
	uint32_t flags;
	uint32_t source;
};

struct cptra_authorize_and_stash_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t auth_req_result;
};

enum image_hash_source {
	invalid = 0,
	inrequest,
	shaacc,
};

#define AUTHORIZE_IMAGE				0xDEADC0DE
#define IMAGE_NOT_AUTHORIZED			0x21523F21
#define IMAGE_HASH_MISMATCH			0x8BFB95CB

#define AUTHORIZE_AND_STASH_FLAGS_SKIP_STASH	BIT(0)

struct cptra_get_fmc_alias_csr_ia {
};

struct cptra_get_fmc_alias_csr_oa {
	uint32_t chksum;
	uint32_t fips_status;
	uint32_t data_size;
	uint8_t data[512]; /* Maximum size for the DER-encoded CSR */
};

struct cptra_sign_with_exported_ecdsa_ia {
	uint8_t exported_cdi_handle[32];
	uint8_t tbs[48];
};

struct cptra_sign_with_exported_ecdsa_oa {
	uint8_t derived_pubkey_x[48];
	uint8_t derived_pubkey_y[48];
	uint8_t signature_r[48];
	uint8_t signature_s[48];
};

struct cptra_revoke_exported_cdi_handle_ia {
	uint8_t exported_cdi_handle[32];
};

struct cptra_revoke_exported_cdi_handle_oa {
	uint32_t chksum;
	uint32_t fips_status;
};

void cptra_test_invoke_dpe_command_derive_context_exported_cdi(uint8_t *derived_context);
int cptra_test_get_fmc_alias_csr(void);
int cptra_test_sign_with_exported_ecdsa(uint8_t *exported_cdi);
int cptra_test_revoke_exported_cdi_handle(uint8_t *exported_cdi);

#endif /* _CPTRA_H_ */
