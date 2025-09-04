/* SPDX-License-Identifier: GPL-2.0 */

#ifndef INCLUDE_CRYPTO_LMS_H_
#define INCLUDE_CRYPTO_LMS_H_

struct cptra_lms_ctx {
	/* public key */
	uint32_t pub_key_tree_type;
	uint32_t pub_key_ots_type;
	int pub_key_id_len;
	uint32_t pub_key_id;
	int pub_key_digest_len;
	uint32_t pub_key_digest;

	/* signature */
	uint32_t sig_q;
	int sig_ots_len;
	uint32_t sig_ots;
	uint32_t sig_tree_type;
	int sig_tree_path_len;
	uint32_t sig_tree_path;
};

#endif /* INCLUDE_CRYPTO_LMS_H_ */
