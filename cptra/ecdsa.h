/* SPDX-License-Identifier: GPL-2.0 */

/**
 * @file
 * @brief Crypto ECDSA structure definitions
 *
 * This file contains the ECDSA Abstraction layer structures.
 *
 * [Experimental] Users should note that the Structures can change
 * as a part of ongoing development.
 */

#ifndef INCLUDE_CRYPTO_ECDSA_STRUCTS_H_
#define INCLUDE_CRYPTO_ECDSA_STRUCTS_H_

/* Curves IDs */
#define ECC_CURVE_NIST_P192	0x0001
#define ECC_CURVE_NIST_P256	0x0002
#define ECC_CURVE_NIST_P384	0x0003

struct ecdsa_key {
	unsigned int curve_id;
	char qx[48];
	char qy[48];
};

/**
 * Structure encoding session parameters.
 *
 * Refer to comments for individual fields to know the contract
 * in terms of who fills what and when w.r.t begin_session() call.
 */
struct cptra_ecdsa_ctx {
	int qx_len;
	uint32_t qx;

	int qy_len;
	uint32_t qy;

	int r_len;
	uint32_t r;

	int s_len;
	uint32_t s;

	int  m_len;
	uint32_t m;
};

#endif /* INCLUDE_CRYPTO_ECDSA_STRUCTS_H_ */
