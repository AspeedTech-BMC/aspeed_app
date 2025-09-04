/* SPDX-License-Identifier: GPL-2.0 */

/**
 * @file
 * @brief Crypto Hash APIs
 *
 * This file contains the Crypto Abstraction layer APIs.
 */
#ifndef INCLUDE_CRYPTO_HASH_H_
#define INCLUDE_CRYPTO_HASH_H_

/**
 * @addtogroup crypto_hash
 * @{
 */

/* Hash digest/block size definition */
#define SHA1_DIGEST_SIZE	20
#define SHA1_BLOCK_SIZE		64
#define SHA1_IV_SIZE		32

#define SHA224_DIGEST_SIZE      28
#define SHA224_BLOCK_SIZE       64
#define SHA224_IV_SIZE		32

#define SHA256_DIGEST_SIZE      32
#define SHA256_BLOCK_SIZE       64
#define SHA256_IV_SIZE		32

#define SHA384_DIGEST_SIZE      48
#define SHA384_BLOCK_SIZE       128
#define SHA384_IV_SIZE		64

#define SHA512_DIGEST_SIZE      64
#define SHA512_BLOCK_SIZE       128
#define SHA512_IV_SIZE		64

#define HMAC_IPAD_VALUE		0x36
#define HMAC_OPAD_VALUE		0x5c

struct hash_ctx;
struct hash_pkt;
typedef int (*hash_op_t)(void *obj, struct hash_ctx *ctx, struct hash_pkt *pkt, bool finish);

/**
 * Hash algorithm
 */
enum hash_algo {
	CRYPTO_HASH_ALGO_SHA1 = 0,
	CRYPTO_HASH_ALGO_SHA224 = 1,
	CRYPTO_HASH_ALGO_SHA256 = 2,
	CRYPTO_HASH_ALGO_SHA384 = 3,
	CRYPTO_HASH_ALGO_SHA512 = 4,
	CRYPTO_HASH_ALGO_SHA512_224 = 5,
	CRYPTO_HASH_ALGO_SHA512_256 = 6,
};

struct cptra_hash_ctx {
	uint32_t algo;
	int in_len;
	uint32_t in_buf;
	int out_len;
	uint32_t out_buf;
};

struct hash_ctx {
	/**
	 * Hash handler set up when the session begins.
	 */
	hash_op_t hash_hndlr;

	uint32_t digest_size;
};

struct hash_pkt {
	/** Start address of input buffer */
	uint8_t *in_buf;

	/** Bytes to be operated upon */
	size_t in_len;

	/**
	 * Start of the output buffer, to be allocated by
	 * the application. Can be NULL for in-place ops. To be populated
	 * with contents by the driver on return from op / async callback.
	 */
	uint8_t *out_buf;

	/**
	 * Context this packet relates to. This can be useful to get the
	 * session details, especially for async ops.
	 */
	struct hash_ctx *ctx;
};

#endif /* INCLUDE_CRYPTO_HASH_H_ */
