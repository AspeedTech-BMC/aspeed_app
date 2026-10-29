/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2026 Aspeed Technology Inc.
 */

#ifndef OTP_IPC_H
#define OTP_IPC_H

#include <stdint.h>
#include <stdbool.h>

/*
 * OTP-over-IPC (CA35 Linux side): lets this app read/program bootmcu-owned
 * OTP through the "mbox-bootmcu-2" mailbox channel instead of the direct
 * /dev/aspeed-otp register path. Same wire protocol as u-boot's
 * lib/aspeed/otp_ipc.c and the BOOTMCU-side Zephyr otp_ipc command set
 * (zephyr/include/zephyr/drivers/misc/aspeed/otp_ipc.h): request/response
 * share one 8x32-bit mailbox message, word1 packs a per-call sequence
 * number into its top 8 bits, the op into the next 8 bits, and an
 * op-specific value into its lower 16 bits. The response's word0 echoes
 * that same sequence number back in its top 8 bits alongside the status
 * in its lower 16 bits, so otp_ipc_call() can tell a late reply from a
 * call it already gave up on apart from the answer to whatever it asks
 * next, instead of risking silently accepting someone else's data.
 *
 * Read request:  word0 = addr, word1 = pack(OTP_IPC_OP_READ, count)
 * Read response: word0 = status, word1..word7 = up to OTP_IPC_READ_MAX_WORDS
 *                16-bit OTP words, packed 2 per word
 *
 * Program request:  word0 = addr, word1 = pack(OTP_IPC_OP_PROGRAM, count),
 *                    word2..word7 = up to OTP_IPC_PROGRAM_MAX_WORDS
 *                    16-bit OTP words to burn, packed 2 per word
 * Program response: word0 = status
 *
 * ECC_GET_STATUS request:  word1 = pack(OTP_IPC_OP_ECC_GET_STATUS, 0)
 * ECC_GET_STATUS response: word0 = status, word1 = ecc_en
 *
 * ECC_SET_ENABLE request:  word1 = pack(OTP_IPC_OP_ECC_SET_ENABLE, enable)
 * ECC_SET_ENABLE response: word0 = status
 *
 * ECC_GET_POLICY request:  word1 = pack(OTP_IPC_OP_ECC_GET_POLICY, region)
 * ECC_GET_POLICY response: word0 = status, word1 = ecc_en, word2 = ecc_supported
 *
 * ECC_SET_POLICY request:  word1 = pack(OTP_IPC_OP_ECC_SET_POLICY, region),
 *                          word2 = ecc_en
 * ECC_SET_POLICY response: word0 = status
 *
 * GET_REVID request:  word1 = pack(OTP_IPC_OP_GET_REVID, 0)
 * GET_REVID response: word0 = status, word1 = SCU0 revid, word2 = SCU1 revid
 *
 * SET_READ_MODE request:  word1 = pack(OTP_IPC_OP_SET_READ_MODE, mode)
 *                          mode: enum otp_read_mode (0=normal, 1=margin)
 * SET_READ_MODE response: word0 = status
 * Affects every subsequent READ until switched back - used for OTP cell
 * margin-screening diagnostics (otp screen), not part of normal traffic.
 */

enum otp_ipc_op {
	OTP_IPC_OP_READ = 0,
	OTP_IPC_OP_PROGRAM,
	OTP_IPC_OP_ECC_GET_STATUS,
	OTP_IPC_OP_ECC_SET_ENABLE,
	OTP_IPC_OP_ECC_GET_POLICY,
	OTP_IPC_OP_ECC_SET_POLICY,
	OTP_IPC_OP_GET_REVID,
	OTP_IPC_OP_SET_READ_MODE,
};

#define OTP_IPC_SEQ_SHIFT		24
#define OTP_IPC_SEQ_MASK		0xFF
#define OTP_IPC_OP_SHIFT		16
#define OTP_IPC_OP_MASK			0xFF
#define OTP_IPC_COUNT_MASK		0xFFFF

#define OTP_IPC_PACK_OP_COUNT(op, count) \
	((((uint32_t)(op) & OTP_IPC_OP_MASK) << OTP_IPC_OP_SHIFT) | ((uint32_t)(count) & OTP_IPC_COUNT_MASK))

/* Response word0: seq echoed back in the top 8 bits, status (sign-extended,
 * every status value here fits in int16_t) in the lower 16 bits.
 */
#define OTP_IPC_RESP_SEQ(word)		(((word) >> OTP_IPC_SEQ_SHIFT) & OTP_IPC_SEQ_MASK)
#define OTP_IPC_RESP_STATUS(word)	((int16_t)((word) & 0xFFFF))

#define OTP_IPC_READ_MAX_WORDS		14	/* 7 msg words x 2 */
#define OTP_IPC_PROGRAM_MAX_WORDS	12	/* 6 msg words x 2 */

/*
 * Scans /dev for the bootmcu OTP mailbox channel and opens it if present.
 * Safe to call once at startup. Returns true when the IPC path is usable;
 * callers must fall back to the direct CA35 path otherwise.
 */
bool otp_ipc_probe(void);

/* True once otp_ipc_probe() has found and opened the mailbox channel. */
bool otp_ipc_available(void);

/*
 * Status convention shared by all otp_ipc_*() calls below: 0 on success, a
 * positive OTP_CMD_ERR_* code on a command failure reported by bootmcu, or
 * a negative -errno on a transport failure (timeout, I/O error, etc).
 */
int otp_ipc_read(uint32_t addr, uint32_t count, uint16_t *out);
int otp_ipc_program(uint32_t addr, uint32_t count, const uint16_t *data);
int otp_ipc_ecc_get_status(int *ecc_en);
int otp_ipc_ecc_set_enable(int enable);
int otp_ipc_ecc_get_policy(uint32_t region, uint32_t *ecc_en, uint32_t *ecc_supported);
int otp_ipc_ecc_set_policy(uint32_t region, uint32_t ecc_en);
int otp_ipc_get_revid(uint32_t *revid0, uint32_t *revid1);
int otp_ipc_set_read_mode(uint32_t mode);

#endif /* OTP_IPC_H */
