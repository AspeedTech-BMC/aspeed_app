// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2026 Aspeed Technology Inc.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "otp_ipc.h"

/*
 * The mailbox channel is probed by name suffix rather than a fixed path
 * because the Linux generic mailbox-client misc device (drivers/soc/aspeed/
 * aspeed-mbox.c) names its /dev node after the devicetree node, which may
 * be prefixed with its unit address (e.g. "431a80000.mbox-bootmcu-2").
 */
#define OTP_MBOX_DEV_DIR	"/dev"
#define OTP_MBOX_DEV_SUFFIX	"mbox-bootmcu-2"

#define OTP_IPC_TIMEOUT_MS	5000

/* Must match drivers/soc/aspeed/aspeed-mbox.c's ioctl ABI. */
#define __ASPEED_MBOX_IOCTL_MAGIC	'X'
#define ASPEED_MBOX_IOCTL_SEND		_IOW(__ASPEED_MBOX_IOCTL_MAGIC, 1, uint32_t[8])
#define ASPEED_MBOX_IOCTL_RECV		_IOR(__ASPEED_MBOX_IOCTL_MAGIC, 2, uint32_t[8])

static int otp_ipc_fd = -1;

static bool find_otp_mbox_dev(char *path, size_t path_sz)
{
	size_t suffix_len = strlen(OTP_MBOX_DEV_SUFFIX);
	struct dirent *ent;
	bool found = false;
	DIR *dir;

	dir = opendir(OTP_MBOX_DEV_DIR);
	if (!dir)
		return false;

	while ((ent = readdir(dir))) {
		size_t len = strlen(ent->d_name);

		if (len < suffix_len)
			continue;
		if (strcmp(ent->d_name + (len - suffix_len), OTP_MBOX_DEV_SUFFIX))
			continue;

		snprintf(path, path_sz, "%s/%s", OTP_MBOX_DEV_DIR, ent->d_name);
		found = true;
		break;
	}

	closedir(dir);
	return found;
}

bool otp_ipc_probe(void)
{
	char path[PATH_MAX];

	if (otp_ipc_fd >= 0)
		return true;

	if (!find_otp_mbox_dev(path, sizeof(path)))
		return false;

	otp_ipc_fd = open(path, O_RDWR);
	if (otp_ipc_fd < 0)
		return false;

	return true;
}

bool otp_ipc_available(void)
{
	return otp_ipc_fd >= 0;
}

static int otp_ipc_call(uint32_t *req, uint32_t *resp)
{
	static uint8_t next_seq;
	struct timespec ts_start, ts_now;
	struct pollfd pfd;
	uint8_t seq;
	int ret;

	seq = ++next_seq;
	req[1] |= ((uint32_t)seq << OTP_IPC_SEQ_SHIFT);

	ret = ioctl(otp_ipc_fd, ASPEED_MBOX_IOCTL_SEND, req);
	if (ret < 0)
		return -errno;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	pfd.fd = otp_ipc_fd;
	pfd.events = POLLIN;

	for (;;) {
		int elapsed_ms, remaining_ms;

		clock_gettime(CLOCK_MONOTONIC, &ts_now);
		elapsed_ms = (ts_now.tv_sec - ts_start.tv_sec) * 1000 +
			     (ts_now.tv_nsec - ts_start.tv_nsec) / 1000000;
		remaining_ms = OTP_IPC_TIMEOUT_MS - elapsed_ms;
		if (remaining_ms <= 0) {
			printf("otp_ipc: timed out waiting for bootmcu response\n");
			return -ETIMEDOUT;
		}

		ret = poll(&pfd, 1, remaining_ms);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (ret == 0) {
			printf("otp_ipc: timed out waiting for bootmcu response\n");
			return -ETIMEDOUT;
		}

		ret = ioctl(otp_ipc_fd, ASPEED_MBOX_IOCTL_RECV, resp);
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			return -errno;
		}

		/* A reply that doesn't echo our seq belongs to a call we
		 * already gave up on; discard it and keep polling for ours
		 * within what's left of the overall timeout.
		 */
		if (OTP_IPC_RESP_SEQ(resp[0]) != seq) {
			printf("otp_ipc: discarding stale reply (seq %u, expected %u)\n",
			       OTP_IPC_RESP_SEQ(resp[0]), seq);
			continue;
		}

		return OTP_IPC_RESP_STATUS(resp[0]);
	}
}

int otp_ipc_read(uint32_t addr, uint32_t count, uint16_t *out)
{
	uint32_t req[8] = {addr, 0, 0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};
	int status;

	if (otp_ipc_fd < 0)
		return -ENODEV;

	if (count > OTP_IPC_READ_MAX_WORDS)
		return -EINVAL;

	req[1] = OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_READ, count);

	status = otp_ipc_call(req, resp);
	if (status == 0)
		memcpy(out, &resp[1], count * sizeof(uint16_t));

	return status;
}

int otp_ipc_program(uint32_t addr, uint32_t count, const uint16_t *data)
{
	uint32_t req[8] = {addr, 0, 0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};

	if (otp_ipc_fd < 0)
		return -ENODEV;

	if (count > OTP_IPC_PROGRAM_MAX_WORDS)
		return -EINVAL;

	req[1] = OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_PROGRAM, count);
	memcpy(&req[2], data, count * sizeof(uint16_t));

	return otp_ipc_call(req, resp);
}

int otp_ipc_ecc_get_status(int *ecc_en)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_ECC_GET_STATUS, 0), 0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};
	int status;

	if (otp_ipc_fd < 0)
		return -ENODEV;

	status = otp_ipc_call(req, resp);
	if (status == 0)
		*ecc_en = (int)resp[1];

	return status;
}

int otp_ipc_ecc_set_enable(int enable)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_ECC_SET_ENABLE, enable ? 1 : 0),
			   0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};

	if (otp_ipc_fd < 0)
		return -ENODEV;

	return otp_ipc_call(req, resp);
}

int otp_ipc_ecc_get_policy(uint32_t region, uint32_t *ecc_en, uint32_t *ecc_supported)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_ECC_GET_POLICY, region),
			   0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};
	int status;

	if (otp_ipc_fd < 0)
		return -ENODEV;

	status = otp_ipc_call(req, resp);
	if (status == 0) {
		*ecc_en = resp[1];
		*ecc_supported = resp[2];
	}

	return status;
}

int otp_ipc_ecc_set_policy(uint32_t region, uint32_t ecc_en)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_ECC_SET_POLICY, region),
			   ecc_en, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};

	if (otp_ipc_fd < 0)
		return -ENODEV;

	return otp_ipc_call(req, resp);
}

int otp_ipc_get_revid(uint32_t *revid0, uint32_t *revid1)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_GET_REVID, 0), 0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};
	int status;

	if (otp_ipc_fd < 0)
		return -ENODEV;

	status = otp_ipc_call(req, resp);
	if (status == 0) {
		*revid0 = resp[1];
		*revid1 = resp[2];
	}

	return status;
}

int otp_ipc_set_read_mode(uint32_t mode)
{
	uint32_t req[8] = {0, OTP_IPC_PACK_OP_COUNT(OTP_IPC_OP_SET_READ_MODE, mode),
			   0, 0, 0, 0, 0, 0};
	uint32_t resp[8] = {0};

	if (otp_ipc_fd < 0)
		return -ENODEV;

	return otp_ipc_call(req, resp);
}
