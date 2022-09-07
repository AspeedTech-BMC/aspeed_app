// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Synopsys, Inc. and/or its affiliates.
 *
 * Author: Vitor Soares <vitor.soares@synopsys.com>
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <linux/types.h>
#include <sys/stat.h>

#define MCTP_BTU 68
#define I3C_MCTP_HDR_SIZE 4
#define I3C_MCTP_PAYLOAD_SIZE 64

struct i3c_mctp_xfer {
	__u32 *data;
	__u16 len;
	__u8 rnw;
	__u8 pad[5];
};

struct i3c_mctp_packet_data {
	__u8 protocol_hdr[I3C_MCTP_HDR_SIZE];
	__u8 payload[I3C_MCTP_PAYLOAD_SIZE];
};

struct i3c_mctp_packet {
	struct i3c_mctp_packet_data data;
	__u32 size;
};

const char *sopts = "d:rw:h";
static const struct option lopts[] = {
	{"device",		required_argument,	NULL,	'd' },
	{"read",		no_argument,		NULL,	'r' },
	{"write",		required_argument,	NULL,	'w' },
	{"command",		required_argument,	NULL,	'c' },
	{"help",		no_argument,		NULL,	'h' },
	{0, 0, 0, 0}
};
static void print_usage(const char *name)
{
	fprintf(stderr, "usage: %s options...\n", name);
	fprintf(stderr, "  options:\n");
	fprintf(stderr, "    -d --device       <dev>          device to use.\n");
	fprintf(stderr, "    -r --read                        read mctp packet.\n");
	fprintf(stderr, "    -w --write        <data block>   send mctp packet.\n");
	fprintf(stderr, "    -h --help                        Output usage message and exit.\n");
}

static int rx_args_to_xfer(struct i3c_mctp_xfer *xfer)
{
	uint8_t *tmp;

	tmp = (uint8_t *)calloc(MCTP_BTU, sizeof(uint8_t));
	if (!tmp)
		return -1;
	xfer->rnw = 1;
	xfer->len = MCTP_BTU;
	xfer->data = (__u32 *)tmp;
	return 0;
}
static int w_args_to_xfer(struct i3c_mctp_xfer *xfer, char *arg)
{
	char *data_ptrs[256];
	int len, i = 0;
	uint8_t *tmp;

	data_ptrs[i] = strtok(arg, ",");
	while (data_ptrs[i] && i < 255)
		data_ptrs[++i] = strtok(NULL, ",");
	tmp = (uint8_t *)calloc(i, sizeof(uint8_t));
	if (!tmp)
		return -1;
	for (len = 0; len < i; len++)
		tmp[len] = (uint8_t)strtol(data_ptrs[len], NULL, 0);
	xfer->rnw = 0;
	xfer->len = len;
	xfer->data = (__u32 *)tmp;
	return 0;
}

void packet_dump(struct i3c_mctp_packet *packet)
{
	int i;

	fprintf(stdout, "packet valid length: 0x%x\n", packet->size);
	fprintf(stdout, "Protocol header:\n");
	for (i = 0; i < (I3C_MCTP_HDR_SIZE >> 2); i++) {
		fprintf(stdout, "%02x %02x %02x %02x\n",
			 packet->data.protocol_hdr[i*4],
			 packet->data.protocol_hdr[i*4 + 1],
			 packet->data.protocol_hdr[i*4 + 2],
			 packet->data.protocol_hdr[i*4 + 3]);
	}
	fprintf(stdout, "Data payload:\n");
	for (i = 0; i < (I3C_MCTP_PAYLOAD_SIZE >> 2); i++) {
		fprintf(stdout, "%02x %02x %02x %02x\n",
			 packet->data.payload[i*4],
			 packet->data.payload[i*4 + 1],
			 packet->data.payload[i*4 + 2],
			 packet->data.payload[i*4 + 3]);
	}
}

static void print_rx_data(struct i3c_mctp_xfer *xfer)
{
	struct i3c_mctp_packet *packet;

	packet = calloc(1, sizeof(struct i3c_mctp_packet));
	if (!packet)
		return;
	memcpy(packet, (void *)(uintptr_t)xfer->data, xfer->len * sizeof(uint8_t));
	packet->size = xfer->len;
	packet_dump(packet);
	free(packet);
}

static int i3c_mctp_poll(int fd, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = fd;
	fds[0].events = POLLIN | POLLOUT;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	if (rc < 0) {
		perror("Poll returned error status");

		return -1;
	}

	return 0;
}

void wait_for_message(int fd)
{
	int rc;
	bool received = false;

	while (!received) {
		rc = i3c_mctp_poll(fd, 1000);
		if (rc & POLLIN)
			received = true;
	}
}

int i3c_mctp_recv(int fd, struct i3c_mctp_xfer *xfer)
{
	int ret;

	ret = read(fd, xfer->data, xfer->len);
	if (ret < 0)
		perror("i3c MCTP read error!\n");
	xfer->len = ret;
	return ret;
}

int i3c_mctp_send(int fd, struct i3c_mctp_xfer *xfer)
{
	int ret;

	ret = write(fd, xfer->data, xfer->len);
	if (ret < 0) {
		perror("i3c MCTP write error!\n");
		return ret;
	}
	return ret;
}

int i3c_mctp_priv_xfer(int fd, struct i3c_mctp_xfer *xfer)
{
	int ret;

	if (xfer->rnw) {
		wait_for_message(fd);
		ret = i3c_mctp_recv(fd, xfer);
	} else {
		ret = i3c_mctp_send(fd, xfer);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	struct i3c_mctp_xfer *xfers;
	int file, ret, opt, i;
	int nxfers = 0;
	char *device = NULL;

	if (!argv[1]) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv,  sopts, lopts, NULL)) != EOF) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'd':
			device = optarg;
			break;
		case 'r':
		case 'w':
			nxfers++;
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (!device)
		exit(EXIT_FAILURE);
	file = open(device, O_RDWR);
	if (file < 0)
		exit(EXIT_FAILURE);
	xfers = (struct i3c_mctp_xfer *)calloc(nxfers, sizeof(*xfers));
	if (!xfers)
		exit(EXIT_FAILURE);

	optind = 1;
	nxfers = 0;
	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) != EOF) {
		switch (opt) {
		case 'h':
		case 'd':
			break;
		case 'r':
			if (rx_args_to_xfer(&xfers[nxfers])) {
				ret = EXIT_FAILURE;
				goto err_free;
			}
			nxfers++;
			break;
		case 'w':
			if (w_args_to_xfer(&xfers[nxfers], optarg)) {
				ret = EXIT_FAILURE;
				goto err_free;
			}
			nxfers++;
			break;
		default:
			break;
		}
	}
	for (i = 0; i < nxfers; i++) {
		if (i3c_mctp_priv_xfer(file, &xfers[i]) < 0) {
			fprintf(stderr, "Error: transfer failed: %s\n", strerror(errno));
			ret = EXIT_FAILURE;
			goto err_free;
		}
		fprintf(stdout, "Success on message %d\n", i);
		if (xfers[i].rnw)
			print_rx_data(&xfers[i]);
	}
	ret = EXIT_SUCCESS;
err_free:
	for (i = 0; i < nxfers; i++)
		free((void *)(uintptr_t)xfers[i].data);
	free(xfers);
	return ret;
}
