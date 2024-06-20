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
#include <time.h>
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

struct mctp_header {
	__u8	msg_tag: 3;
	__u8	to: 1;
	__u8	pkt_seq: 2;
	__u8	eom: 1;
	__u8	som: 1;
	__u8	src_eid;
	__u8	dest_eid;
	__u8	header_ver: 4;
	__u8	rsvd: 4;
};

struct i3c_mctp_packet_data {
	__u8 protocol_hdr[I3C_MCTP_HDR_SIZE];
	__u8 payload[I3C_MCTP_PAYLOAD_SIZE];
};

struct i3c_mctp_packet {
	struct i3c_mctp_packet_data data;
	__u32 size;
};

static int read_timeout_ms = 10000;

const char *sopts = "d:rw:t:v:c:m:h";
static const struct option lopts[] = {
	{"device",		required_argument,	NULL,	'd' },
	{"read",		no_argument,		NULL,	'r' },
	{"write",		required_argument,	NULL,	'w' },
	{"test",		optional_argument,	NULL,	't' },
	{"verify",		optional_argument,	NULL,	'v' },
	{"continue",		optional_argument,	NULL,	'c' },
	{"ms",			required_argument,	NULL,	'm' },
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
	fprintf(stderr, "    -t --test         <length>       send test pattern.\n");
	fprintf(stderr, "    -v --verify       <length>       verify the test pattern.\n");
	fprintf(stderr, "    -c --continue     <num>          0: infinity loop, n: loop count\n");
	fprintf(stderr, "    -m --ms           <ms>           read wait in ms, 0: wait forever\n");
	fprintf(stderr, "    -h --help                        Output usage message and exit.\n");
}

/*TODO: Find the method to get the device address*/
static bool cal_pec;

uint8_t crc8(uint8_t crc, const uint8_t *data, uint8_t len)
{
	int i, j;

	if (!data)
		return crc;

	for (i = 0; i < len; ++i) {
		crc ^= data[i];

		for (j = 0; j < 8; ++j) {
			if ((crc & 0x80) != 0)
				crc = (uint8_t)((crc << 1) ^ 0x07);
			else
				crc <<= 1;
		}
	}

	return crc;
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

	if (cal_pec) {
		int buf_size = i;
		uint8_t pec, addr = ((0x08 << 1) | 0x01);

		buf_size++;

		tmp = (uint8_t *)calloc(buf_size, sizeof(uint8_t));
		if (!tmp)
			return -1;

		for (len = 0; len < i; len++)
			tmp[len] = (uint8_t)strtol(data_ptrs[len], NULL, 0);

		pec = crc8(0, &addr, 1);
		pec = crc8(pec, tmp, len);
		tmp[len++] = pec;
	} else {
		tmp = (uint8_t *)calloc(i, sizeof(uint8_t));
		if (!tmp)
			return -1;
		for (len = 0; len < i; len++)
			tmp[len] = (uint8_t)strtol(data_ptrs[len], NULL, 0);
	}
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
	return rc;
}

int wait_for_message(int fd)
{
	int rc;

	rc = i3c_mctp_poll(fd, read_timeout_ms);
	if (rc == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	return 0;
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
		ret = wait_for_message(fd);
		if (ret < 0)
			return ret;
		ret = i3c_mctp_recv(fd, xfer);
	} else {
		ret = i3c_mctp_send(fd, xfer);
	}
	return ret;
}

static int send_test_pattern(int file, int length)
{
	struct i3c_mctp_xfer *xfers, *xfer;
	struct i3c_mctp_packet_data *packet;
	struct mctp_header *header;
	unsigned char *payload;
	unsigned char pattern = 0;
	unsigned char sed = 0;
	int i, xfer_index = 0, payload_index, nxfers;
	unsigned int remain_xfer = length;

	pattern = rand();
	sed = 0x01;

	nxfers = (length + (I3C_MCTP_PAYLOAD_SIZE - 1)) / I3C_MCTP_PAYLOAD_SIZE;

	xfers = (struct i3c_mctp_xfer *)calloc(nxfers, sizeof(*xfers));
	if (!xfers)
		return -1;
	packet = calloc(nxfers, sizeof(struct i3c_mctp_packet_data));
	if (!packet)
		return -1;
	header = (struct mctp_header *)packet[xfer_index].protocol_hdr;

	header->msg_tag = 0;
	header->to = 0;
	header->pkt_seq = 0;
	header->src_eid = 0;
	header->som = 1;
	header->dest_eid = 0;
	header->header_ver = 0x1;
	payload = packet[xfer_index].payload;
	payload[0] = 0x1;
	payload[1] = 0x2;
	payload[2] = 0x3;
	payload[3] = 0x4;

	for (i = 4; i < 10; i++)
		payload[i] = 0x5a;

	payload[10] = 0;
	payload[11] = 0;
	payload[12] = 0;
	payload[13] = 0;
	payload[14] = sed;
	payload[15] = pattern;

	while (remain_xfer > I3C_MCTP_PAYLOAD_SIZE) {
		header->eom = 0;
		payload_index = header->som ? 17 : 1;
		payload[payload_index - 1] = (pattern + sed) % 0xff;
		for (; payload_index < I3C_MCTP_PAYLOAD_SIZE; payload_index++)
			payload[payload_index] =
				(payload[payload_index - 1] + sed) % 0xff;
		xfer = &xfers[xfer_index];
		xfer->rnw = 0;
		xfer->len = sizeof(struct i3c_mctp_packet_data);
		xfer->data = (__u32 *)&packet[xfer_index];
		xfer_index++;
		memcpy(packet[xfer_index].protocol_hdr, header,
		       I3C_MCTP_HDR_SIZE);
		header = (struct mctp_header *)packet[xfer_index].protocol_hdr;
		header->som = 0;
		header->pkt_seq += 1;
		pattern = payload[I3C_MCTP_PAYLOAD_SIZE - 1] % 0xff;
		remain_xfer -= I3C_MCTP_PAYLOAD_SIZE;
		payload = packet[xfer_index].payload;
	}

	if (remain_xfer) {
		header->eom = 1;
		payload_index = header->som ? 17 : 1;
		payload[payload_index - 1] = (pattern + sed) % 0xff;
		for (; payload_index < remain_xfer; payload_index++)
			payload[payload_index] =
				(payload[payload_index - 1] + sed) % 0xff;

		xfer = &xfers[xfer_index];
		xfer->rnw = 0;
		xfer->len = I3C_MCTP_HDR_SIZE + remain_xfer;
		xfer->data = (__u32 *)&packet[xfer_index];
	}

	for (i = 0; i < nxfers; i++) {
		if (i3c_mctp_priv_xfer(file, &xfers[i]) < 0) {
			fprintf(stdout, "Error: transfer failed: %s\n", strerror(errno));
			return -1;
		}
	}
	free(xfers);
	free(packet);

	return 0;
}

static int verify_test_pattern(int file)
{
	struct i3c_mctp_xfer *xfer;
	struct i3c_mctp_packet *packet;
	struct mctp_header *header;
	unsigned char *payload;
	unsigned char *rx_tmp;
	unsigned char sed = 0;
	unsigned char pattern = 0;
	int cmp_err = 0;
	int mctp_seq_num = 0;
	int mctp_tag = 0;
	int i;

	xfer = (struct i3c_mctp_xfer *)malloc(sizeof(*xfer));
	if (!xfer)
		return -1;
	rx_tmp = (uint8_t *)malloc(MCTP_BTU);
	if (!rx_tmp) {
		free(xfer);
		return -1;
	}
	packet = malloc(sizeof(struct i3c_mctp_packet));
	if (!packet) {
		free(xfer);
		free(rx_tmp);
		return -1;
	}
	xfer->rnw = 1;
	xfer->len = MCTP_BTU;
	xfer->data = (__u32 *)rx_tmp;

	while (1) {
		if (i3c_mctp_priv_xfer(file, xfer) < 0) {
			fprintf(stdout, "Error: Read failed: %s\n",
				strerror(errno));
			return -1;
		}

		memcpy(packet, (void *)(uintptr_t)xfer->data,
		       xfer->len * sizeof(uint8_t));
		packet->size = xfer->len;
		header = (struct mctp_header *)packet->data.protocol_hdr;
		if (!packet->size)
			return -1;
		payload = packet->data.payload;

		if (header->som) {
			mctp_tag = header->msg_tag;
			mctp_seq_num = header->pkt_seq;
			if (!header->eom) {
				mctp_seq_num++;
				mctp_seq_num &= 0x3;
			}
			if (payload[0] != 0x1 || payload[1] != 0x2 ||
			    payload[2] != 0x3 || payload[3] != 0x4)
				cmp_err = 1;

			for (i = 4; i < 10; i++)
				if (payload[i] != 0x5a)
					cmp_err = 1;

			for (i = 10; i < 14; i++)
				if (payload[i] != 0x0)
					cmp_err = 1;

			if (cmp_err) {
				printf("\nHEADER Error !!\n");
				packet_dump(packet);
				return -1;
			}

			sed = payload[14];
			pattern = payload[15];

			for (i = 16; i < packet->size - I3C_MCTP_HDR_SIZE;
			     i++) {
				if (payload[i] !=
				    ((payload[i - 1] + sed) % 0xff)) {
					cmp_err = 1;
					break;
				}
			}
			if (cmp_err) {
				printf("\nPayload Error!!\n");
				packet_dump(packet);
				return -1;
			}
			pattern = payload[i - 1] % 0xff;
		} else {
			if (mctp_tag != header->msg_tag) {
				printf("mctp tag error expected:%x received:%x\n",
				       mctp_tag, header->msg_tag);
				cmp_err = 1;
				packet_dump(packet);
				return -1;
			}
			if (mctp_seq_num != header->pkt_seq) {
				printf("mctp seq error mctp_seq_num %d , header->pkt_seq %d\n",
				       mctp_seq_num, header->pkt_seq);
				cmp_err = 1;
				packet_dump(packet);
				return -1;
			}
			mctp_seq_num++;
			mctp_seq_num &= 0x3;
			if (payload[0] != (pattern + sed) % 0xff)
				cmp_err = 1;
			for (i = 1; i < packet->size - I3C_MCTP_HDR_SIZE; i++) {
				if (payload[i] !=
				    ((payload[i - 1] + sed) % 0xff)) {
					cmp_err = 1;
					break;
				}
			}
			pattern = payload[i - 1] % 0xff;
			if (cmp_err) {
				printf("\nPayload Error!!\n");
				packet_dump(packet);
				return -1;
			}
		}

		if (header->eom)
			break;
	}

	free(xfer);
	free(rx_tmp);
	free(packet);
	return 0;
}
int main(int argc, char *argv[])
{
	struct i3c_mctp_xfer *xfers;
	int file, ret, opt, i, count = 1;
	bool infinity_loop = 0, send_with_test_pattern = 0, rx_with_test_pattern = 0;
	int nxfers = 0;
	int length = 64;
	char *device = NULL;

	if (!argv[1]) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	srand(time(NULL));

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
		case 'c':
			count = strtoul(optarg, 0, 0);
			if (count == 0)
				infinity_loop = 1;
			break;
		case 't':
			send_with_test_pattern = 1;
			length = strtoul(optarg, 0, 0);
			break;
		case 'v':
			rx_with_test_pattern = 1;
			length = strtoul(optarg, 0, 0);
			break;
		case 'm':
			read_timeout_ms = strtoul(optarg, 0, 0);
			if (!read_timeout_ms)
				read_timeout_ms = -1;
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	file = open(device, O_RDWR);
	if (file < 0) {
		printf("Can't open %s ret = %d\n", device, file);
		exit(EXIT_FAILURE);
	}
	if (send_with_test_pattern) {
		while (1) {
			if (send_test_pattern(file, length) < 0)
				exit(EXIT_FAILURE);
			if (verify_test_pattern(file) < 0)
				exit(EXIT_FAILURE);
			if (!infinity_loop && !(--count))
				break;
		}
		fprintf(stdout, "PASS\n");
		exit(EXIT_SUCCESS);
	}

	if (rx_with_test_pattern) {
		while (1) {
			if (verify_test_pattern(file) < 0)
				exit(EXIT_FAILURE);
			if (send_test_pattern(file, length) < 0)
				exit(EXIT_FAILURE);
			if (!infinity_loop && !(--count))
				break;
		}
		fprintf(stdout, "PASS\n");
		exit(EXIT_SUCCESS);
	}

	xfers = (struct i3c_mctp_xfer *)calloc(nxfers, sizeof(*xfers));
	if (!xfers)
		exit(EXIT_FAILURE);

	optind = 1;
	nxfers = 0;
	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) != EOF) {
		switch (opt) {
		case 'h':
		case 'd':
		case 'p':
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
	while (1) {
		for (i = 0; i < nxfers; i++) {
			if (i3c_mctp_priv_xfer(file, &xfers[i]) < 0) {
				fprintf(stdout, "Error: transfer failed: %s\n", strerror(errno));
				ret = EXIT_FAILURE;
				goto err_free;
			}
			fprintf(stdout, "Success on message %d\n", i);
			if (xfers[i].rnw)
				print_rx_data(&xfers[i]);
		}
		if (!infinity_loop && !(--count))
			break;
	}
	ret = EXIT_SUCCESS;
err_free:
	for (i = 0; i < nxfers; i++)
		free((void *)(uintptr_t)xfers[i].data);
	free(xfers);
	return ret;
}
