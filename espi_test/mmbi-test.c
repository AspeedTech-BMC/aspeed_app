/*
 * Copyright 2021 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <mtd/mtd-user.h>
#include <byteswap.h>
#include <poll.h>

/* based on MMBI draft */
struct mmbi_desc {
	uint32_t h2b_base;
	uint32_t b2h_base;
	uint8_t h2b_cb_depth;
	uint8_t b2h_cb_depth;
	uint8_t rsvd[2];
	uint32_t host_rop_ptr;
	uint32_t host_rwp_ptr;
	uint8_t TBD[12];
} __attribute__((packed));

struct host_rwp {
	uint32_t h_rdy : 1;
	uint32_t h_rst : 1;
	uint32_t h2b_cb_wptr : 30;
	uint32_t b2h_cb_rptr;
} __attribute__((packed));

struct host_rop {
	uint32_t b_rdy : 1;
	uint32_t b_rst : 1;
	uint32_t h2b_cb_rptr : 30;
	uint32_t b2h_cb_wptr;
} __attribute__((packed));

struct mmbi_context {
	int b2h_fd;
	char b2h_dev[256];
	void *b2h_map;

	int h2b_fd;
	char h2b_dev[256];
	void *h2b_map;

	uint32_t map_sz;
};
static struct mmbi_context mmbi_ctx[1];

static const char opt_short[] = "b:h:s:";

static const struct option opt_long [] = {
	{ "b2h-dev",	required_argument,	NULL,		'b'	},
	{ "h2b-dev",	required_argument,	NULL,       'h' },
	{ "size",		required_argument,	NULL,       's' },
	{ 0, 0, 0, 0 }
};

static void print_usage(int argc, char **argv)
{
	printf(
			"Usage: %s [options]\n"
			"eSPI MMBI test\n\n"
			"Options:\n"
			" -b | --b2h-dev    eSPI MMBI B2H device node\n"
			" -h | --h2b-dev    eSPI MMBI H2B device node\n"
			" -s | --size       eSPI MMBI instance size\n"
			"",
			argv[0]);
}

void mmbi_loop(void)
{
	int i, rc;
	struct pollfd fds;

	struct mmbi_desc *d = mmbi_ctx->b2h_map;

	struct host_rop *h_rop = (struct host_rop *)(d + 1);
	struct host_rwp *h_rwp = mmbi_ctx->h2b_map;

	uint8_t *b2h_cb = (uint8_t *)(h_rop + 1);
	uint32_t b2h_cbsz = mmbi_ctx->map_sz - sizeof(*d) - sizeof(*h_rop);

	uint8_t *h2b_cb = (uint8_t *)(h_rwp + 1);
	uint32_t h2b_cbsz = mmbi_ctx->map_sz - sizeof(*h_rwp);

	uint8_t data;
	uint32_t h2b_rptr, h2b_wptr;

	/* init mmbi desc */
	d->h2b_base = (mmbi_ctx->map_sz * 8) + sizeof(struct host_rwp);
	d->b2h_base = sizeof(struct mmbi_desc) + sizeof(struct host_rop);
	d->h2b_cb_depth = __builtin_ctz(mmbi_ctx->map_sz);
	d->b2h_cb_depth = __builtin_ctz(mmbi_ctx->map_sz);
	d->host_rop_ptr = d->b2h_base - sizeof(struct host_rop);
	d->host_rwp_ptr = d->h2b_base - sizeof(struct host_rwp);

	/* init host read-only pointers */
	h_rop->b_rdy = 1;
	h_rop->b_rst = 0;
	h_rop->h2b_cb_rptr = 0;
	h_rop->b2h_cb_wptr = 0;

	fds.fd = mmbi_ctx->h2b_fd;
	fds.events = POLLIN;

	while (1) {
		rc = poll(&fds, 1, -1);
		if (rc <= 0) {
			printf("rc=%d\n", rc);
			continue;
		}

		printf("H2B write:");

		i = 0;
		h2b_rptr = h_rop->h2b_cb_rptr << 2;
		h2b_wptr = h_rwp->h2b_cb_wptr << 2;

		while (h2b_rptr != h2b_wptr) {
			if ((i++ % 16) == 0)
				printf("\n");

			data = h2b_cb[h2b_rptr];
			printf("%02x ", data);
			b2h_cb[h_rop->b2h_cb_wptr] = data + 1;

			h2b_rptr++;
			h2b_rptr %= h2b_cbsz;

			h_rop->b2h_cb_wptr++;
			h_rop->b2h_cb_wptr %= b2h_cbsz;
		}

		h_rop->h2b_cb_rptr = h2b_rptr >> 2;

		printf("\n");
		fflush(stdout);
	}
}

int main(int argc, char *argv[])
{
	char opt;

	while ((opt=getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char)-1) {
		switch(opt) {
		case 'b':
			strcpy(mmbi_ctx->b2h_dev, optarg);
			break;
		case 'h':
			strcpy(mmbi_ctx->h2b_dev, optarg);
			break;
		case 's':
			mmbi_ctx->map_sz = strtoul(optarg, NULL, 0);
			break;
		default:
			print_usage(argc, argv);
			return -1;
		}
	}

	if (strlen(mmbi_ctx->b2h_dev) == 0 ||
		strlen(mmbi_ctx->h2b_dev) == 0 ||
		!mmbi_ctx->map_sz) {
		print_usage(argc, argv);
		return -1;
	}

	mmbi_ctx->b2h_fd = open(mmbi_ctx->b2h_dev, O_RDWR);
	if (mmbi_ctx->b2h_fd == -1) {
		printf("cannot open eSPI MMBI B2H device\n");
		return -1;
	}

	mmbi_ctx->h2b_fd = open(mmbi_ctx->h2b_dev, O_RDWR);
	if (mmbi_ctx->h2b_fd == -1) {
		printf("cannot open eSPI MMBI H2B device\n");
		return -1;
	}

	mmbi_ctx->map_sz += (getpagesize() - 1);
	mmbi_ctx->map_sz /= getpagesize();
	mmbi_ctx->map_sz *= getpagesize();

	mmbi_ctx->b2h_map = mmap(NULL, mmbi_ctx->map_sz,
			PROT_READ | PROT_WRITE, MAP_SHARED, mmbi_ctx->b2h_fd, 0);
	if (mmbi_ctx->b2h_map == MAP_FAILED) {
		printf("cannot map MMBI B2H region\n");
		perror("la");
		return -1;
	}

	mmbi_ctx->h2b_map = mmap(NULL, mmbi_ctx->map_sz,
			PROT_READ, MAP_SHARED, mmbi_ctx->h2b_fd, 0);
	if (mmbi_ctx->h2b_map == MAP_FAILED) {
		printf("cannot map MMBI H2B region\n");
		return -1;
	}

	mmbi_loop();

	close(mmbi_ctx->b2h_fd);
	close(mmbi_ctx->h2b_fd);

	return 0;
}
