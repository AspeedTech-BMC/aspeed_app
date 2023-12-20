// SPDX-License-Identifier: GPL-2.0
//
// mctp-echo: MCTP echo server, for testing.
//
// Copyright (c) 2021 Code Construct
// Copyright (c) 2021 Google

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <err.h>
#include <string.h>
#include <sys/socket.h>
#include "mctp.h"

bool debug;
bool skip;
static const int DEFAULT_NET = 1;
static const mctp_eid_t DEFAULT_EID = 8;
static const size_t DEFAULT_LEN = 1;

static void usage(void)
{
	fprintf(stderr, "mctp-echo [type <type>] [skip 1] [debug 1]\n");
	fprintf(stderr, "default eid %d net %d len %zd\n",
			DEFAULT_EID, DEFAULT_NET, DEFAULT_LEN);
}

int main(int argc, char **argv)
{
	struct sockaddr_mctp addr;
	unsigned char *buf;
	socklen_t addrlen;
	size_t buflen;
	ssize_t len;
	char *endp, *optname, *optval;
	u8 type = 1;
	unsigned int tmp;
	int rc, sd;

	if (!(argc % 2)) {
		warnx("extra argument %s", argv[argc - 1]);
		usage();
		return 255;
	}

	for (int i = 1; i < argc; i += 2) {
		optname = argv[i];
		optval = argv[i + 1];

		tmp = strtoul(optval, &endp, 0);

		if (!strcmp(optname, "debug")) {
			debug = true;
		} else if (!strcmp(optname, "skip")) {
			skip = true;
		} else if (!strcmp(optname, "type")) {
			if (tmp > 0xff)
				errx(EXIT_FAILURE, "Bad type");
			type = tmp;
		}
	}
	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = type;
	addr.smctp_tag = MCTP_TAG_OWNER;

	buflen = 0;
	buf = NULL;

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		err(EXIT_FAILURE, "bind");

	for (;;) {
		len = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
		if (len < 0) {
			warn("recvfrom(MSG_PEEK)");
			continue;
		}

		if ((size_t)len > buflen) {
			buflen = len;
			buf = realloc(buf, buflen);
			if (!buf)
				err(EXIT_FAILURE, "realloc(%zd)", buflen);
		}

		addrlen = sizeof(addr);
		len = recvfrom(sd, buf, buflen, 0,
				(struct sockaddr *)&addr, &addrlen);
		if (len < 0) {
			warn("recvfrom");
			continue;
		}

		if (addrlen != sizeof(addr)) {
			warnx("unknown address length %d, exp %zd",
				addrlen, sizeof(addr));
			continue;
		}

		if (debug) {
			printf("recv: message from (net %d, eid %d), tag %d, type %d: len %zd",
					addr.smctp_network, addr.smctp_addr.s_addr,
					addr.smctp_tag,
					addr.smctp_type,
					len);

			printf("data:\n");
			for (int i = 0; i < len; i++)
				printf("0x%02x ", buf[i]);
			printf("\n");
		}

		// If has [skip 1], skip echo request message to requester.
		if (skip)
			continue;

		addr.smctp_tag &= ~MCTP_TAG_OWNER;

		rc = sendto(sd, buf, len, 0,
				(struct sockaddr *)&addr, sizeof(addr));

		if (rc != (int)len) {
			warn("sendto");
			continue;
		}
	}

	return EXIT_SUCCESS;
}
