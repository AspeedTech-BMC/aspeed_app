/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>

#include <sys/mman.h>
#include "ast-jtag.h"

int jtag_fd;
int mode;

#define DEBUG 0

#if DEBUG
#define ast_jtag_printf(...) printf(__VA_ARGS__)
#else
#define ast_jtag_printf(...)
#endif 

/*************************************************************************************/
/*				AST JTAG LIB					*/
int ast_jtag_open(char *dev)
{
	jtag_fd = open(dev, O_RDWR);
	if (jtag_fd == -1) {
		printf("Can't open %s, please install driver!! \n", dev);
		return -1;
	}
	return 0;
}

void ast_jtag_close(void)
{
	close(jtag_fd);
}

unsigned int ast_get_jtag_freq(void)
{
	int retval;
	unsigned int freq = 0;
	retval = ioctl(jtag_fd, ASPEED_JTAG_GIOCFREQ, &freq);
	if (retval == -1) {
		perror("ioctl JTAG run reset fail!\n");
		return 0;
	}

	return freq;
}

int ast_set_jtag_freq(unsigned int freq)
{
	int retval;
	retval = ioctl(jtag_fd, ASPEED_JTAG_SIOCFREQ, freq);
	if (retval == -1) {
		perror("ioctl JTAG run reset fail!\n");
		return -1;
	}

	return 0;
}

int ast_jtag_run_test_idle(unsigned char end, unsigned int tck)
{
	int retval;
	struct jtag_runtest_idle run_idle;

	run_idle.mode = mode;
	run_idle.end = end;
	run_idle.tck = tck;

	retval = ioctl(jtag_fd, ASPEED_JTAG_IOCRUNTEST, &run_idle);
	if (retval == -1) {
		perror("ioctl JTAG run reset fail!\n");
		return -1;
	}

//	if(end)
//		usleep(3000);

	return 0;
}

int ast_jtag_xfer(unsigned char endsts, unsigned int len, unsigned int *out, unsigned int *in, enum jtag_xfer_type type)
{
	int 	retval;
	struct jtag_xfer xfer;

	xfer.mode = mode;
	xfer.length = len;
	xfer.end_sts = endsts;
	xfer.tdo = in;
	xfer.tdi = out;
	xfer.type = type;
#if DEBUG
	int i, send_len;
	send_len = xfer.length >> 5;
	if (xfer.length & 0x1f)
		send_len++;
	for (i = 0; i < send_len; i++)
		ast_jtag_printf("tdo:%08x tdi:%08x\n",xfer.tdo[i], xfer.tdi[i]);
#endif
	retval = ioctl(jtag_fd, ASPEED_JTAG_IOCXFER, &xfer);
	if (retval == -1) {
		perror("ioctl JTAG sir fail!\n");
		return -1;
	}
#if DEBUG
	for (i = 0; i < send_len; i++)
		ast_jtag_printf("tdo:%08x tdi:%08x\n",xfer.tdo[i], xfer.tdi[i]);
#endif
	return 0;
}
