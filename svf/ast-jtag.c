// SPDX-License-Identifier: GPL-2.0+
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
	retval = ioctl(jtag_fd, JTAG_GIOCFREQ, &freq);
	if (retval == -1) {
		perror("ioctl JTAG get freq fail!\n");
		return 0;
	}

	return freq;
}

int ast_set_jtag_mode(uint8_t sw_mode)
{
	struct jtag_mode jtag_mode;
	int retval;

	jtag_mode.feature = JTAG_XFER_MODE;
	jtag_mode.mode = sw_mode ? JTAG_XFER_SW_MODE : JTAG_XFER_HW_MODE;
	retval = ioctl(jtag_fd, JTAG_SIOCMODE, &jtag_mode);
	if (retval == -1) {
		perror("ioctl JTAG set mode fail!\n");
		return -1;
	}
	return 0;
}

int ast_set_jtag_freq(unsigned int freq)
{
	int retval;
	unsigned int jtag_freq = freq;
	retval = ioctl(jtag_fd, JTAG_SIOCFREQ, &jtag_freq);
	if (retval == -1) {
		perror("ioctl JTAG set freq fail!\n");
		return -1;
	}

	return 0;
}

int ast_set_jtag_trst(unsigned int active)
{
	int retval;
	unsigned int trst_active = active;

	retval = ioctl(jtag_fd, JTAG_SIOCTRST, &trst_active);
	if (retval == -1) {
		perror("ioctl JTAG set trst fail!\n");
		return -1;
	}
	return 0;
}

int ast_get_tap_state(enum jtag_tapstate* tap_state)
{
	int retval;

	if (tap_state == NULL)
		return -1;
	retval = ioctl(jtag_fd, JTAG_GIOCSTATUS, tap_state);
	if (retval == -1) {
		perror("ioctl JTAG get tap state fail!\n");
		return -1;
	}
	return 0;
}

int ast_jtag_run_test_idle(unsigned char end, unsigned int tck)
{
	int retval;
	struct jtag_tap_state run_idle;
	__u8 execute_tck;

	while (tck) {
		execute_tck = tck > 0xff ? 0xff : tck;
		run_idle.from = JTAG_STATE_CURRENT;
		run_idle.reset = JTAG_NO_RESET;
		run_idle.endstate = end;
		run_idle.tck = execute_tck;

		ast_jtag_printf("from:%d, reset:%d, endstate:%d, tck:%d\n",
				run_idle.from, run_idle.reset,
				run_idle.endstate, run_idle.tck);

		retval = ioctl(jtag_fd, JTAG_SIOCSTATE, &run_idle);
		if (retval == -1) {
			perror("ioctl JTAG run reset fail!\n");
			return -1;
		}
		tck -= execute_tck;
	}

//	if(end)
//		usleep(3000);

	return 0;
}

int ast_jtag_xfer(unsigned char endsts, unsigned int len, unsigned int *out, unsigned int *in, enum jtag_xfer_type type)
{
	int 	retval;
	enum jtag_tapstate current_state;
	struct jtag_xfer xfer;
	unsigned int send_len_byte;

	ast_get_tap_state(&current_state);
	xfer.type = type;
	xfer.direction = JTAG_READ_WRITE_XFER;
	xfer.from = current_state;
	xfer.endstate = endsts;
	xfer.padding = 0;
	xfer.length = len;
	xfer.tdio = (__u64)out;
	send_len_byte = DIV_ROUND_UP(xfer.length, BITS_PER_BYTE);

#if DEBUG
	int i;
	for (i = 0; i < DIV_ROUND_UP(send_len_byte, 4); i++)
		ast_jtag_printf("tdo:%08x\n", out[i]);
#endif
	retval = ioctl(jtag_fd, JTAG_IOCXFER, &xfer);
	if (retval == -1) {
		perror("ioctl JTAG sir fail!\n");
		return -1;
	}
	memcpy(in, out, send_len_byte);
#if DEBUG
	for (i = 0; i < DIV_ROUND_UP(send_len_byte, 4); i++)
		ast_jtag_printf("tdi:%08x\n",out[i]);
#endif
	return 0;
}
