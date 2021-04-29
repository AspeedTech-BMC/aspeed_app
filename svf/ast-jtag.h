/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */
enum jtag_xfer_mode {
	HW_MODE = 0,
	SW_MODE,
};

enum jtag_xfer_type {
	JTAG_SIR_XFER = 0,
	JTAG_SDR_XFER = 1,
};

enum jtag_endstate {
	JTAG_TLRESET,
	JTAG_IDLE,
	JTAG_PAUSEDR,
	JTAG_PAUSEIR,
	JTAG_SHIFTDR,
	JTAG_SHIFTIR
};

struct jtag_runtest_idle {
	enum jtag_xfer_mode mode;
	enum jtag_endstate end;
	unsigned int tck;
};

struct jtag_xfer {
	enum jtag_xfer_mode mode;
	enum jtag_xfer_type type;
	unsigned short length;
	unsigned int *tdi;
	unsigned int *tdo;
	enum jtag_endstate end_sts;
};

struct io_xfer {
	enum jtag_xfer_mode mode;
	unsigned long Address;
	unsigned long Data;
};

struct trst_reset {
	unsigned long operation;
	unsigned long Data;
};

#define JTAGIOC_BASE 'T'

#define ASPEED_JTAG_IOCRUNTEST _IOW(JTAGIOC_BASE, 0, struct jtag_runtest_idle)
#define ASPEED_JTAG_IOCXFER _IOWR(JTAGIOC_BASE, 1, struct jtag_xfer)
#define ASPEED_JTAG_SIOCFREQ _IOW(JTAGIOC_BASE, 2, unsigned int)
#define ASPEED_JTAG_GIOCFREQ _IOR(JTAGIOC_BASE, 3, unsigned int)
#define ASPEED_JTAG_IOWRITE _IOW(JTAGIOC_BASE, 4, struct io_xfer)
#define ASPEED_JTAG_IOREAD _IOR(JTAGIOC_BASE, 5, struct io_xfer)
#define ASPEED_JTAG_RESET _IOW(JTAGIOC_BASE, 6, struct io_xfer)
#define ASPEED_JTAG_TRST_RESET _IOW(JTAGIOC_BASE, 7, struct trst_reset)
#define ASPEED_JTAG_RUNTCK _IOW(JTAGIOC_BASE, 8, struct io_xfer)
/******************************************************************************************************************/
int ast_jtag_open(char *dev);
void ast_jtag_close(void);
unsigned int ast_get_jtag_freq(void);
int ast_set_jtag_freq(unsigned int freq);
int ast_jtag_run_test_idle(unsigned char end, unsigned int tck);
int ast_jtag_xfer(unsigned char endsts, unsigned int len, unsigned int *out, unsigned int *in, enum jtag_xfer_type type);