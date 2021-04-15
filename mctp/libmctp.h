/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>
#include <linux/types.h>
#include <pthread.h>
#include "list.h"

/*************************************************************************************/
#define ASPEED_MCTP_XFER_SIZE	4096
#define MCTPIOC_BASE			'M'
#define ASPEED_MCTP_IOCTX		_IOW(MCTPIOC_BASE, 0, struct aspeed_mctp_xfer*)
#define ASPEED_MCTP_IOCRX		_IOR(MCTPIOC_BASE, 1, struct aspeed_mctp_xfer*)

#define EMPTY			0
#define START			(1 << 1)
#define END				(1 << 2)
#define NONE			(1 << 3)


//#define ASPEED_MCTP_DEBUG

#ifdef ASPEED_MCTP_DEBUG
#define MCTP_DBUG(fmt, args...) printf("%s() " fmt,__FUNCTION__, ## args)
#else
#define MCTP_DBUG(fmt, args...)
#endif

/*************************************************************************************/
struct pcie_vdm_header {
	__u32		length: 10,
				revd0: 2,
				attr: 2,
				ep: 1,
				td: 1,
				revd1: 4,
				tc: 3,
				revd2: 1,
				type_routing: 5,
				fmt: 2,
				revd3: 1;
	__u8		message_code;
	__u8		vdm_code: 4,
				pad_len: 2,
				tag_revd: 2;
	__u16		pcie_req_id;
	__u16		vender_id;
	__u16		pcie_target_id;
	__u8		msg_tag: 3,
				to: 1,
				pkt_seq: 2,
				eom: 1,
				som: 1;
	__u8		src_epid;
	__u8		dest_epid;
	__u8		header_ver: 4,
				rsvd: 4;
};

struct aspeed_mctp_xfer {
	unsigned char *xfer_buff;
	struct pcie_vdm_header header;
};

struct aspeed_mctp_rx_list {
	struct list_head list;
	struct list_head xfer_head;
	struct aspeed_mctp_xfer *seq_buff[4];
	unsigned int seq;
	unsigned int recv_sts;
	unsigned int ep_id; //source end point id
	unsigned int tag_owner; //header TO
	unsigned int msg_tag; //header TO
	unsigned int routing; //routing type
};

struct aspeed_mctp_xfer_list {
	struct list_head list;
	struct aspeed_mctp_xfer *xfer;
};

struct aspeed_mctp_ctx {
	struct list_head rx_list;
	pthread_t recv_thread;
	pthread_mutex_t mutex;
	int mctp_fd;
	int recv_flag;
};

int aspeed_mctp_init(char *dev);
void aspeed_mctp_exit(void);
void aspeed_mctp_rx_pool_thread_init();
int aspeed_mctp_send(struct aspeed_mctp_xfer *xfer);
int aspeed_mctp_recv(struct aspeed_mctp_xfer *xfer);
void release_xfer(struct aspeed_mctp_xfer *xfer);