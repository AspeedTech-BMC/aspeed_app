/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright 2021 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>
#include <linux/types.h>
/*************************************************************************************/
#define ASPEED_MCTP_XFER_SIZE 4096

/*
 * MCTP operations
 * @ASPEED_MCTP_IOCTL_FILTER_EID: enable/disable filter incoming packets based
 * on Endpoint ID (BROKEN)
 * @ASPEED_MCTP_IOCTL_GET_BDF: read PCI bus/device/function of MCTP Controller
 * @ASPEED_MCTP_IOCTL_GET_MEDIUM_ID: read MCTP physical medium identifier
 * related to PCIe revision
 * @ASPEED_MCTP_IOCTL_GET_MTU: read max transmission unit (in bytes)
 * @ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER Register client as default
 * handler that receives all MCTP messages that were not dispatched to other
 * clients
 * @ASPEED_MCTP_IOCTL_REGISTER_TYPE_HANDLER Register client to receive all
 * messages of specified MCTP type or PCI vendor defined type
 * @ASPEED_MCTP_IOCTL_UNREGISTER_TYPE_HANDLER Unregister client as handler
 * for specified MCTP type or PCI vendor defined message type
 * @ASPEED_MCTP_GET_EID_INFO: read list of existing endpoint mappings
 * returns count which is less of the two requested count and existing count
 * @ASPEED_MCTP_SET_EID_INFO: write list of endpoint mappings
 * overwrites already existing endpoint mappings
 */

struct aspeed_mctp_filter_eid {
	__u8 eid;
	bool enable;
};

struct aspeed_mctp_get_bdf {
	__u16 bdf;
};

struct aspeed_mctp_get_medium_id {
	__u8 medium_id;
};

struct aspeed_mctp_get_mtu {
	__u16 mtu;
};

struct aspeed_mctp_type_handler_ioctl {
	__u8 mctp_type;		/* MCTP message type as per DSP239*/
	/* Below params must be 0 if mctp_type is not Vendor Defined PCI */
	__u16 pci_vendor_id;	/* PCI Vendor ID */
	__u16 vendor_type;	/* Vendor specific type */
	__u16 vendor_type_mask; /* Mask applied to vendor type */
};

struct aspeed_mctp_eid_info {
	__u8 eid;
	__u16 bdf;
};

struct aspeed_mctp_get_eid_info {
	__u64 ptr;
	__u16 count;
	__u8 start_eid;
};

struct aspeed_mctp_set_eid_info {
	__u64 ptr;
	__u16 count;
};

#define ASPEED_MCTP_IOCTL_BASE 0x4d

#define ASPEED_MCTP_IOCTL_FILTER_EID                                           \
	_IOW(ASPEED_MCTP_IOCTL_BASE, 0, struct aspeed_mctp_filter_eid)
#define ASPEED_MCTP_IOCTL_GET_BDF                                              \
	_IOR(ASPEED_MCTP_IOCTL_BASE, 1, struct aspeed_mctp_get_bdf)
#define ASPEED_MCTP_IOCTL_GET_MEDIUM_ID                                        \
	_IOR(ASPEED_MCTP_IOCTL_BASE, 2, struct aspeed_mctp_get_medium_id)
#define ASPEED_MCTP_IOCTL_GET_MTU                                              \
	_IOR(ASPEED_MCTP_IOCTL_BASE, 3, struct aspeed_mctp_get_mtu)
#define ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER                             \
	_IO(ASPEED_MCTP_IOCTL_BASE, 4)
#define ASPEED_MCTP_IOCTL_REGISTER_TYPE_HANDLER                                \
	_IOW(ASPEED_MCTP_IOCTL_BASE, 6, struct aspeed_mctp_type_handler_ioctl)
#define ASPEED_MCTP_IOCTL_UNREGISTER_TYPE_HANDLER                              \
	_IOW(ASPEED_MCTP_IOCTL_BASE, 7, struct aspeed_mctp_type_handler_ioctl)
#define ASPEED_MCTP_IOCTL_GET_EID_INFO                                         \
	_IOWR(ASPEED_MCTP_IOCTL_BASE, 8, struct aspeed_mctp_get_eid_info)
#define ASPEED_MCTP_IOCTL_SET_EID_INFO                                         \
	_IOW(ASPEED_MCTP_IOCTL_BASE, 9, struct aspeed_mctp_set_eid_info)

#define ASPEED_MCTP_PCIE_VDM_HDR_SIZE 16
#define ASPEED_MCTP_PCIE_VDM_HDR_SIZE_DW 4

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (a)-1)

#define ASPEED_MCTP_DEBUG

#ifdef ASPEED_MCTP_DEBUG
#define MCTP_DBUG(fmt, args...) printf("%s() " fmt, __func__, ##args)
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
	unsigned int *header;
	unsigned char *xfer_buff;
	unsigned int buf_len;
};

struct mctp_binding_astpcie {
	int fd;
	__u16 mtu;
};

void mctp_swap_pcie_vdm_hdr(struct aspeed_mctp_xfer *data);
void wait_for_message(struct mctp_binding_astpcie *astpcie);
struct mctp_binding_astpcie *aspeed_mctp_init(char *dev);
void aspeed_mctp_free(struct mctp_binding_astpcie *astpcie);
int aspeed_mctp_send(struct mctp_binding_astpcie *astpcie,
		     struct aspeed_mctp_xfer *xfer);
int aspeed_mctp_recv(struct mctp_binding_astpcie *astpcie,
		     struct aspeed_mctp_xfer *xfer);
int aspeed_mctp_register_default_handler(struct mctp_binding_astpcie *astpcie);
int aspeed_mctp_get_mtu(struct mctp_binding_astpcie *astpcie);
