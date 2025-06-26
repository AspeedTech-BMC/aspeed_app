// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2021 Aspeed Technology Inc.
 */
#include "libmctp.h"

void mctp_swap_pcie_vdm_hdr(struct aspeed_mctp_xfer *xfer)
{
	int i;

	for (i = 0; i < 4; i++)
		xfer->header[i] = htobe32(xfer->header[i]);
}

struct mctp_binding_astpcie *aspeed_mctp_init(char *dev)
{
	struct mctp_binding_astpcie *astpcie;

	astpcie = malloc(sizeof(struct mctp_binding_astpcie));

	astpcie->fd = open(dev, O_RDWR, 0);
	if (astpcie->fd == -1)
		return NULL;
	/* close on exec */
	if (fcntl(astpcie->fd, F_SETFD, 1) == -1) {
		close(astpcie->fd);
		astpcie->fd = -1;
		return NULL;
	}
	return astpcie;
}

void aspeed_mctp_free(struct mctp_binding_astpcie *astpcie)
{
	close(astpcie->fd);
}

static int aspeed_mctp_poll(struct mctp_binding_astpcie *astpcie, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = astpcie->fd;
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

int aspeed_mctp_recv(struct mctp_binding_astpcie *astpcie,
		     struct aspeed_mctp_xfer *xfer)
{
	int ret;

	ret = read(astpcie->fd, xfer->header, ASPEED_MCTP_XFER_SIZE);
	if (ret < 0) {
		MCTP_DBUG("err\n");
		perror("MCTP read error!\n");
	}
	return ret;
}

int aspeed_mctp_send(struct mctp_binding_astpcie *astpcie,
		     struct aspeed_mctp_xfer *xfer)
{
	int ret;

	ret = write(astpcie->fd, xfer->header,
		    xfer->buf_len + ASPEED_MCTP_PCIE_VDM_HDR_SIZE);
	if (ret < 0) {
		perror("MCTP write error!\n");
		return ret;
	}
	return ret;
}

void wait_for_message(struct mctp_binding_astpcie *astpcie)
{
	int rc;
	bool received = false;

	while (!received) {
		rc = aspeed_mctp_poll(astpcie, 1000);
		if (rc & POLLIN)
			received = true;
	}
}

void wait_for_xfer_done(struct mctp_binding_astpcie *astpcie)
{
	int rc;
	bool xfered = false;

	while (!xfered) {
		rc = aspeed_mctp_poll(astpcie, 1000);
		if (rc & POLLOUT)
			xfered = true;
	}
}

int aspeed_mctp_register_type_handler(struct mctp_binding_astpcie *astpcie, unsigned char type)
{
	struct aspeed_mctp_type_handler_ioctl type_handler;

	type_handler.mctp_type = type;
	type_handler.pci_vendor_id = ASPEED_MCTP_VENDOR_ID;
	type_handler.vendor_type = ASPEED_MCTP_VENDOR_TYPE;
	type_handler.vendor_type_mask = ASPEED_MCTP_VENDOR_TYPE_MASK;

	return ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_REGISTER_TYPE_HANDLER, &type_handler);
}

int aspeed_mctp_unregister_type_handler(struct mctp_binding_astpcie *astpcie, unsigned char type)
{
	struct aspeed_mctp_type_handler_ioctl type_handler;

	type_handler.mctp_type = type;
	type_handler.pci_vendor_id = ASPEED_MCTP_VENDOR_ID;
	type_handler.vendor_type = ASPEED_MCTP_VENDOR_TYPE;
	type_handler.vendor_type_mask = ASPEED_MCTP_VENDOR_TYPE_MASK;

	return ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_UNREGISTER_TYPE_HANDLER, &type_handler);
}

int aspeed_mctp_register_default_handler(struct mctp_binding_astpcie *astpcie)
{
	return ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER);
}

int aspeed_mctp_get_mtu(struct mctp_binding_astpcie *astpcie)
{
	struct aspeed_mctp_get_mtu get_mtu;
	int rc;

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_MTU,
		   &get_mtu);
	if (!rc)
		astpcie->mtu = get_mtu.mtu;
	printf("astpcie->mtu = %d\n", astpcie->mtu);

	return rc;
}
