/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "libmctp.h"

static struct aspeed_mctp_ctx mctp_ctx = {
	.rx_list = LIST_HEAD_INIT(mctp_ctx.rx_list),
	.recv_flag = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

void aspeed_mctp_recv_list_init(struct aspeed_mctp_rx_list *rx_entry)
{
	int i;

	MCTP_DBUG("\n");
	INIT_LIST_HEAD(&rx_entry->xfer_head);
	for (i = 0; i < 4; i++)
		rx_entry->seq_buff[i] = NULL;
	rx_entry->seq = 3;
	rx_entry->recv_sts = EMPTY;
	list_add_tail(&rx_entry->list, &mctp_ctx.rx_list);
}

int aspeed_mctp_recv_list_delete(struct aspeed_mctp_rx_list *rx_entry)
{
	struct aspeed_mctp_xfer_list *tmp, *tmpb;

	MCTP_DBUG("\n");
	list_for_each_entry_safe(tmp, tmpb, &rx_entry->xfer_head, list) {
		free(tmp->xfer->xfer_buff);
		free(tmp->xfer);
		list_del(&tmp->list);
		free(tmp);
	}
	list_del(&rx_entry->list);
	free(rx_entry);
	return 0;
}

void aspeed_mctp_add_xfer_list(struct aspeed_mctp_rx_list *rx_entry, struct aspeed_mctp_xfer *xfer)
{
	struct aspeed_mctp_xfer_list *xfer_list;

	MCTP_DBUG("\n");
	xfer_list = malloc(sizeof(struct aspeed_mctp_xfer_list));
	xfer_list->xfer = xfer;
	list_add_tail(&xfer_list->list, &rx_entry->xfer_head);
}

void seq_buffer_add_to_list(struct aspeed_mctp_rx_list *rx_entry)
{
	const int SEQ = rx_entry->seq;
	int cur = 0;
	int i;

	MCTP_DBUG("\n");
	for (i = 1; i <= 4; i ++) {
		cur = (i + SEQ) % 4;
		if (rx_entry->seq_buff[cur] == NULL)
			break;
		aspeed_mctp_add_xfer_list(rx_entry, rx_entry->seq_buff[cur]);
		rx_entry->seq_buff[cur] = NULL;
		rx_entry->seq = cur;
	}
}

int aspeed_mctp_recv_list(struct aspeed_mctp_xfer *xfer)
{
	struct list_head *rx_list = &mctp_ctx.rx_list;
	struct aspeed_mctp_rx_list *tmp, *rx_entry = NULL;
	struct pcie_vdm_header *header = &xfer->header;
	int msg_tag = header->msg_tag;
	int EID = header->src_epid;
	int TO  = header->to;
	int SOM = header->som;
	int EOM = header->eom;
	int SEQ = header->pkt_seq;

	MCTP_DBUG("\n");
	MCTP_DBUG("SOM = %d, EOM = %d, SEQ = %d\n", SOM, EOM, SEQ);
	MCTP_DBUG("EID = %d, TO = %d, msg_tag = %d\n", EID, TO, msg_tag);
	list_for_each_entry(tmp, rx_list, list) {
		MCTP_DBUG("find list\n");
		MCTP_DBUG("tmp->recv_sts = %d\n", tmp->recv_sts);
		if (EID == tmp->ep_id && TO == tmp->tag_owner &&
			msg_tag == tmp->msg_tag && !((tmp->recv_sts & START) && (tmp->recv_sts & END))) {
			MCTP_DBUG("hit\n");
			rx_entry = tmp;
			break;
		}
	}
	MCTP_DBUG("a\n");
	if (rx_entry == NULL)
		goto new_entry;

	MCTP_DBUG("rx_entry->seq = %d\n", rx_entry->seq);
	MCTP_DBUG("rx_entry->ep_id = %d\n", rx_entry->ep_id);
	MCTP_DBUG("rx_entry->tag_owner = %d\n", rx_entry->tag_owner);
	MCTP_DBUG("rx_entry->msg_tag = %d\n", rx_entry->msg_tag);
	MCTP_DBUG("rx_entry = %x\n", rx_entry);

	if (rx_entry->seq_buff[SEQ] != NULL) {
		// packet loss
		MCTP_DBUG("packet_loss\n");
		aspeed_mctp_recv_list_delete(rx_entry);
		goto new_entry;
	}

	if (SOM) {
		if (rx_entry->recv_sts & START) {
			// packet loss
			aspeed_mctp_recv_list_delete(rx_entry);
			goto new_entry;
		}
		rx_entry->recv_sts |= START;
	}
	if (EOM) {
		if (rx_entry->recv_sts & END) {
			// packet loss
			aspeed_mctp_recv_list_delete(rx_entry);
			goto new_entry;
		}
		if (!(rx_entry->recv_sts & START)) {
			// packet loss
			aspeed_mctp_recv_list_delete(rx_entry);
			free(xfer->xfer_buff);
			free(xfer);
			return 0;
		}
		rx_entry->recv_sts |= END;
	}

	if (SEQ == (rx_entry->seq + 1) % 4) {
		aspeed_mctp_add_xfer_list(rx_entry, xfer);
		rx_entry->seq = SEQ;
	} else {
		rx_entry->seq_buff[SEQ] = xfer;
	}
	seq_buffer_add_to_list(rx_entry);

	return 0;
new_entry:
	rx_entry = malloc(sizeof(struct aspeed_mctp_rx_list));
	aspeed_mctp_recv_list_init(rx_entry);
	MCTP_DBUG("rx_entry = %x\n", rx_entry);
	rx_entry->ep_id = EID;
	rx_entry->tag_owner = TO;
	rx_entry->msg_tag = msg_tag;
	rx_entry->routing = header->type_routing;
	if (SOM) {
		aspeed_mctp_add_xfer_list(rx_entry, xfer);
		rx_entry->seq = SEQ;
		rx_entry->recv_sts |= START;
	} else {
		rx_entry->seq_buff[SEQ] = xfer;
		rx_entry->seq = 3; //expect to recv seq 0
	}
	if (EOM)
		rx_entry->recv_sts |= END;

	return 0;
}

void *aspeed_mctp_recv_thread()
{
	struct aspeed_mctp_xfer *xfer;
	int ret = 0;
	int used;

	MCTP_DBUG("\n");

	xfer = malloc(sizeof(struct aspeed_mctp_xfer));
	memset(xfer, 0, sizeof(struct aspeed_mctp_xfer));
	xfer->xfer_buff = malloc(ASPEED_MCTP_XFER_SIZE);
	xfer->header.length = 0;
	used = 0;

	do {
		if (used) {
			xfer = malloc(sizeof(struct aspeed_mctp_xfer));
			memset(xfer, 0, sizeof(struct aspeed_mctp_xfer));
			xfer->xfer_buff = malloc(ASPEED_MCTP_XFER_SIZE);
			xfer->header.length = 0;
			used = 0;
		}
		// ret = ioctl(mctp_ctx.mctp_fd, ASPEED_MCTP_IOCRX, xfer);
		ret = read(mctp_ctx.mctp_fd, xfer, sizeof(struct aspeed_mctp_xfer));
		if (ret < 0) {
			MCTP_DBUG("err\n");
			perror("ioctl MCTP No RX!\n");
			break;
		}
		if (xfer->header.length != 0) {
			MCTP_DBUG("get\n");
			MCTP_DBUG("xfer.header.pcie_target_id = %x\n", xfer->header.pcie_target_id);
			pthread_mutex_lock(&mctp_ctx.mutex);
			aspeed_mctp_recv_list(xfer);
			pthread_mutex_unlock(&mctp_ctx.mutex);
			used = 1;
		}
	} while (mctp_ctx.recv_flag);
	pthread_exit(NULL);
}

int aspeed_mctp_init(char *dev)
{
	static int fd;

	MCTP_DBUG("\n");

	if ((fd = open(dev, O_RDWR, 0)) == -1)
		return (-1);
	/* close on exec */
	if (fcntl(fd, F_SETFD, 1) == -1) {
		close(fd);
		fd = -1;
		return (-1);
	}
	mctp_ctx.mctp_fd = fd;
	return 0;
}

void aspeed_mctp_rx_pool_thread_init()
{
	mctp_ctx.recv_flag = 1;
	pthread_create(&mctp_ctx.recv_thread, NULL, aspeed_mctp_recv_thread, NULL);
}

void aspeed_mctp_exit(void)
{
	if(mctp_ctx.recv_flag) {
		mctp_ctx.recv_flag = 0;
		pthread_join(mctp_ctx.recv_thread, NULL);
	}
	close(mctp_ctx.mctp_fd);
}

#if 0
int aspeed_mctp_recv(struct aspeed_mctp_xfer **xfer)
{
	struct aspeed_mctp_rx_list *tmp, *rx_entry = NULL;
	struct list_head *rx_list = &mctp_ctx.rx_list;
	struct aspeed_mctp_xfer_list *dequeue_xfer;

	// MCTP_DBUG("\n");
	pthread_mutex_lock(&mctp_ctx.mutex);
	list_for_each_entry(tmp, rx_list, list) {
		if ((tmp->recv_sts & START) && (tmp->recv_sts & END)) {
			MCTP_DBUG("hit\n");
			rx_entry = tmp;
			break;
		}
	}
	// MCTP_DBUG("b\n");

	if (rx_entry == NULL) {
		pthread_mutex_unlock(&mctp_ctx.mutex);
		return -1;
	}

	dequeue_xfer = list_first_entry(&rx_entry->xfer_head, struct aspeed_mctp_xfer_list, list);
	if (dequeue_xfer->list.next == dequeue_xfer->list.prev) {
		MCTP_DBUG("is last xfer_list\n");
		list_del(&dequeue_xfer->list);
		list_del(&rx_entry->list);
		free(rx_entry);
	} else {
		list_del(&dequeue_xfer->list);
	}
	*xfer = dequeue_xfer->xfer;
	pthread_mutex_unlock(&mctp_ctx.mutex);

	return 0;
}
#else
int aspeed_mctp_recv(struct aspeed_mctp_xfer *xfer)
{
	int ret;

	// ret = ioctl(mctp_ctx.mctp_fd, ASPEED_MCTP_IOCRX, xfer);
	ret = read(mctp_ctx.mctp_fd, xfer, sizeof(struct aspeed_mctp_xfer));
	if (ret < 0) {
		MCTP_DBUG("err\n");
		perror("ioctl MCTP No RX!\n");
	}
	return ret;
}
#endif
void release_xfer(struct aspeed_mctp_xfer *xfer)
{
	MCTP_DBUG("\n");
	MCTP_DBUG("release xfer_list\n");
	free(xfer->xfer_buff);
	free(xfer);
}

int aspeed_mctp_send(struct aspeed_mctp_xfer *xfer)
{
	int ret;

	MCTP_DBUG("\n");

	// ret = ioctl(mctp_ctx.mctp_fd, ASPEED_MCTP_IOCTX, xfer);
	ret = write(mctp_ctx.mctp_fd, xfer, sizeof(struct aspeed_mctp_xfer));
	if (ret < 0) {
		perror("ioctl MCTP TX error!\n");
		return ret;
	}
	return ret;
}
