// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2025 Aspeed Technology Inc.
 */

#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include "cptra.h"
#include "cmd_cptra.h"
#include "ecdsa.h"
#include "hash.h"
#include "lms.h"

// #define DEBUG
#ifdef DEBUG
#define dbg_printf(fmt, args...)		printf(fmt, ##args)
#else
#define dbg_printf(fmt, args...)
#endif

#define BIT(n)		(1U << (n))

// Define ioctl numbers (replace with actual values from your kernel driver)
#define MBOX_IOCTL_CAPS				_IOR('X', 0x00, uint32_t[4])
#define MBOX_IOCTL_SEND				_IOW('X', 0x01, uint32_t[8])
#define MBOX_IOCTL_RECV				_IOR('X', 0x02, uint32_t[8])

#define IPC_CHANNEL_1_BOOTMCU_IN_ADDR		0xB1880000
#define IPC_CHANNEL_1_BOOTMCU_OUT_ADDR		0xB1980000
#define IPC_CHANNEL_1_NS_CA35_IN_ADDR		0x431880000
#define IPC_CHANNEL_1_NS_CA35_OUT_ADDR		0x431980000
#define SHARED_MEM_SIZE				0x100000

#define CPTRA_FW_ADDR				0x100000000
#define CPTRA_FW_SIZE				0x20000

#define IDEVID_CSR_BASE				0x14bbf000
#define IDEVID_CSR_OFFSET			0x800
#define IDEVID_CSR_SIZE				0x1c0
#define PAGE_SIZE				0x1000

#define ARRAY_SIZE(arr)				(sizeof(arr) / sizeof((arr)[0]))

static int gbl_fd;

/* volatile is intentional here */
static volatile uint8_t *shared_mem_in;
static uint8_t certificate_chain[4096] = {0};
static int certificate_chain_size;

void safe_memcpy(volatile uint8_t *dst, volatile uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[i];
}

static void *map_phys(off_t offset, size_t len)
{
	size_t page_size = getpagesize();
	off_t page_base = offset & ~(page_size - 1);
	off_t page_offset = offset - page_base;
	int fd = open("/dev/mem", O_RDWR | O_SYNC);

	if (fd < 0) {
		perror("open /dev/mem");
		return NULL;
	}

	return mmap(NULL, page_offset + len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page_base);
}

static int cptra_ipc_trigger(enum cptra_ipc_cmd cmd, uint32_t *input, int input_size)
{
	uint32_t data[8] = {0};
	int ret;

	dbg_printf("%s: Start cmd:0x%x, input_size:%d\n", __func__, cmd, input_size);

	if (input_size < 2 * (int)sizeof(uint32_t)) {
		printf("input_size:%d is too small\n", input_size);
		return -1;
	}

	data[0] = cmd;
	data[1] = input[0];
	data[2] = input[1];

	ret = ioctl(gbl_fd, MBOX_IOCTL_SEND, data);
	if (ret < 0) {
		perror("send");
		return 1;
	}
	dbg_printf("Message sent.\n");

	return 0;
}

int cptra_ipc_receive(enum cptra_ipc_rx_type type, void *output, int output_size)
{
	uint32_t cptra_ipc_rx_data[8];
	struct pollfd fds[1];
	uint32_t *msg;
	int ret = 0;

	fds[0].fd = gbl_fd;
	fds[0].events = POLLIN;

	while (1) {
		ret = poll(fds, 1, 1000);
		if (ret & POLLIN)
			break;

		printf("poll timeout\n");
	}

	msg = cptra_ipc_rx_data;

	dbg_printf("%s: rx type:0x%x, output_size:%d\n", __func__, type,
		   output_size);
	if (type == CPTRA_IPC_RX_TYPE_INTERNAL) {
		ret = ioctl(gbl_fd, MBOX_IOCTL_RECV, msg);
		if (ret < 0) {
			perror("ioctl(MBOX_IOCTL_RECV)");
			return 1;
		}
		memcpy(output, msg, output_size);
		dbg_printf("Message received: 0x%x 0x%x\n", msg[0], msg[1]);

	} else {
		ret = read(gbl_fd, output, output_size);
		if (ret < 0) {
			perror("read");
			return 1;
		}

		ret = ioctl(gbl_fd, MBOX_IOCTL_RECV, msg);
		if (ret < 0) {
			perror("ioctl(MBOX_IOCTL_RECV)");
			return 1;
		}
		dbg_printf("Message received: 0x%x 0x%x\n", msg[0], msg[1]);
		ret = msg[0];
	}

	return ret;
}

static void dbg_hexdump(const void *data, size_t size, const char *title)
{
#ifdef DEBUG
	const unsigned char *p = (const unsigned char *)data;
#endif
	if (title)
		dbg_printf("%s\n", title);

	for (size_t i = 0; i < size; i++) {
		if (i % 16 == 0)
			dbg_printf("%08zx  ", i); // offset
		dbg_printf("%02x ", p[i]); // hex value

		if (i % 16 == 15 || i == size - 1) {
			// print ASCII
			int pad = 16 - (i % 16 + 1);

			for (int j = 0; j < pad; j++)
				dbg_printf("   ");
			dbg_printf(" |");

			for (size_t j = i - (i % 16); j <= i; j++) {
				dbg_printf("%c", (p[j] >= 32 && p[j] <= 126) ?
							 p[j] :
							 '.');
			}
			dbg_printf("|\n");
		}
	}
}

static void hexdump(const void *data, size_t size, const char *title)
{
	const unsigned char *p = (const unsigned char *)data;

	if (title)
		printf("%s\n", title);

	for (size_t i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("%08zx  ", i); // offset
		printf("%02x ", p[i]); // hex value

		if (i % 16 == 15 || i == size - 1) {
			// print ASCII
			int pad = 16 - (i % 16 + 1);

			for (int j = 0; j < pad; j++)
				printf("   ");
			printf(" |");

			for (size_t j = i - (i % 16); j <= i; j++) {
				printf("%c", (p[j] >= 32 && p[j] <= 126) ?
						     p[j] :
						     '.');
			}
			printf("|\n");
		}
	}
}

static int cptra_test_get_idevid_csr(void)
{
	uint8_t csr[IDEVID_CSR_SIZE];
	volatile uint8_t *shared_mem_in;

	shared_mem_in = (volatile uint8_t *)map_phys(IDEVID_CSR_BASE, PAGE_SIZE);
	if (!shared_mem_in) {
		printf("map_phys failed\n");
		return -1;
	}

	safe_memcpy(csr, (volatile uint8_t *)shared_mem_in + IDEVID_CSR_OFFSET, IDEVID_CSR_SIZE);

	hexdump(csr, IDEVID_CSR_SIZE, "IDEVID CSR:");

	munmap((void *)shared_mem_in, PAGE_SIZE);
	return 0;
}

static int invoke_dpe_command(void *input, int intput_size,
			      struct cptra_invoke_dpe_command_oa *output)
{
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_INVOKE_DPE_COMMAND;
	int ret;

	ret = cptra_ipc_trigger(ipccmd, (uint32_t *)input, intput_size);
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, output,
				sizeof(struct cptra_invoke_dpe_command_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output->chksum, output->fips_status);

#ifdef DEBUG
	int dlen;

	if (output->data_size > 0x400)
		dlen = 0x400;
	else
		dlen = output->data_size;

	dbg_hexdump(output->data, dlen, "DPE COMMAND RESP:");
#endif
	return 0;
end:
	return ret;
}

static int cptra_dpe_response_check(struct dpe_rsp_header *header)
{
	if (header->magic != DPE_RESPONSE_MAGIC || header->status != 0)
		return 1;

	return 0;
}

static int cptra_test_invoke_dpe_command_get_profile(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_get_profile_i *get_profile_input = NULL;
	struct dpe_get_profile_o *get_profile_output = NULL;
	int ret;

	printf("\tTest GetProfile...\n");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	get_profile_input = (struct dpe_get_profile_i *)input.data;
	get_profile_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	get_profile_input->cmd_hdr.cmd = GET_PROFILE;
	input.data_size = sizeof(struct dpe_get_profile_i);

	get_profile_output = (struct dpe_get_profile_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&get_profile_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       get_profile_output->rsp_hdr.magic,
		       get_profile_output->rsp_hdr.status,
		       get_profile_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		printf("DPE Profile: %08x\n", get_profile_output->rsp_hdr.profile);
		printf("Major Version: %04x Minor Version: %04x\n",
		       get_profile_output->major_version,
		       get_profile_output->minor_version);
		printf("Vendor ID: %08x Sku ID: %08x\n",
		       get_profile_output->vendor_id,
		       get_profile_output->vendor_sku);
		printf("Max TCI Nodes: %d Flags: %08x\n",
		       get_profile_output->max_tci_nodes,
		       get_profile_output->flags);
	}

	return ret;
}

__attribute__((__unused__)) static void cptra_test_invoke_dpe_command_initialize_context(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_initialize_context_i *initialize_context_input = NULL;
	struct dpe_new_context_o *initialize_context_output = NULL;
	int ret;

	printf("\tTest InitializeContext...\n");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	initialize_context_input = (struct dpe_initialize_context_i *)input.data;
	initialize_context_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	initialize_context_input->cmd_hdr.cmd = INITIALIZE_CONTEXT;
	initialize_context_input->cmd_hdr.profile = p384sha384;
	initialize_context_input->init_ctx_cmd = BIT(30); // DEFAULT_FLAG_MASK
	input.data_size = sizeof(struct dpe_initialize_context_i);

	initialize_context_output = (struct dpe_new_context_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input,
		    sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n",
		       ret);

	} else if (cptra_dpe_response_check(&initialize_context_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       initialize_context_output->rsp_hdr.magic,
		       initialize_context_output->rsp_hdr.status,
		       initialize_context_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		dbg_hexdump(initialize_context_output->context_handle,
			    sizeof(initialize_context_output->context_handle),
			    "context_handle:");
	}
}

static int
cptra_test_invoke_dpe_command_derive_context(uint8_t *dervied_context)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_derive_context_i *derive_context_input = NULL;
	struct dpe_derive_context_o *derive_context_output = NULL;
	int ret;

	printf("\tTest DeriveContext...\n");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	derive_context_input = (struct dpe_derive_context_i *)input.data;
	derive_context_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	derive_context_input->cmd_hdr.cmd = DERIVE_CONTEXT;
	derive_context_input->cmd_hdr.profile = p384sha384;
	derive_context_input->flags = BIT(25) | BIT(26) | BIT(30) | BIT(31); // INPUT_ALLOW_X509 |
									     // INPUT_ALLOW_CA |
									     // INPUT_DICE |
									     // INPUT_INFO
	input.data_size = sizeof(struct dpe_derive_context_i);

	derive_context_output = (struct dpe_derive_context_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&derive_context_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       derive_context_output->rsp_hdr.magic,
		       derive_context_output->rsp_hdr.status,
		       derive_context_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		dbg_hexdump(derive_context_output->context_handle,
			    sizeof(derive_context_output->context_handle),
			    "context_handle:");
		dbg_hexdump(derive_context_output->parent_context_handle,
			    sizeof(derive_context_output->parent_context_handle),
			    "parent_context_handle:");
		memcpy(dervied_context, derive_context_output->context_handle,
		       sizeof(derive_context_output->context_handle));
	}

	return ret;
}

void cptra_test_invoke_dpe_command_derive_context_exported_cdi(uint8_t *derived_context)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_derive_context_i *derive_context_input = NULL;
	struct dpe_derive_context_exported_cdi_o *derive_context_output = NULL;
	int ret;

	printf("\tTest DeriveContext...\n");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	derive_context_input = (struct dpe_derive_context_i *)input.data;
	derive_context_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	derive_context_input->cmd_hdr.cmd = DERIVE_CONTEXT;
	derive_context_input->cmd_hdr.profile = p384sha384;
	derive_context_input->flags = EXPORT_CDI | CREATE_CERTIFICATE;
	input.data_size = sizeof(struct dpe_derive_context_i);

	derive_context_output = (struct dpe_derive_context_exported_cdi_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&derive_context_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       derive_context_output->rsp_hdr.magic,
		       derive_context_output->rsp_hdr.status,
		       derive_context_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		dbg_hexdump(derive_context_output->context_handle,
			    sizeof(derive_context_output->context_handle),
			    "context_handle:");
		dbg_hexdump(derive_context_output->parent_context_handle,
			    sizeof(derive_context_output->parent_context_handle),
			    "parent_context_handle:");
		dbg_hexdump(derive_context_output->exported_cdi,
			    sizeof(derive_context_output->exported_cdi),
			    "exported_cdi:");
		dbg_hexdump(derive_context_output->new_certificate,
			    derive_context_output->certificate_size,
			    "new_certificate:");
		memcpy(derived_context, derive_context_output->exported_cdi,
		       sizeof(derive_context_output->exported_cdi));
	}
}

static int cptra_test_invoke_dpe_command_rotate_context(uint8_t *context_handle,
							 uint8_t *new_context_handle)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_rotate_context_handle_i *rotate_context_handle_input = NULL;
	struct dpe_new_context_o *rotate_context_handle_output = NULL;
	int ret;

	printf("\tTest RotateContextHandle...\n");
	dbg_hexdump(context_handle, 16, "context_handle:");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	rotate_context_handle_input = (struct dpe_rotate_context_handle_i *)input.data;
	rotate_context_handle_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	rotate_context_handle_input->cmd_hdr.cmd = ROTATE_CONTEXT_HANDLE;
	rotate_context_handle_input->cmd_hdr.profile = p384sha384;
	memcpy(rotate_context_handle_input->handle, context_handle,
	       sizeof(rotate_context_handle_input->handle));
	input.data_size = sizeof(struct dpe_rotate_context_handle_i);

	rotate_context_handle_output = (struct dpe_new_context_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);
		goto end;

	} else if (cptra_dpe_response_check(&rotate_context_handle_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       rotate_context_handle_output->rsp_hdr.magic,
		       rotate_context_handle_output->rsp_hdr.status,
		       rotate_context_handle_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		dbg_hexdump(rotate_context_handle_output->context_handle,
			    sizeof(rotate_context_handle_output->context_handle),
			    "context_handle:");
		memcpy(new_context_handle,
		       rotate_context_handle_output->context_handle,
		       sizeof(rotate_context_handle_output->context_handle));
	}
end:
	return ret;
}

static int cptra_test_invoke_dpe_command_destroy_context(uint8_t *context_handle)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_destroy_context_i *destroy_context_input = NULL;
	struct dpe_destroy_context_o *destroy_context_output = NULL;
	int ret;

	printf("\tTest DestroyContext...\n");
	dbg_hexdump(context_handle, 16, "context_handle:");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	destroy_context_input = (struct dpe_destroy_context_i *)input.data;
	destroy_context_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	destroy_context_input->cmd_hdr.cmd = DESTROY_CONTEXT;
	destroy_context_input->cmd_hdr.profile = p384sha384;
	memcpy(destroy_context_input->handle, context_handle,
	       sizeof(destroy_context_input->handle));
	input.data_size = sizeof(struct dpe_destroy_context_i);

	destroy_context_output = (struct dpe_destroy_context_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&destroy_context_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       destroy_context_output->rsp_hdr.magic,
		       destroy_context_output->rsp_hdr.status,
		       destroy_context_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
	}

	return ret;
}

static int cptra_test_invoke_dpe_command_certify_key(uint8_t *context_handle,
						     int format,
						     uint8_t *public_key,
						     uint8_t *certify_handle)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_certify_key_i *certify_key_input = NULL;
	struct dpe_certify_key_o *certify_key_output = NULL;
	int ret;

	printf("\tTest CertifyKey... %s\n", format ? "CSR" : "Certificate");
	dbg_hexdump(context_handle, 16, "context_handle:");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	certify_key_input = (struct dpe_certify_key_i *)input.data;
	certify_key_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	certify_key_input->cmd_hdr.cmd = CERTIFY_KEY;
	certify_key_input->cmd_hdr.profile = p384sha384;
	certify_key_input->format = format;
	memcpy(certify_key_input->handle, context_handle, sizeof(certify_key_input->handle));
	input.data_size = sizeof(struct dpe_certify_key_i);
	certify_key_output = (struct dpe_certify_key_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&certify_key_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       certify_key_output->rsp_hdr.magic,
		       certify_key_output->rsp_hdr.status,
		       certify_key_output->rsp_hdr.profile);

	} else {
		printf("DPE command CERTIFY_KEY Success\n");
		dbg_hexdump(certify_key_output->context_handle,
			    sizeof(certify_key_output->context_handle),
			    "context_handle:");
		dbg_hexdump(certify_key_output->public_key_x,
			    sizeof(certify_key_output->public_key_x),
			    "public_key_x:");
		dbg_hexdump(certify_key_output->public_key_y,
			    sizeof(certify_key_output->public_key_y),
			    "public_key_y:");
		dbg_hexdump(certify_key_output->cert,
			    certify_key_output->cert_size, "cert:");

		memcpy(public_key, certify_key_output->public_key_x,
		       sizeof(certify_key_output->public_key_x));
		memcpy(public_key + sizeof(certify_key_output->public_key_x),
		       certify_key_output->public_key_y,
		       sizeof(certify_key_output->public_key_y));
		memcpy(certify_handle, certify_key_output->context_handle,
		       sizeof(certify_key_output->context_handle));
	}

	return ret;
}

static int cptra_test_invoke_dpe_command_sign(uint8_t *context_handle, uint8_t *public_key)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_sign_i *sign_input = NULL;
	struct dpe_sign_o *sign_output = NULL;
	int ret;

	printf("\tTest Sign...\n");
	dbg_hexdump(public_key, 97, "public_key:");
	dbg_hexdump(context_handle, 16, "context_handle:");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	sign_input = (struct dpe_sign_i *)input.data;
	sign_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	sign_input->cmd_hdr.cmd = SIGN;
	sign_input->cmd_hdr.profile = p384sha384;
	memcpy(sign_input->handle, context_handle, sizeof(sign_input->handle));
	input.data_size = sizeof(struct dpe_sign_i);
	sign_output = (struct dpe_sign_o *)output.data;

	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
	ret = invoke_dpe_command(data, sizeof(data), &output);

	if (ret) {
		printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);

	} else if (cptra_dpe_response_check(&sign_output->rsp_hdr)) {
		printf("DPE command failed, magic:0x%08x status:0x%08x profile:0x%08x\n",
		       sign_output->rsp_hdr.magic, sign_output->rsp_hdr.status,
		       sign_output->rsp_hdr.profile);

	} else {
		dbg_printf("Success\n");
		dbg_hexdump(sign_output->context_handle,
			    sizeof(sign_output->context_handle),
			    "context_handle:");
		dbg_hexdump(sign_output->signature_r,
			    sizeof(sign_output->signature_r), "signature_r:");
		dbg_hexdump(sign_output->signature_s,
			    sizeof(sign_output->signature_s), "signature_s:");

		memcpy(context_handle, sign_output->context_handle,
		       sizeof(sign_output->context_handle));
	}

	return ret;
}

static int cptra_test_invoke_dpe_command_get_certificate_chain(bool debug)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint32_t data[2] = { (uint32_t)(uintptr_t)p8_bmcu_in,
			     (uint32_t)(uintptr_t)p8_bmcu_out };

	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_get_certificate_chain_i *get_certificate_chain_input = NULL;
	struct dpe_get_certificate_chain_o *get_certificate_chain_output = NULL;
	uint32_t offset = 0;
	int ret;

	printf("\tTest GetCertificateChain...\n");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	get_certificate_chain_input = (struct dpe_get_certificate_chain_i *)input.data;
	get_certificate_chain_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	get_certificate_chain_input->cmd_hdr.cmd = GET_CERTIFICATE_CHAIN;
	get_certificate_chain_input->cmd_hdr.profile = p384sha384;

	get_certificate_chain_output = (struct dpe_get_certificate_chain_o *)output.data;
	input.data_size = sizeof(struct dpe_get_certificate_chain_i);
	do {
		get_certificate_chain_input->offset = offset;
		get_certificate_chain_input->size =
			sizeof(get_certificate_chain_output->cert_chain);

		safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia));
		ret = invoke_dpe_command(data, sizeof(data), &output);

		if (ret) {
			printf("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);
			goto end;

		} else {
			printf("Successful offset=%u size=%u\n", offset,
			       get_certificate_chain_output->size);

			memcpy(&certificate_chain[offset],
			       get_certificate_chain_output->cert_chain,
			       get_certificate_chain_output->size);
			offset += get_certificate_chain_output->size;

			if (get_certificate_chain_output->size <
			    sizeof(get_certificate_chain_output->cert_chain)) {
				break;
			}
		}
	} while (1);

	if (debug)
		hexdump(certificate_chain, offset, "certificate_chain:");
	else
		dbg_hexdump(certificate_chain, offset, "certificate_chain:");

	certificate_chain_size = offset;

end:
	return ret;
}

static int cptra_test_get_cert_chain(void)
{
	return cptra_test_invoke_dpe_command_get_certificate_chain(true);
}

static int cptra_test_invoke_dpe_command(void)
{
	int ret;

	printf("Test caliptra_invoke_dpe_command...\n");

	uint8_t derived_context[16] = {0};
	uint8_t rotated_context[16] = {0};
	uint8_t default_context[16] = {0};
	uint8_t certify_context[16] = {0};
	uint8_t public_key[97] = {0};

	// 0x04 is the prefix for uncompressed public key
	public_key[0] = 0x04;

	ret = cptra_test_invoke_dpe_command_get_profile();
	ret += cptra_test_invoke_dpe_command_get_certificate_chain(false);

	// Default Context
	ret += cptra_test_invoke_dpe_command_certify_key(default_context, 0, public_key + 1, certify_context);
	ret += cptra_test_invoke_dpe_command_sign(default_context, public_key);

	// Dervied Context
	ret += cptra_test_invoke_dpe_command_derive_context(derived_context);
	ret += cptra_test_invoke_dpe_command_certify_key(derived_context, 0, public_key + 1, certify_context);
	ret += cptra_test_invoke_dpe_command_sign(certify_context, public_key);

	// Rotated Context
	ret += cptra_test_invoke_dpe_command_rotate_context(certify_context, rotated_context);
	ret += cptra_test_invoke_dpe_command_certify_key(rotated_context, 0, public_key + 1, certify_context);
	ret += cptra_test_invoke_dpe_command_sign(certify_context, public_key);

	// Destroy Context
	ret += cptra_test_invoke_dpe_command_destroy_context(certify_context);

	return ret;
}

__attribute__((__unused__)) static int cptra_test_shutdown(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_shutdown_ia input;
	struct cptra_shutdown_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_SHUTDOWN;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_shutdown_ia));
	memset(&output, 0, sizeof(struct cptra_shutdown_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_shutdown_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_shutdown_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_version(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_version_ia input;
	struct cptra_version_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_FIPS_VERSION;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_version_ia));
	memset(&output, 0, sizeof(struct cptra_version_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_version_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_version_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_printf("mode: 0x%x\n", output.mode);
	dbg_hexdump(output.fips_rev, sizeof(output.fips_rev), "fips_rev:");
	dbg_hexdump(output.name, sizeof(output.name), "name:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_capabilities(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_capabilities_ia input;
	struct cptra_capabilities_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_CAPABILITIES;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_capabilities_ia));
	memset(&output, 0, sizeof(struct cptra_capabilities_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_capabilities_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_capabilities_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.capabilities, sizeof(output.capabilities), "capabilities:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_fw_info(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_fw_info_ia input;
	struct cptra_fw_info_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_FW_INFO;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_fw_info_ia));
	memset(&output, 0, sizeof(struct cptra_fw_info_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_fw_info_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_fw_info_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);
	dbg_printf("pl0_pauser=0x%x\n", output.pl0_pauser);
	dbg_printf("runtime_svn=0x%x\n", output.runtime_svn);
	dbg_printf("min_runtime_svn=0x%x\n", output.min_runtime_svn);
	dbg_printf("fmc_manifest_svn: 0x%x\n", output.fmc_manifest_svn);
	dbg_printf("attestation_disabled: 0x%x\n", output.attestation_disabled);
	dbg_hexdump(output.rom_revision, sizeof(output.rom_revision), "rom_revision:");
	dbg_hexdump(output.fmc_revision, sizeof(output.fmc_revision), "fmc_revision:");
	dbg_hexdump(output.runtime_revision, sizeof(output.runtime_revision), "runtime_revision:");
	dbg_hexdump(output.rom_sha256_digest, sizeof(output.rom_sha256_digest),
		    "rom_sha256_digest:");
	dbg_hexdump(output.fmc_sha384_digest, sizeof(output.fmc_sha384_digest),
		    "fmc_sha384_digest:");
	dbg_hexdump(output.runtime_sha384_digest, sizeof(output.runtime_sha384_digest),
		    "runtime_sha384_digest:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_get_rt_alias_cert(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_get_rt_alias_cert_ia input;
	struct cptra_get_rt_alias_cert_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_GET_RT_ALIAS_CERT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_get_rt_alias_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_rt_alias_cert_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_get_rt_alias_cert_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_get_rt_alias_cert_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.data, output.data_size, "rt_alias_cert:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_get_fmc_alias_cert(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_get_fmc_alias_cert_ia input;
	struct cptra_get_fmc_alias_cert_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_GET_FMC_ALIAS_CERT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_get_fmc_alias_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_fmc_alias_cert_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_get_fmc_alias_cert_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_get_fmc_alias_cert_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.data, output.data_size, "fmc_alias_cert:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_get_ldev_cert(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_get_ldev_cert_ia input;
	struct cptra_get_ldev_cert_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_GET_LDEV_CERT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_get_ldev_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_ldev_cert_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_get_ldev_cert_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_get_ldev_cert_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.data, output.data_size, "ldev_cert:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_get_idev_info(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_get_idev_info_ia input;
	struct cptra_get_idev_info_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_GET_IDEV_INFO;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_get_idev_info_ia));
	memset(&output, 0, sizeof(struct cptra_get_idev_info_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_get_idev_info_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_get_idev_info_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.idev_pub_x, sizeof(output.idev_pub_x), "idev_pub_x:");
	dbg_hexdump(output.idev_pub_y, sizeof(output.idev_pub_y), "idev_pub_y:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

__attribute__((__unused__)) static int cptra_test_populate_idev_cert(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_populate_idev_cert_ia input;
	struct cptra_populate_idev_cert_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_POPULATE_IDEV_CERT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_populate_idev_cert_ia));
	memset(&output, 0, sizeof(struct cptra_populate_idev_cert_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_populate_idev_cert_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_populate_idev_cert_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

__attribute__((__unused__)) static int cptra_test_get_idev_cert(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_get_idev_cert_ia input;
	struct cptra_get_idev_cert_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_GET_IDEV_CERT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_get_idev_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_idev_cert_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_get_idev_cert_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_get_idev_cert_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.cert, output.cert_size, "cert:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_disable_attestation(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_disable_attestation_ia input;
	struct cptra_disable_attestation_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_DISABLE_ATTESTATION;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_disable_attestation_ia));
	memset(&output, 0, sizeof(struct cptra_disable_attestation_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_disable_attestation_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_disable_attestation_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_certify_key_extended(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_certify_key_extended_ia input;
	struct cptra_certify_key_extended_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_CERTIFY_KEY_EXTENDED;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_certify_key_extended_ia));
	memset(&output, 0, sizeof(struct cptra_certify_key_extended_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_certify_key_extended_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_certify_key_extended_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_add_subject_alt_name(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_add_subject_alt_name_ia input;
	struct cptra_add_subject_alt_name_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_ADD_SUBJECT_ALT_NAME;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_add_subject_alt_name_ia));
	memset(&output, 0, sizeof(struct cptra_add_subject_alt_name_oa));

	/* TODO: customize input data by application */
	const char *dev_info = "abc:def:ghi";

	memcpy(input.dmtf_device_info, dev_info, strlen(dev_info));
	input.dmtf_device_info_size = strlen(dev_info);

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_add_subject_alt_name_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_add_subject_alt_name_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_dpe_get_tagged_tci(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_dpe_get_tagged_tci_ia input;
	struct cptra_dpe_get_tagged_tci_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_DPE_GET_TAGGED_TCI;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_dpe_get_tagged_tci_ia));
	memset(&output, 0, sizeof(struct cptra_dpe_get_tagged_tci_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_dpe_get_tagged_tci_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_dpe_get_tagged_tci_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

	dbg_hexdump(output.tci_cumulative, sizeof(output.tci_cumulative), "tci_cumulative:");
	dbg_hexdump(output.tci_current, sizeof(output.tci_current), "tci_current:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_dpe_tag_tci(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_dpe_tag_tci_ia input;
	struct cptra_dpe_tag_tci_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_DPE_TAG_TCI;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_dpe_tag_tci_ia));
	memset(&output, 0, sizeof(struct cptra_dpe_tag_tci_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_dpe_tag_tci_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_dpe_tag_tci_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_increment_pcr_reset_counter(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_increment_pcr_reset_counter_ia input;
	struct cptra_increment_pcr_reset_counter_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_INCREMENT_PCR_RESET_COUNTER;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_increment_pcr_reset_counter_ia));
	memset(&output, 0, sizeof(struct cptra_increment_pcr_reset_counter_oa));

	/* TODO: customize input data by application */
	input.index = 31;

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_increment_pcr_reset_counter_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_increment_pcr_reset_counter_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_extend_pcr(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_extend_pcr_ia input;
	struct cptra_extend_pcr_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_EXTEND_PCR;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_extend_pcr_ia));
	memset(&output, 0, sizeof(struct cptra_extend_pcr_oa));

	/* TODO: customize input data by application */
	input.index = 31;
	input.value[0] = 0x28;
	input.value[1] = 0x01;

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_extend_pcr_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_extend_pcr_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_quote_pcrs(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_quote_pcrs_ia input;
	struct cptra_quote_pcrs_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_QUOTE_PCRS;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_quote_pcrs_ia));
	memset(&output, 0, sizeof(struct cptra_quote_pcrs_oa));

	/* TODO: customize input data by application */

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_quote_pcrs_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_quote_pcrs_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x\n", output.chksum,
		   output.fips_status);
	dbg_hexdump(output.pcrs[31], sizeof(output.pcrs[31]), "pcrs[31]:");
	dbg_hexdump(output.nonce, sizeof(output.nonce), "nonce:");
	dbg_hexdump(output.digest, sizeof(output.digest), "digest:");
	dbg_hexdump(output.reset_ctrs, sizeof(output.reset_ctrs), "reset_ctrs:");
	dbg_hexdump(output.signature_r, sizeof(output.signature_r), "signature_r:");
	dbg_hexdump(output.signature_s, sizeof(output.signature_s), "signature_s:");

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_test_stash_measurement(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_stash_measurement_ia input;
	struct cptra_stash_measurement_oa output;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_STASH_MEASUREMENT;
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)(uintptr_t)p8_bmcu_in;
	data[1] = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Initialize input data */
	memset(&input, 0, sizeof(struct cptra_stash_measurement_ia));
	memset(&output, 0, sizeof(struct cptra_stash_measurement_oa));

	/* TODO: customize input data by application */
	memcpy(input.metadata, "META", 4);

	/* Copy input data into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&input, sizeof(struct cptra_stash_measurement_ia));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &output,
				sizeof(struct cptra_stash_measurement_oa));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

	dbg_printf("output: chksum=0x%x, fips_status=0x%x, dpe_result=0x%x\n",
		   output.chksum, output.fips_status, output.dpe_result);

end:
	printf("%s: %s\n", __func__, ret ? "Failed" : "Pass");
	return ret;
}

static int cptra_sha384(uint8_t *msg, int msg_size, uint8_t *output, int output_size)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_SHA384_DIGEST;
	volatile uint32_t *p32 = (uint32_t *)shared_mem_in;
	struct cptra_hash_ctx ctx;
	volatile uint8_t *p8;
	uint32_t data[2];
	int ret;

	dbg_printf("%s, msg_size:0x%x\n", __func__, msg_size);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	ctx.algo = CRYPTO_HASH_ALGO_SHA384;
	ctx.in_len = msg_size;
	ctx.in_buf = (uint32_t)((uintptr_t)p8_bmcu_in + sizeof(struct cptra_hash_ctx));
	ctx.out_len = output_size;
	ctx.out_buf = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Clear shared memory - use for loop instead of memset to avoid alignment issues. */
	for (int i = 0; i < SHARED_MEM_SIZE / (int)sizeof(uint32_t); i++)
		*p32++ = 0;

	/* Copy input data structure into shared memory */
	safe_memcpy(shared_mem_in, (volatile uint8_t *)&ctx, sizeof(struct cptra_hash_ctx));
	p8 = (uint8_t *)shared_mem_in + sizeof(struct cptra_hash_ctx);

	/* Copy input data into shared memory.
	 * Using a byte-wise copy to avoid alignment issues.
	 */
	safe_memcpy((volatile uint8_t *)p8, (volatile uint8_t *)msg, msg_size);

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, output, output_size);

end:
	return ret;
}

static int cptra_sha384_init(void)
{
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_SHA384_INIT;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;

	dbg_printf("%s\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	ctx.algo = CRYPTO_HASH_ALGO_SHA384;

	/* Copy input data structure into shared memory */
	memcpy((void *)shared_mem_in, &ctx, sizeof(struct cptra_hash_ctx));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

end:
	return ret;
}

static int cptra_sha384_update(uint8_t *msg, int msg_size)
{
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_SHA384_UPDATE;
	volatile uint8_t *p8 = shared_mem_in;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;

	dbg_printf("%s\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	ctx.algo = CRYPTO_HASH_ALGO_SHA384;
	ctx.in_len = msg_size;
	ctx.in_buf = (uint32_t)(uintptr_t)p8_bmcu_in + sizeof(struct cptra_hash_ctx);

	/* Copy input data structure into shared memory */
	memcpy((void *)shared_mem_in, &ctx, sizeof(struct cptra_hash_ctx));
	p8 += sizeof(struct cptra_hash_ctx);

	/* Copy input data into shared memory */
	for (int i = 0; i < msg_size; i++)
		*p8++ = *msg++;

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

end:
	return ret;
}

static int cptra_sha384_final(uint8_t *output, int output_size)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_SHA384_FINAL;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;

	dbg_printf("%s\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	ctx.algo = CRYPTO_HASH_ALGO_SHA384;
	ctx.out_len = output_size;
	ctx.out_buf = (uint32_t)(uintptr_t)p8_bmcu_out;

	/* Copy input data structure into shared memory */
	memcpy((void *)shared_mem_in, &ctx, sizeof(struct cptra_hash_ctx));

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	ret = cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, output, output_size);
	if (ret) {
		printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd, ret);
		goto end;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

end:
	return ret;
}

static int cptra_test_ecdsa_verify(void)
{
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_ECDSA384_SIGNATURE_VERIFY;
	const struct ecdsa_testvec *tv = secp384r1_tv;
	int tv_size = ARRAY_SIZE(secp384r1_tv);
	struct cptra_ecdsa_ctx ctx;
	volatile uint32_t *p32;
	volatile uint8_t *p8;
	uint8_t digest[64];
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);
	for (int i = 0; i < tv_size; i++) {
		dbg_printf("Test vector %d\n", i);

		p32 = (uint32_t *)shared_mem_in;
		/* Clear shared memory - use for loop instead of memset to avoid alignment issues. */
		for (int i = 0; i < SHARED_MEM_SIZE / (int)sizeof(uint32_t); i++)
			*p32++ = 0;

		/* Doing hash first for Caliptra secure IP case */
		cptra_sha384((uint8_t *)tv[i].raw, tv[i].raw_size, digest, 48);
		if (!memcmp(digest, tv[i].m, tv[i].m_size)) {
			dbg_printf("digest compare - PASS\n");
		} else {
			printf("digest compare - FAIL\n");
			return -1;
		}

		/* Prepare tx data to bootmcu */
		p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
		p8_bmcu_in += sizeof(struct cptra_ecdsa_ctx);
		ctx.qx = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += 48;
		ctx.qy = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += 48;
		ctx.r = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += 48;
		ctx.s = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += 48;
		ctx.m = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += tv[i].m_size;
		ctx.qx_len = 48;
		ctx.qy_len = 48;
		ctx.r_len = 48;
		ctx.s_len = 48;
		ctx.m_len = tv[i].m_size;

		p8 = shared_mem_in;
		safe_memcpy(p8, (volatile uint8_t *)&ctx, sizeof(struct cptra_ecdsa_ctx));
		p8 += sizeof(struct cptra_ecdsa_ctx);
		safe_memcpy(p8, (volatile uint8_t *)tv[i].qx, 48);
		p8 += 48;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].qy, 48);
		p8 += 48;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].r, 48);
		p8 += 48;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].s, 48);

		data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
		data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

		ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
		if (ret) {
			printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
			goto end;
		} else {
			dbg_printf("cptra_ipc_trigger:%x is successful\n", ipccmd);
		}

		cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));
		if (ret && !tv[i].result) {
			dbg_printf(" result expected (failed), Pass\n");
		} else if (ret == 0 && tv[i].result) {
			dbg_printf(" result expected (pass), Pass\n");
		} else {
			printf(" result unexpected (ret=%d), Failed\n", ret);
			ret = -1;
			goto end;
		}

		ret = 0;
	}

	printf("%s: Pass\n", __func__);

end:
	return ret;
}

static int cptra_test_lms_verify(void)
{
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_LMS_SIGNATURE_VERIFY;
	volatile uint32_t *p32 = (uint32_t *)shared_mem_in;
	const struct lms_testvec *tv = lms_tv;
	int tv_size = ARRAY_SIZE(lms_tv);
	struct cptra_lms_ctx ctx;
	volatile uint8_t *p8;
	uint8_t digest[64];
	uint32_t data[2];
	int ret;

	printf("%s: Start...\n", __func__);
	for (int i = 0; i < tv_size; i++) {
		dbg_printf("Test vector %d\n", i);

		/* Clear shared memory - use for loop instead of memset to avoid alignment issues. */
		for (int i = 0; i < SHARED_MEM_SIZE / (int)sizeof(uint32_t); i++)
			*p32++ = 0;

		/* Doing hash first for Caliptra secure IP case */
		cptra_sha384((uint8_t *)tv[i].raw, tv[i].raw_size, digest, 48);

		/* Prepare tx data to bootmcu */
		p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
		p8_bmcu_in += sizeof(struct cptra_lms_ctx);
		ctx.pub_key_id = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += tv[i].pub_key_id_len;
		ctx.pub_key_digest = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += tv[i].pub_key_digest_len;
		ctx.sig_ots = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += tv[i].sig_ots_len;
		ctx.sig_tree_path = (uint32_t)(uintptr_t)p8_bmcu_in;
		p8_bmcu_in += tv[i].sig_tree_path_len;

		ctx.pub_key_tree_type = tv[i].pub_key_tree_type;
		ctx.pub_key_ots_type = tv[i].pub_key_ots_type;
		ctx.pub_key_id_len = tv[i].pub_key_id_len;
		ctx.pub_key_digest_len = tv[i].pub_key_digest_len;
		ctx.sig_q = tv[i].sig_q;
		ctx.sig_ots_len = tv[i].sig_ots_len;
		ctx.sig_tree_type = tv[i].sig_tree_type;
		ctx.sig_tree_path_len = tv[i].sig_tree_path_len;

		p8 = shared_mem_in;
		safe_memcpy(p8, (volatile uint8_t *)&ctx, sizeof(struct cptra_lms_ctx));
		p8 += sizeof(struct cptra_lms_ctx);

		// Do not use memcpy to avoid alignment issues.
		safe_memcpy(p8, (volatile uint8_t *)tv[i].pub_key_id, tv[i].pub_key_id_len);
		p8 += tv[i].pub_key_id_len;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].pub_key_digest, tv[i].pub_key_digest_len);
		p8 += tv[i].pub_key_digest_len;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].sig_ots, tv[i].sig_ots_len);
		p8 += tv[i].sig_ots_len;
		safe_memcpy(p8, (volatile uint8_t *)tv[i].sig_tree_path, tv[i].sig_tree_path_len);
		p8 += tv[i].sig_tree_path_len;

		data[0] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
		data[1] = (uint32_t)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

		ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
		if (ret) {
			printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd, ret);
			goto end;
		} else {
			dbg_printf("cptra_ipc_trigger:%x is successful\n", ipccmd);
		}

		cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));
		if (ret && !tv[i].result) {
			dbg_printf(" result expected (failed), Pass\n");
		} else if (ret == 0 && tv[i].result) {
			dbg_printf(" result expected (pass), Pass\n");
		} else {
			printf(" result unexpected (ret=%d), Failed\n", ret);
			ret = -1;
			goto end;
		}
	}

	printf("%s: Pass\n", __func__);

end:
	return ret;
}

static int cptra_test_sha384(void)
{
	const struct hash_testvec *tv = sha384_tv_template;
	int tv_size = ARRAY_SIZE(sha384_tv_template);
	uint8_t digest[64];

	printf("%s: Start...\n", __func__);
	for (int i = 0; i < tv_size; i++) {
		dbg_printf("Test vector %d\n", i);

		cptra_sha384((uint8_t *)tv[i].plaintext, tv[i].psize, digest, 48);
		if (!memcmp(digest, tv[i].digest, 48)) {
			dbg_printf("digest compare - PASS\n");
		} else {
			printf("digest compare - FAIL\n");
			return -1;
		}
	}

	printf("%s: Pass\n", __func__);

	return 0;
}

static int cptra_test_sha384_acc(void)
{
	const struct hash_testvec *tv = sha384_tv_template;
	int tv_size = ARRAY_SIZE(sha384_tv_template);
	uint8_t digest[64];
	uint8_t *p8;
	int tsize, bsize;

	printf("%s: Start...\n", __func__);
	for (int i = 0; i < tv_size; i++) {
		dbg_printf("Test vector %d\n", i);

		p8 = (uint8_t *)tv[5].plaintext;
		tsize = tv[5].psize;

		cptra_sha384_init();
		for (int i = 0; i < tsize; i += 64) {
			if (tsize - i > 64)
				bsize = 64;
			else
				bsize = tsize - i;

			dbg_printf("input=%d, bsize=%d\n", i, bsize);
			cptra_sha384_update(p8 + i, bsize);
		}

		cptra_sha384_final(digest, 48);
		if (!memcmp(digest, tv[5].digest, 48)) {
			dbg_printf("digest compare - PASS\n");
		} else {
			printf("digest compare - FAIL\n");
			return -1;
		}
	}

	printf("%s: Pass\n", __func__);

	return 0;
}

static int cptra_test_caliptra_fw_load(void)
{
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	enum cptra_ipc_cmd ipccmd = CPTRA_IPCCMD_CALIPTRA_FW_LOAD;
	uint32_t data[2] = {0};
	void *msg_src, *msg_dst;
	int ret;

	printf("%s: Start...\n", __func__);

	/* Prepare tx data to bootmcu */
	data[0] = (uintptr_t)p8_bmcu_in;
	data[1] = CPTRA_FW_SIZE;

	msg_src = map_phys(CPTRA_FW_ADDR, CPTRA_FW_SIZE);
	if (!msg_src) {
		printf("map_phys failed\n");
		return -1;
	}

	msg_dst = (void *)shared_mem_in;

	dbg_printf("memcpy to addr %lx\n", (uintptr_t)msg_dst);
	memcpy(msg_dst, (void *)msg_src, CPTRA_FW_SIZE);

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		dbg_printf("cptra_ipc_trigger:0x%x is failure, ret:0x%x\n", ipccmd,
		       ret);
		goto cleanup;
	} else {
		dbg_printf("cptra_ipc_trigger:0x%x is successful\n", ipccmd);
	}

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));
	if (ret) {
		dbg_printf("cptra_ipc_receive:0x%x is failure, ret:0x%x\n", ipccmd,
		       ret);
		goto cleanup;
	} else {
		dbg_printf("cptra_ipc_receive:0x%x is successful\n", ipccmd);
	}

cleanup:
	munmap(msg_src, CPTRA_FW_SIZE);

	if (ret)
		goto end;

	printf("%s: Pass\n", __func__);
	return 0;

end:
	printf("%s: Failed\n", __func__);
	return ret;
}

typedef int (*cptra_test_func_t)(void);

struct cptra_test_entry {
	const char *name;
	cptra_test_func_t func;
};

static struct cptra_test_entry cptra_tests[] = {
	/* Firmware Load Test */
	{ "caliptra_fw_load",			cptra_test_caliptra_fw_load },

	/*  Crypto Tests */
	{ "sha384",				cptra_test_sha384 },
	{ "sha384_acc",				cptra_test_sha384_acc },
	{ "ecdsa_verify",			cptra_test_ecdsa_verify },
	{ "lms_verify",				cptra_test_lms_verify },

	/* DICE Tests */
	{ "stash_measurement",			cptra_test_stash_measurement },
	{ "quote_pcrs",				cptra_test_quote_pcrs },
	{ "extend_pcr",				cptra_test_extend_pcr },
	{ "increment_pcr_reset_counter",	cptra_test_increment_pcr_reset_counter },
	{ "dpe_tag_tci",			cptra_test_dpe_tag_tci },
	{ "dpe_get_tagged_tci",			cptra_test_dpe_get_tagged_tci },
	{ "add_subject_alt_name",		cptra_test_add_subject_alt_name },
	{ "certify_key_extended",		cptra_test_certify_key_extended },
	{ "disable_attestation",		cptra_test_disable_attestation },
	{ "get_idev_cert",			cptra_test_get_idev_cert },
	{ "get_idev_info",			cptra_test_get_idev_info },
	{ "get_ldev_cert",			cptra_test_get_ldev_cert },
	{ "get_fmc_alias_cert",			cptra_test_get_fmc_alias_cert },
	{ "get_rt_alias_cert",			cptra_test_get_rt_alias_cert },
	{ "get_idevid_csr",			cptra_test_get_idevid_csr },
	{ "invoke_dpe_command",			cptra_test_invoke_dpe_command },
	{ "get_cert_chain",			cptra_test_get_cert_chain },

	{ "fw_info",				cptra_test_fw_info },
	{ "capabilities",			cptra_test_capabilities },
	{ "version",				cptra_test_version },
	// Add more test functions here as needed
};

static int cptra_tests_count = ARRAY_SIZE(cptra_tests);

static void set_file_descriptor_limit(void)
{
	struct rlimit limit;

	limit.rlim_cur = 4096;
	limit.rlim_max = 4096;

	if (setrlimit(RLIMIT_NOFILE, &limit) == 0)
		printf("File descriptor limit set to 4096\n");
	else
		perror("Failed to set file descriptor limit");
}

static int stress_cptra(int fd)
{
	gbl_fd = fd;
	int iterations = 1000; // Number of iterations for stress test
	int ret;

	set_file_descriptor_limit();

	shared_mem_in = (volatile uint8_t *)map_phys(IPC_CHANNEL_1_NS_CA35_IN_ADDR, SHARED_MEM_SIZE);
	if (!shared_mem_in) {
		printf("map_phys failed\n");
		return -1;
	}

	printf("Starting stress test with %d iterations...\n", iterations);
	for (int i = 0; i < iterations; i++) {
		printf("Iteration %d/%d\n", i + 1, iterations);
		for (int j = 0; j < cptra_tests_count; j++) {
			if (strcmp(cptra_tests[j].name, "dpe_tag_tci") == 0 ||
			    strcmp(cptra_tests[j].name, "dpe_get_tagged_tci") == 0 ||
			    strcmp(cptra_tests[j].name, "invoke_dpe_command") == 0)
				continue; // Skip tests that may alter state

			 // Skip stash measurements tests after one time
			if (i >= 1 && (strcmp(cptra_tests[j].name, "stash_measurement") == 0))
				continue;

			printf(" Running test: %s\n", cptra_tests[j].name);
			ret = cptra_tests[j].func();
			if (ret) {
				printf("  Test %s failed: %d\n", cptra_tests[j].name, ret);
				goto end;
			}
		}
	}

	printf("Stress test completed successfully.\n");
	munmap((void *)shared_mem_in, SHARED_MEM_SIZE);
end:
	return ret;
}

static int cmd_cptra(int fd, int num)
{
	int results = 0, ret = -1;

	gbl_fd = fd;
	shared_mem_in = (volatile uint8_t *)map_phys(IPC_CHANNEL_1_NS_CA35_IN_ADDR, SHARED_MEM_SIZE);
	if (!shared_mem_in) {
		printf("map_phys failed\n");
		return -1;
	}

	if (num < 0) {
		for (int i = 0; i < cptra_tests_count; i++) {
			printf("Running test: %s\n", cptra_tests[i].name);
			ret = cptra_tests[i].func();
			if (ret) {
				printf("Test %s failed: %d\n", cptra_tests[i].name, ret);
				results++;
			}
		}
		printf("Total tests run: %d, Failures: %d\n", cptra_tests_count, results);

	} else if (num >= 0 && num < cptra_tests_count) {
		printf("Running test: %s\n", cptra_tests[num].name);
		ret = cptra_tests[num].func();
		if (ret)
			printf("Test %s failed: %d\n", cptra_tests[num].name, ret);

	} else {
		printf("Invalid test number: %d\n", num);
	}

	munmap((void *)shared_mem_in, SHARED_MEM_SIZE);

	return ret;
}

static void usage(void)
{
	printf("Usage:\n");
	printf("1. aspeed-cptra list\n");
	printf("\tlist all available mailbox devices\n\n");
	printf("2. aspeed-cptra <dev_name> <subcommand> [args...]\n");
	printf("\tall				# run all subcommands\n");
	printf("\tlist				# list all subcommands\n");
	printf("\t<num>				# run cptra subcommands #num\n");
	printf("\tstress			# run cptra stress test\n");
}

int main(int argc, char *argv[])
{
	const char *device = argv[1];
	const char *cmd = NULL;
	char filename[256];
	int fd, ret;

	if (argc != 2 && argc != 3) {
		usage();
		return 1;
	}

	if (argc == 2 && strcmp(device, "list") != 0) {
		usage();
		return 1;
	}

	cmd = argv[2];

	if (strcmp(device, "list") == 0) {
		struct dirent *de;
		DIR *dfd = opendir("/dev");
		uint32_t buf[4] = {0};

		if (!dfd) {
			perror("opendir");
			return 1;
		}

		printf("Device:                      TX-SHMEM                RX-SHMEM\n");
		while ((de = readdir(dfd)) != NULL) {
			snprintf(filename, sizeof(filename), "/dev/%s", de->d_name);

			if (!strstr(filename, "mbox"))
				continue;

			fd = open(filename, O_RDWR);
			if (fd < 0)
				continue;

			ret = ioctl(fd, MBOX_IOCTL_CAPS, buf);
			if (ret < 0) {
				close(fd);
				continue;
			}
			printf("%-28s 0x%09llx, 0x%06x  0x%09llx, 0x%06x\n", de->d_name,
				  ((unsigned long long)buf[0]) << 8, buf[1],
				  ((unsigned long long)buf[2]) << 8, buf[3]);
			close(fd);
		}
	} else if (strcmp(cmd, "stress") == 0) {
		snprintf(filename, sizeof(filename), "/dev/%s", device);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		stress_cptra(fd);

		close(fd);

	} else if (strcmp(cmd, "all") == 0) {
		snprintf(filename, sizeof(filename), "/dev/%s", device);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		ret = cmd_cptra(fd, -1);
		if (ret) {
			printf("cptra command failed: %d\n", ret);
			close(fd);
			return 1;
		}

		close(fd);

	} else if (strcmp(cmd, "list") == 0) {
		snprintf(filename, sizeof(filename), "/dev/%s", device);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		/* list all cptra subcommands  */
		printf("Available cptra subcommands:\n");
		for (int i = 0; i < cptra_tests_count; i++)
			printf("  %d: %s\n", i, cptra_tests[i].name);

		close(fd);

	} else if (cmd && isdigit(cmd[0])) {
		snprintf(filename, sizeof(filename), "/dev/%s", device);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		int num = atoi(cmd);

		if (num < 0) {
			usage();
			return 1;
		}

		printf("num=%d\n", num);
		/* run cptra subcommand #num */
		ret = cmd_cptra(fd, num);

		close(fd);

	} else {
		usage();
		return 1;
	}

	return 0;
}
