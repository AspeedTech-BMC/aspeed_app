// SPDX-License-Identifier: GPL-2.0+
// aspeed_mbox.c - Linux user-space tool for ASPEED mailbox
// Usage: aspeed_mbox <subcommand> [args...]
// Subcommands: list, stress, send, recv, read, write

#include <dirent.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

// Define ioctl numbers (replace with actual values from your kernel driver)
#define MBOX_IOCTL_CAPS  _IOR('X', 0x00, uint32_t[4])
#define MBOX_IOCTL_SEND  _IOW('X', 0x01, uint32_t[8])
#define MBOX_IOCTL_RECV  _IOR('X', 0x02, uint32_t[8])

void usage(void)
{
	printf("Usage: aspeed-mbox <subcommand> [args...]\n");
	printf("  list\n");
	printf("  stress <name>             # <name>: Device name (e.g., mbox0)\n");
	printf("  send <name> <addr>        # <name>: Device name, <addr>: Physical address (hex)\n");
	printf("  recv <name> <addr>        # <name>: Device name, <addr>: Physical address (hex)\n");
	printf("  read <name> <addr> <len>  # <name>: Device name, <addr>: Physical address (hex), <len>: Length (hex)\n");
	printf("  write <name> <addr> <len> # <name>: Device name, <addr>: Physical address (hex), <len>: Length (hex)\n");
}

int stress_test(int fd)
{
	struct pollfd fds[1];
	uint32_t msg[8] = {0};
	uint32_t buf[0x1000];
	uint8_t cmd;
	int size, counter = 0;
	uint32_t pattern;
	int ret;

	while (1) {
		fds[0].fd = fd;
		fds[0].events = POLLIN;

		while (1) {
			ret = poll(fds, 1, 1000);
			if (ret & POLLIN) {
				ret = ioctl(fd, MBOX_IOCTL_RECV, msg);
				break;
			}
		}

		cmd = msg[0] & 0xff;
		if (cmd != 0xF0) {
			if (cmd == 0xF1)
				printf("Received shutdown command, exiting stress test.\n");
			else
				printf("Unexpected message type: 0x%x\n", msg[0]);
			break;
		}
		size = msg[0] >> 8;
		pattern = msg[1];
		printf("Received message: 0x%x 0x%x\n", msg[0], msg[1]);
		ret = read(fd, buf, size);
		if (ret != size) {
			perror("read");
			return 1;
		}

		for (int i = 0; i < size / 4; i++, pattern++) {
			if (buf[i] != pattern) {
				printf("Data mismatch at index %d: expected 0x%x, got 0x%x\n", i, pattern, buf[i]);
				return 1;
			}
		}

		printf("stress round-%d pass\n", ++counter);

		msg[1] = pattern;
		for (int i = 0; i < size / 4; i++, pattern++)
			buf[i] = pattern;

		ret = write(fd, buf, size);
		if (ret != size) {
			perror("write");
			return 1;
		}

		// Echo back
		ret = ioctl(fd, MBOX_IOCTL_SEND, msg);
		if (ret < 0) {
			perror("ioctl(MBOX_IOCTL_SEND)");
			return 1;
		}
		printf("Sent message back.\n");
	}

	return 0;
}

void *map_phys(off_t offset, size_t len)
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

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return 1;
	}
	const char *cmd = argv[1];
	char filename[256];
	int fd, ret;

	if (strcmp(cmd, "list") == 0) {
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
		snprintf(filename, sizeof(filename), "/dev/%s", argv[2]);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		stress_test(fd);

		close(fd);
	} else if (strcmp(cmd, "send") == 0) {
		if (argc != 4) {
			usage();
			return 1;
		}

		snprintf(filename, sizeof(filename), "/dev/%s", argv[2]);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		uint64_t msg_addr = strtoull(argv[3], NULL, 16);
		void *msg = map_phys(msg_addr, 32);

		ret = ioctl(fd, MBOX_IOCTL_SEND, msg);
		if (ret < 0) {
			perror("ioctl(MBOX_IOCTL_SEND)");
			close(fd);
			return 1;
		}
		printf("Message sent.\n");
		close(fd);
	} else if (strcmp(cmd, "recv") == 0) {
		if (argc != 4) {
			usage();
			return 1;
		}

		snprintf(filename, sizeof(filename), "/dev/%s", argv[2]);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		uint64_t msg_addr = strtoull(argv[3], NULL, 16);
		uint32_t *msg = (uint32_t *)map_phys(msg_addr, 32);

		ret = ioctl(fd, MBOX_IOCTL_RECV, msg);
		if (ret < 0) {
			perror("ioctl(MBOX_IOCTL_RECV)");
			close(fd);
			return 1;
		}
		printf("Message received: 0x%x 0x%x\n", msg[0], msg[1]);
		close(fd);
	} else if (strcmp(cmd, "read") == 0) {
		if (argc != 5) {
			usage();
			return 1;
		}

		snprintf(filename, sizeof(filename), "/dev/%s", argv[2]);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			printf("Error opening device %s: ", argv[2]);
			perror("open");
			return 1;
		}

		uint64_t buf_addr = strtoull(argv[3], NULL, 16);
		size_t len = strtoull(argv[4], NULL, 16);
		void *buf = map_phys(buf_addr, len);

		ret = read(fd, buf, len);
		if (ret < 0) {
			perror("read");
			close(fd);
			return 1;
		}
		printf("Read %d bytes from to addr %lx\n", ret, buf_addr);
		close(fd);
	} else if (strcmp(cmd, "write") == 0) {
		if (argc != 5) {
			usage();
			return 1;
		}

		snprintf(filename, sizeof(filename), "/dev/%s", argv[2]);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		uint64_t buf_addr = strtoull(argv[3], NULL, 16);
		size_t len = strtoull(argv[4], NULL, 16);
		void *buf = map_phys(buf_addr, len);

		ret = write(fd, buf, len);
		if (ret < 0) {
			perror("write");
			close(fd);
			return 1;
		}
		printf("Wrote %d bytes from addr %lx\n", ret, buf_addr);
		close(fd);
	} else {
		usage();
		return 1;
	}
	return 0;
}
