/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <stdint.h>
#include "mem_common.h"
#include "compiler.h"

/* Create a compile-time value */
#ifdef MEM_SUPPORT_64BIT_DATA
#define SUPPORT_64BIT_DATA 1
#else
#define SUPPORT_64BIT_DATA 0
#endif

int main(int argc, char *argv[])
{
	unsigned long writeval; /* 64-bit if SUPPORT_64BIT_DATA */
	unsigned long addr, count;
	int size;
	void *map_base;
	int fd;

	if ((argc < 3) || (argc > 4)) {
		printf("Usage:\n%s\n", "mw address value");
		return 1;
	}

	/* Check for size specification.
	*/
	if ((size = cmd_get_data_size(argv[0], 4)) < 1)
		return 1;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd == -1) {
		printf("open /dev/mem fail ..\n");
		return (-1);
	}

	/* Address is specified since argc > 1
	*/
	addr = simple_strtoul(argv[1], NULL, 16);

	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			addr & ~MAP_MASK);

	if (map_base == (void *)-1) {
		printf("mmap fail .. \n");
		return (-1);
	}

	/*printf("mapping base = %08x , addr = %08x\n", map_base, addr); */

	addr = map_base + (addr & MAP_MASK);

	/* Get the value to write.
	*/
	writeval = simple_strtoul(argv[2], NULL, 16);

	/* Count ? */
	if (argc == 4) {
		count = simple_strtoul(argv[3], NULL, 16);
	} else {
		count = 1;
	}

	while (count-- > 0) {
		if (size == 4)
			*((uint32_t *)addr) = (uint32_t)writeval;
		else if (SUPPORT_64BIT_DATA && size == 8)
			*((uint64_t *)addr) = writeval;
		else if (size == 2)
			*((uint16_t *)addr) = (uint16_t)writeval;
		else
			*((uint8_t *)addr) = (uint8_t)writeval;
		addr += size;
	}

	if (munmap(map_base, MAP_SIZE) == -1)
		printf("mmap fail ..\n");
	close(fd);

	return 0;
}
