/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "mem_common.h"

int main(int argc, char *argv[])
{
	unsigned long   addr, writeval, count;
	void * map_base; 
	int	size, fd;

	if ((argc < 3) || (argc > 4)) {
		printf ("Usage:\n%s\n", "mw address value");
		return 1;
	}

	/* Check for size specification.
	*/
	if ((size = cmd_get_data_size(argv[0], 4)) < 1)
		return 1;

    fd = open("/dev/mem", O_RDWR|O_SYNC);  
    if (fd == -1)  
    {  
    	printf("open /dev/mem fail .. \n");
		return (-1);  
    }  

	/* Address is specified since argc > 1
	*/
	addr = simple_strtoul(argv[1], NULL, 16);

	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, addr & ~MAP_MASK);

	if(map_base == (void *) -1) {
		printf("mmap fail .. \n");
		return (-1);  
	}

/*	printf("mapping base = %08x , addr = %08x \n", map_base, addr); */

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
			*((unsigned long *) addr) = (unsigned long) writeval;
		else if (size == 2)
			*((unsigned short *) addr) = (unsigned short) writeval;
		else
			*((unsigned char *) addr) = (unsigned char) writeval;
		addr += size;
	}

	if(munmap(map_base, MAP_SIZE) == -1) printf("mmap fail .. \n");
    close(fd);	

	return 0;
}
