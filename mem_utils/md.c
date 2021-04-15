/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "mem_common.h"

int print_buffer (unsigned long, void *, unsigned int, unsigned int, unsigned int);

unsigned long phy_addr = 0;

#define DISP_LINE_LEN   16

int main(int argc, char *argv[])
{
	unsigned long virt_addr, length;
	void * map_base; 
	int	size, fd;
	int	rc = 0;
	unsigned long dp_last_addr=0, dp_last_size=0, dp_last_length=32;

	/* We use the last specified parameters, unless new ones are
	 * entered.
	 */
	if (dp_last_addr) phy_addr = dp_last_addr;
	if (dp_last_size) size = dp_last_size;
	if (dp_last_length) length = dp_last_length;

	if (argc < 2) {
		printf ("Usage:\n%s\n", "md address range");
		return 1;
	}

    fd = open("/dev/mem", O_RDWR|O_SYNC);  
    if (fd == -1)  
    {  
    	printf("open /dev/mem fail .. \n");
		return (-1);  
    }  

	/* New command specified.  Check for a size specification.
	 * Defaults to long if no or incorrect specification.
	 */
	if ((size = cmd_get_data_size(argv[0], 4)) < 0)
		return 1;

	/* Address is specified since argc > 1
	addr = simple_strtoul(argv[1], NULL, 16); */
	phy_addr = simple_strtoul(argv[1], NULL, 16);
/*	printf("addr = %08x \n", addr); */

	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, phy_addr & ~MAP_MASK);

	if(map_base == (void *) -1) {
    	printf("mmap fail .. \n");
		return (-1);  
	}

/*	printf("mapping base = %08x , addr = %08x \n", map_base, addr); 
	addr = map_base + (addr & MAP_MASK); */
	virt_addr = map_base + (phy_addr & MAP_MASK); 
	
	/* If another parameter, it is the length to display.
	* Length is the number of objects, not number of bytes.
	*/
	if (argc > 2)
		length = simple_strtoul(argv[2], NULL, 16);

	/* Print the lines. */
	print_buffer(virt_addr, (void*)virt_addr, size, length, DISP_LINE_LEN/size);
	phy_addr += size*length;

	dp_last_addr = phy_addr;
	dp_last_length = length;
	dp_last_size = size;
	if(munmap(map_base, MAP_SIZE) == -1) printf("mmap fail .. \n");
    close(fd);	
	return (rc);
}

#define MAX_LINE_LENGTH_BYTES (64)
#define DEFAULT_LINE_LENGTH_BYTES (16)
int print_buffer (unsigned long addr, void* data, unsigned int width, unsigned int count, unsigned int linelen)
{
	unsigned char linebuf[MAX_LINE_LENGTH_BYTES];
	unsigned int *uip = (void*)linebuf;
	unsigned short int *usp = (void*)linebuf;
	unsigned char *ucp = (void*)linebuf;
	int i;

	if (linelen*width > MAX_LINE_LENGTH_BYTES)
		linelen = MAX_LINE_LENGTH_BYTES / width;
	if (linelen < 1)
		linelen = DEFAULT_LINE_LENGTH_BYTES / width;

	while (count) {
		printf("%08lx:", phy_addr);

		/* check for overflow condition */
		if (count < linelen)
			linelen = count;

		/* Copy from memory into linebuf and print hex values */
		for (i = 0; i < linelen; i++) {
			if (width == 4) {
				uip[i] = *(volatile unsigned int *) data;
				printf(" %08x", uip[i]);
			} else if (width == 2) {
				usp[i] = *(volatile unsigned short int *) data;
				printf(" %04x", usp[i]);
			} else {
				ucp[i] = *(volatile unsigned char *) data;
				printf(" %02x", ucp[i]);
			}
			data += width;
		}
#if 0
		/* Print data in ASCII characters */
		puts("    ");
		for (i = 0; i < linelen * width; i++)
			putchar(isprint(ucp[i]) && (ucp[i] < 0x80) ? ucp[i] : '.');
#endif
		putchar ('\n');

		/* update references */
		addr += linelen * width;
		phy_addr += linelen * width;
		count -= linelen;
	}
	return 0;
}
