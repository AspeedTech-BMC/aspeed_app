/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "mem_common.h"

static void *spi_base_virt = 0;
static void *spi_mem_virt = 0;
static unsigned long *spi_mem_base = 0;

static unsigned long spim_cs=1,spim_hadr;

static int fd;

unsigned long spi_read(unsigned long reg)
{
	unsigned long read_result;
	read_result = *((unsigned long *) (spi_base_virt + reg));
	return read_result;
}

void spi_write(unsigned long val, unsigned long reg)
{
	*((unsigned long *) (spi_base_virt + reg)) = val;
}

void spim_end()
{
	unsigned long data;
	data = spi_read(0x10 + (spim_cs << 2));
	spi_write(data | 0x4, 0x10 + (spim_cs << 2));
	spi_write(data, 0x10 + (spim_cs << 2));
}

void spim_init(int cs)
{
  	unsigned long data;

  	spim_cs = cs;
	spi_write((0x2 << (cs << 1)) | (0x10000 << cs), 0x00);
	spi_write( 0x00000007, 0x10 + (cs << 2));
	spi_write( 0x00002003, 0x10 + (cs << 2));
	spi_write( 0x100 << cs, 0x04);	
	data = spi_read(0x30 + (cs << 2));

	spi_mem_base = 0x20000000 | ((data & 0x007f0000) << 7);
	spi_mem_virt = mmap(0, 0xff, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (unsigned long)(spi_mem_base) & ~MAP_MASK);
/* 	printf("spi_mem_base = %x , map spi_mem_virt = %x \n",spi_mem_base, spi_mem_virt ); */
	*((unsigned long *) (spi_mem_virt)) = SPIM_CMD_WHA;
  	spim_end();
	spim_hadr = 0;
}

unsigned long spim_status()
{
	unsigned long data;

	*((unsigned long *) (spi_mem_virt)) = SPIM_CMD_STA;
	data = *((unsigned long *) (spi_mem_virt));	
	spim_end();
	return((data >> 8) & 0xFF);
}

void spim_wha(unsigned long addr)
{
	if((addr & 0xff000000) != spim_hadr){
		spim_hadr = addr & 0xff000000;
		*((unsigned long *) (spi_mem_virt)) = SPIM_CMD_WHA | (spim_hadr >> 16);
		spim_end();
	}
}

unsigned long spim_get_byte(unsigned long type)
{
	static unsigned int spim_rbuf = 0, spim_rbuflsb = 0, spim_rbcnt = 0;

	if(!type){
		spim_rbcnt = 0;
		spim_rbuflsb = 0;
	}else{
		spim_rbuflsb = spim_rbuf & 0x1;
	}
	spim_rbuf = spim_rbuf >> 8;
	if(spim_rbcnt == 0){
		spim_rbuf = *((unsigned long *) (spi_mem_virt));
		spim_rbcnt = 4;
	}
	spim_rbcnt--;
#ifdef AST2300_A1
	return(((spim_rbuf & 0xff) >> 1) | (spim_rbuflsb << 7));
#else
	return(spim_rbuf & 0xff);
#endif
}

void spim_write(unsigned long addr, unsigned long data)
{
	spim_wha(addr);
	*((unsigned long *) (spi_mem_virt)) = SPIM_CMD_WR  |
	                           ((addr >> 8) & 0xff00) |
	                           ((addr << 8) & 0xff0000) |
	                           ((addr << 24) & 0xff000000);
	

	*((unsigned long *) (spi_mem_virt)) = data;
	
	spim_end();
}


int main(int argc, char *argv[])
{
	unsigned long   addr, writeval, count;
	int	size;

	if ((argc < 3) || (argc > 4)) {
		printf ("Usage:\n%s\n", "mw 0x241000 0x30000000");
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

	spi_base_virt = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SPI_BASE & ~MAP_MASK);

	if(spi_base_virt == (void *) -1) {
    	printf("mmap fail .. \n");
		return (-1);  
	}

	spim_cs = 1;
	spim_init(spim_cs);

/*	printf("mapping base = %08x , addr = %08x \n", map_base, addr); */


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
		spim_write(addr, writeval);
		addr += size;
	}

	if(munmap(spi_base_virt, MAP_SIZE) == -1) printf("mmap fail .. \n");
	if(munmap(spi_mem_virt, MAP_SIZE) == -1) printf("mmap fail .. \n");
    close(fd);	

	return 0;
}
