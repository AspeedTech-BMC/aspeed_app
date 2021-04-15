/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include "mem_common.h"

int print_buffer (unsigned long, void *, unsigned int, unsigned int, unsigned int);

#define DISP_LINE_LEN   16

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

unsigned long spim_read(unsigned long addr)
{
	unsigned long data, tcnt1, tcnt2;

	tcnt1 = 0;
	do{
		spim_wha(addr);
		*((unsigned long *) (spi_mem_virt)) = SPIM_CMD_RD  |
		                             ((addr >> 8) & 0xff00) |
		                             ((addr << 8) & 0xff0000) |
		                             ((addr << 24) & 0xff000000);

		tcnt2 = 0;
		do{
			data = spim_get_byte(tcnt2);
			if(++tcnt2 > 500000){
				printf("Read polling timeout. Get status = %x\n",data);
				spim_end();
				exit(0);
			}
			if(tcnt2 > 100 && data != 0x55 && data != 0xAA){
				spim_end();
				break;
			}
		}while(data != 0xAA);
		if(++tcnt1 > 100){
		  printf("Read polling timeout. Error status = %x\n",data);
		  spim_end();
		  exit(0);
		}
	}while(data != 0xAA);
	
	data  = spim_get_byte(1);
	data |= spim_get_byte(1) << 8;
	data |= spim_get_byte(1) << 16;
	data |= spim_get_byte(1) << 24;
	spim_end();
	return(data);
}

int main(int argc, char *argv[])
{
	unsigned long	addr, length;
	int	size;
	int	rc = 0;
	unsigned long dp_last_addr=0, dp_last_size=0, dp_last_length=32;

	/* We use the last specified parameters, unless new ones are
	 * entered.
	 */
	if (dp_last_addr) addr = dp_last_addr;
	if (dp_last_size) size = dp_last_size;
	if (dp_last_length) length = dp_last_length;

	if (argc < 2) {
		printf ("Usage:\n%s\n", "md 0x241000 0x30");
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
	*/
	addr = simple_strtoul(argv[1], NULL, 16);
/*	printf("addr = %08x \n", addr); */

	spi_base_virt = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SPI_BASE & ~MAP_MASK);

	if(spi_base_virt == (void *) -1) {
    	printf("mmap fail .. \n");
		return (-1);  
	}


	spim_cs = 1;
	spim_init(spim_cs);

/*	printf("spi_base_virt = %08x , addr = %08x \n", spi_base_virt, addr);  */

	
	/* If another parameter, it is the length to display.
	* Length is the number of objects, not number of bytes.
	*/
	if (argc > 2)
		length = simple_strtoul(argv[2], NULL, 16);

	/* Print the lines. */
	print_buffer(addr, (void*)addr, size, length, DISP_LINE_LEN/size);
	addr += size*length;

	dp_last_addr = addr;
	dp_last_length = length;
	dp_last_size = size;
	if(munmap(spi_base_virt, MAP_SIZE) == -1) printf("mmap fail .. \n");
	if(munmap(spi_mem_virt, MAP_SIZE) == -1) printf("mmap fail .. \n");
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
		printf("%08lx:", addr);

		/* check for overflow condition */
		if (count < linelen)
			linelen = count;

		/* Copy from memory into linebuf and print hex values */
		for (i = 0; i < linelen; i++) {
			if (width == 4) {
				uip[i] = spim_read(data);
				printf(" %08x", uip[i]);
			} else if (width == 2) {
				usp[i] = spim_read(data);
				printf(" %04x", usp[i]);
			} else {
				ucp[i] = spim_read(data);
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
		count -= linelen;
	}
	return 0;
}
