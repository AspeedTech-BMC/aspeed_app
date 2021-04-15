#include <stdio.h>   
#include <linux/types.h>   
#include <fcntl.h>   
#include <unistd.h>   
#include <stdlib.h>   
#include <sys/types.h>   
#include <sys/ioctl.h>   
#include <errno.h>   
#include <assert.h>   
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>

#include <sys/mman.h>

#include <linux/i2c.h>   
#include <linux/i2c-dev.h>   

#define I3C_M_CCC			0x9000


typedef unsigned char u8;
typedef signed char s8;

typedef unsigned long int u32;
typedef signed long int s32;

typedef unsigned short int u16;
typedef signed short int s16;

static void
usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
		"Usage: %s [options]\n\n"
		"Options:\n"
		" -h | --help             Print this message\n"
		" -a | --address/cmd_id   address or ccc_cmd id\n"
		" -r | --read             read length \n"
		" -w | --write            write length \n"
		" -s | --smbus            smbus transfer \n"
		" -c | --ccc              ccc cmd \n"
		" -d | --dev              device node \n"
		"",
		argv[0]);
}

static const char short_options [] = "ha:r:w:d:c:s";

static const struct option
	long_options [] = {
	{ "help",               no_argument,            NULL,   'h' },
	{ "addr",               required_argument,      NULL,   'a' },
	{ "read",               required_argument,      NULL,   'r' },
	{ "write",              required_argument,      NULL,   'w' },
	{ "device",             required_argument,      NULL,   'd' },
	{ "ccc",             	required_argument,      NULL,   'c' },
	{ "smbus",               no_argument,      NULL,   's' },
	{ 0, 0, 0, 0 }
};

unsigned int StrToHex(char *p)
{
        int i, sum;
        int temp, length;
        char c;
        sum = 0;
        length = strlen(p);
        for( i = 0; i < (length) ; i++ )
        {
                c = *p;
                if( c >= 'a' && c <= 'z') {
                        temp = c - 87;
                        sum += ((temp) << (4*(length - i - 1)));
                } else if( c >= 'A' && c <= 'Z') {
                        temp = c - 55;
                        sum += ((temp) << (4*(length - i - 1)));
                } else {
                        temp = c - 48;
                        sum = sum + ((temp) << (4*(length - i - 1)));
                }

                p = p + 1;
        }
        return sum;
}


int main(int argc, char *argv[])
{  
	int fd, ret, i;  
	char option;

	char wdata[20];
	int write_len = 0;
	int read_len = 0;
	int ccc_cmd_id = -1;
	unsigned char device_addr = 0;
	unsigned char read_data[40];
	char write_data[40];
	char devpatch[30];
	int smbus = 0;
	struct i2c_rdwr_ioctl_data i2c_rdwr_data;  

	if(argc == 1) {
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}
		
	while ((option = getopt_long(argc, argv, short_options, long_options, NULL)) != (char) -1) {
//			printf("option is c %c\n", option);
			switch (option) {
					case 'h':
							usage(stdout, argc, argv);
							exit(EXIT_SUCCESS);
							break;
					case 'd':
							memset(devpatch, 0, 30);
							strcpy(devpatch, optarg);
							break;
					case 'a':
							device_addr = atol(optarg);
							break;
					case 'c':
							ccc_cmd_id = StrToHex(optarg);
							break;
							
					case 'r':
							read_len = atol(optarg);
							break;
					case 'w':
							write_len = atol(optarg);
							printf("write_len %d \n", write_len);
							break;
					case 's':
							smbus = 1;
							break;
					default:
							usage(stdout, argc, argv);
							exit(EXIT_FAILURE);
					}
	}

	if(ccc_cmd_id) {
		printf("[%s] - ccc cmd id %d, read %d, write %d \n", devpatch, ccc_cmd_id, read_len, write_len);
	} else 
		printf("[%s] - addr %x, read %d, write %d \n", devpatch, device_addr, read_len, write_len);

	fd= open(devpatch, O_RDWR);  
		if(fd < 0) {  
		perror("openerror");  
		exit(1);  
	}  

	i2c_rdwr_data.nmsgs = 2;

	i2c_rdwr_data.msgs= (struct i2c_msg *)malloc(i2c_rdwr_data.nmsgs * sizeof(struct i2c_msg));  

	if(i2c_rdwr_data.msgs == NULL) {  
		perror("mallocerror");  
		exit(1);  
	}  

	i2c_rdwr_data.msgs[0].addr = device_addr;  

	if(ccc_cmd_id != -1) {
		i2c_rdwr_data.msgs[0].len = write_len + 2;
		i2c_rdwr_data.msgs[0].flags = I3C_M_CCC;	 /* write */  
		i2c_rdwr_data.msgs[0].buf = (u8 *)write_data;
		i2c_rdwr_data.msgs[0].buf[0] = ccc_cmd_id;
		i2c_rdwr_data.msgs[0].buf[1] = 0;

		i2c_rdwr_data.nmsgs = 1;  

		if(write_len) {
			i2c_rdwr_data.msgs[0].buf[1] = write_len;	 /* write length */  
			for(i = 0; i < write_len; i++) {
				printf("[%d] = ", i);
				scanf("%s", wdata);
				i2c_rdwr_data.msgs[0].buf[i + 2] = StrToHex(wdata);
			}
//			for(i = 0; i < write_len + 1; i++)
//				printf("%x ", i2c_rdwr_data.msgs[0].buf[i]);
		}

		if(read_len) {		
			i2c_rdwr_data.msgs[0].len = read_len + 2;  
			i2c_rdwr_data.msgs[0].flags = I3C_M_CCC | I2C_M_RD; 	/* read */	
			i2c_rdwr_data.msgs[0].buf[0] = ccc_cmd_id;
			i2c_rdwr_data.msgs[0].buf[1] = read_len;
		}

		if(!write_len && !write_len) {
			i2c_rdwr_data.nmsgs = 1; 			
		}
		
		ret= ioctl(fd, I2C_RDWR, (unsigned long)&i2c_rdwr_data);  
		if(ret < 0) {  
			perror("ccc cmd error");	
			exit(1);  
		}

		
		printf("======== rx ==========================\n");
//		for(i = 0; i < i2c_rdwr_data.msgs[0].buf[0]; i ++) 
//			printf("%x \n", i2c_rdwr_data.msgs[0].buf[0]);
		printf("==================================\n");
	} else if (smbus) {
	
	} else {
		printf("write xxx \n");
		/*向e2prom的rdwr_addr地址寫入資料data*/  
		i2c_rdwr_data.nmsgs = 1;  
		i2c_rdwr_data.msgs[0].len = 2;
		i2c_rdwr_data.msgs[0].addr= device_addr;  
		i2c_rdwr_data.msgs[0].flags = 0;     /* write */  
		i2c_rdwr_data.msgs[0].buf = write_data;  
		i2c_rdwr_data.msgs[0].buf[0] = 0x50;    /* write address */  
		i2c_rdwr_data.msgs[0].buf[1] = 0xaa;    /* write data */  
		ret= ioctl(fd, I2C_RDWR, (unsigned long)&i2c_rdwr_data);  
		if(ret < 0) {  
			perror("writedata error");  
			exit(1);  
		}  
	}
exit(1);
#if 0	
	printf("writedata: %d to address: %#x\n", data, rdwr_addr);  
	data= 0;  /* be zero*/  
	/*從e2prom的rdwr_addr地址讀取資料存入buf*/  
	i2c_rdwr_data.nmsgs= 2;  
	i2c_rdwr_data.msgs[0].len= 1;  
	i2c_rdwr_data.msgs[0].addr= device_addr;  
	//      i2c_rdwr_data.msgs[0].flags= 0;     /* write */   
	i2c_rdwr_data.msgs[0].buf= &rdwr_addr;  
	i2c_rdwr_data.msgs[1].len= 1;  
	i2c_rdwr_data.msgs[1].addr= device_addr;  
	i2c_rdwr_data.msgs[1].flags= 1;     /* read */  
	i2c_rdwr_data.msgs[1].buf= &data;  
	ret= ioctl(fd, I2C_RDWR, (unsigned long)&i2c_rdwr_data);  
	if(ret < 0) {  
		perror("readerror");  
		exit(1);  
	}  

	printf("read  data: %d from address: %#x\n", data,rdwr_addr);  
#endif	
	free(i2c_rdwr_data.msgs);  
	close(fd);  
	return 0;  
}
