/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/string.h>
#include <poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

typedef unsigned char u8;
typedef signed char s8;
  
typedef unsigned long int u32;
typedef signed long int s32;
    
typedef unsigned short int u16;
typedef signed short int s16;
    

#define BUFFER_SIZE			(0x1000) //pc DMA size
#define MAX_BOX_SIZE        (16)
#define DEV_PATH_MAX        (20)

struct bt_response {
	u8 length;
	u8 netfn_lun;
	u8 seq;
	u8 cmd;
	u8 comp_code;
	u8 data[0];
};

struct bt_request {
	u8 length;
	u8 netfn_lun;
	u8 seq;
	u8 cmd;
	u8 data[0];
};

struct kcs_response {
	u8 netfn_lun;
	u8 cmd;
	u8 comp_code;
	u8 data[0];
};

struct kcs_request {
	u8 netfn_lun;
	u8 cmd;
	u8 data[0];
};

static void
usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
		"Usage: %s [options]\n\n"
		"Options:\n"
		" -h | --help                   Print this message\n"
		" -k | --kcs                    kcs device node\n"
		" -b | --bt                     bt device node\n"
		" -m | --mbox                   mbox device node\n"
		" -s | --snoop                  snoop device node\n"
		"",
		argv[0]);
}

static const char short_options [] = "hk:b:m:s:";

static const struct option
	long_options [] = {
	{ "help",               no_argument,            NULL,   'h' },
	{ "kcs",               required_argument,      NULL,   'k' },
	{ "bt",               required_argument,      NULL,   'b' },
	{ "mbox",               required_argument,      NULL,   'm' },
	{ "snoop",               required_argument,      NULL,   's' },
	{ 0, 0, 0, 0 }
};

u8 request[BUFFER_SIZE];
u8 reponse[BUFFER_SIZE];

int main(int argc, char *argv[])
{
 	int size,index;
	char option;
 	int rc;
	int kcs = 0;
	int bt = 0;
	int mbox = 0;
	int snoop = 0;
 	struct pollfd mb_fd;
	char devpath[DEV_PATH_MAX];
	u8 resp_size = 0;
 
	while ((option = getopt_long(argc, argv, short_options, long_options, NULL)) != (char) -1) {
	//	printf("option is c %c\n", option);
		switch (option) {
			case 'h':
				usage(stdout, argc, argv);
				exit(EXIT_SUCCESS);
				break;
			case 'k':
				kcs = 1;
				memset(devpath, 0, DEV_PATH_MAX);
				strcpy(devpath, optarg);
				break;
			case 'b':
				bt = 1;
				memset(devpath, 0, DEV_PATH_MAX);
				strcpy(devpath, optarg);
				break;
			case 'm':
				mbox = 1;
				memset(devpath, 0, DEV_PATH_MAX);
				strcpy(devpath, optarg);
				break;
			case 's':
				snoop = 1;
				memset(devpath, 0, DEV_PATH_MAX);
				strcpy(devpath, optarg);
				break;
			default:
				usage(stdout, argc, argv);
				exit(EXIT_FAILURE);
			}
	}

    memset(request,0x00,BUFFER_SIZE);
    printf("Open devnode : %s\n", devpath);
 	
    mb_fd.fd = open(devpath, O_RDWR | O_NONBLOCK);
 	if (mb_fd.fd < 0) {
 		printf("Couldn't open %s with flags O_RDWR: %s\n",
 				devpath, strerror(errno));
 		return -errno;
 	}
 
 	mb_fd.events = POLLIN;
	while (1) {
		printf("Waiting for ipmi in\n");

		rc = poll(&mb_fd, 1, -1);

		if (rc < 0) {
			printf("Error from poll(): %s\n", strerror(errno));
			break;
		}
		if (mb_fd.revents & POLLIN) {
			printf("Device %s event\n",argv[1]);
			if (mbox) {
				size = read(mb_fd.fd,request,MAX_BOX_SIZE);
			} else {
				size = read(mb_fd.fd,request,BUFFER_SIZE);
			}
			if (size < 0 ) {
				printf("Couldn't read %s \n",strerror(errno));
				return -errno;
			} else if ( size < BUFFER_SIZE ) {
				printf("Read less: size %d \n",size);
			}
			for (index = 0; index < size; index++) {
				printf("Request data - index[%d]: 0x%.2x\n", index, request[index]);
			}
			memcpy(reponse,request,size);
			resp_size = size;
			
			if (bt == 1) {
				struct bt_response *pres = (struct bt_response *) reponse;
				pres->length += 1;
				pres->comp_code = 0x0;
				resp_size += 1;
			} else if (kcs == 1) {
				struct kcs_response *pres = (struct kcs_response *) reponse;
				//pres->netfn_lun += 0x4;
				pres->comp_code = 0x0;
				resp_size += 1;
				for (index = 0; index < resp_size; index++) {
					printf("Response data - index[%d]: 0x%.2x\n", index, reponse[index]);
				}
			} else if (mbox == 1) {
				for (index = 0; index < resp_size; index++) {
					printf("Response data - index[%d]: 0x%.2x\n", index, reponse[index]);
				}
			} else if (snoop == 1) {
				continue;
			}
			if (snoop == 1) {
				break;
			}
			printf("Write starts size %d\n",resp_size);
			size = write(mb_fd.fd,reponse,resp_size);
			if (size<resp_size) {
				printf("Couldn't write %s \n",strerror(errno));
				return -errno;
			}
		}
	}

     close(mb_fd.fd);
     return 0;
}
