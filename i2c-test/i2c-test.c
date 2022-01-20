/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright Aspeed Technology Inc.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>

#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
/*****************************************************************************/
#define DEF_I2C_ADDR    0x04

#define DEF_THREAD_CH   12
#define DEF_PAIR0_DEV   0
#define DEF_PAIR1_DEV   1

#define DEF_PAIR1_ADDR  0x03
#define DEF_PAIR2_ADDR  0x04
#define TIMEOUT 10

#define DEF_SLAVE_ADDR  0x3a
#define DEF_XFER_BUF_SIZE  128

int debug = 0;
struct thread_data {
	char filename[512];
	uint8_t slave_addr;

	int ack_send_length;
	int loop_cnt;
	int continuous_flag;
	int random_flag;
	int xfer_size;		
	unsigned char *xfer_buf;
	unsigned char *pattern;
	int address;
	int bus;
	struct thread_data *pair_thread_data;
};

static void usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
			"Usage: %s [options]\n\n"
			"Options:\n"
			" -h | --help           Print this message\n"
			" -m | --master         master mode \n"
			" -s | --slave          slave mode\n"
			" -b | --bus            test bus number[default : 0]\n"
			" -a | --address        slav address [default : 0x04]\n"
			" -z | --tx_size        transfer size[default : 255]\n"
			" -c | --continuous     contunuous\n"
			" -l | --loop           loop test\n"
			" -p | --pair           pair on the same board[I2c-1 <-> I2c-2]\n"
			" -e | --echo           echo (0: tx 1: respond)\n"
			" -r | --random         test pattern is random\n"
			" -u | --multi          multi master test (-1: only echo1, >0: echo0 bus)\n"
			" -d | --debug          debug mode\n"
			" -i | --disable        disable the slave mode"
			"example:\n"
			"master and slave test:\n"
			"  boardA : $./i2c-test -m -a0x04 -b0\n"
			"  boardB : $./i2c-test -s -a0x04 -b0\n"
			"echo test:\n"
			"  boardA : $./i2c-test -e0\n"
			"  boardB : $./i2c-test -e1\n"
			"one board test:\n"
			"  boardA : $./i2c-test -p\n"
			"         : $./i2c-test -p -e0\n"
			"multi master test:\n"
			"  boardA : $./i2c-test -u0 -b1 -a0x4 ( a=(b+1)*2 ) \n"
			"  boardB : $./i2c-test -u-1 -b1 \n"
			"  boardA bus should equal boardB bus\n"
			"  boardA address should equal (bus+1)*2\n"
			"disable slave mode:\n"
			"$./i2c-test -i -b0"
			"",
			argv[0]);
}

static const char short_options [] = "hm:s:c:prdie:s:l:b:a:u:";

static const struct option
	long_options [] = {
	{ "help",       no_argument,            NULL,   'h' },
	{ "master",     no_argument,            NULL,   'm' },
	{ "slave",      no_argument,            NULL,   's' },
	{ "continuous", no_argument,            NULL,   'c' },
	{ "bus",        required_argument,      NULL,   'b' },
	{ "tx_size",    required_argument,      NULL,   's' },
	{ "loop",       required_argument,      NULL,   'l' },
	{ "pair",       no_argument,            NULL,   'p' },
	{ "echo",       required_argument,      NULL,   'e' },
	{ "random",     no_argument,            NULL,   'r' },
	{ "address",    required_argument,      NULL,   'a' },
	{ "multi",      required_argument,      NULL,   'u' },
	{ "debug",      no_argument,            NULL,   'd' },
	{ "disable",    no_argument,            NULL,   'i' },

	{ 0, 0, 0, 0 }
};

static void print_buf(unsigned char *pattern, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (!(i % 16))
			printf("\n");
		printf("%2x ", pattern[i]);
	}
	
	printf("\n");
}

static int compare_pattern(unsigned char *pattern0, unsigned char *pattern1,
						   int size)
{
	int i;
	for (i = 0; i < size; i++) {
		if (pattern0[i] != pattern1[i]) {
			return 0;
		}
	}
	return 1;
}

static void test_pattern_prepare(unsigned char *pattern, int size)
{
	int i, j;
	for (i = 0; i < size; i++) {
		j = i % 0xff;
		pattern[i] = j;
	}
}

static void random_pattern_prepare(unsigned char *pattern, int size)
{
	int i;
	FILE *fp;
	int randno;

	if ((fp = fopen("/dev/urandom", "r")) == NULL) {
		fprintf(stderr, "Error! Could not open /dev/urandom for read\n");
		exit(EXIT_FAILURE);
	}

	randno = fgetc(fp);

	for (i = 0; i < size; i++) {
		randno = fgetc(fp);
		pattern[i] = randno % 0xff;
	}

	fclose(fp);
}

void *i2c_master_thread(void *arg)
{
	struct thread_data *master_data = (struct thread_data *) arg;
	int loop_cnt        = master_data->loop_cnt;
	int continuous_flag = master_data->continuous_flag;
	int xfer_length 	= master_data->xfer_size;
	uint8_t *data 		= master_data->xfer_buf;	
	int fd;
	int result = 0;
	int xfer_cnt = 0;

	if(!continuous_flag)
		printf("MM loop_cnt %d\n", loop_cnt);
	
	fd = open(master_data->filename, O_RDWR);
	if (fd < 0) {
		printf("can't open %s \n", master_data->filename);
		return NULL;
	}

	if (ioctl(fd, I2C_SLAVE, master_data->slave_addr) < 0) {
		perror("i2cSetAddress");
		return NULL;
	}

	while (1) {
		if (debug) printf("[%d]:Mw [%x] len %d \n", xfer_cnt, master_data->slave_addr, xfer_length);
		if (write(fd, data, xfer_length) != xfer_length) {
			perror("write fail \n");
			result = 1;
			break;
		}
		
		if(!continuous_flag) {		
			loop_cnt--;
			if(!loop_cnt) break;
		}
		xfer_cnt++;
		if (debug) sleep(1);
	}

	close(fd);
	
	if (debug) printf("master thread end \n");

	if(result) 
		return (void *)1;
	else
		return NULL;

}

void *i2c_slave_thread(void *arg)
{
	struct thread_data *slave_data = (struct thread_data *) arg;
	int loop_cnt        = slave_data->loop_cnt;
	int continuous_flag = slave_data->continuous_flag;
//	int xfer_length 	= slave_data->xfer_size;
	uint8_t *data 		= slave_data->xfer_buf;	
	
    int i, r;
    struct pollfd pfd;
    struct timespec ts;
	int result = 0;

	if(!continuous_flag)
		printf("SS loop_cnt %d\n", loop_cnt);

    pfd.fd = open(slave_data->filename, O_RDONLY | O_NONBLOCK);
    if (pfd.fd < 0) {
		printf("%s not find \n", slave_data->filename);
        return NULL;
    }

    pfd.events = POLLPRI;

    while (1) {
        r = poll(&pfd, 1, 5000);
        if (r < 0)
            break;

        if (r == 0 || !(pfd.revents & POLLPRI))
            continue;

        lseek(pfd.fd, 0, SEEK_SET);
        r = read(pfd.fd, data, 512);
        if (r <= 0)
            continue;

		if(debug || continuous_flag) {
	        clock_gettime(CLOCK_MONOTONIC, &ts);
	        printf("[%ld.%.9ld] :", ts.tv_sec, ts.tv_nsec);
	        for (i = 0; i < r; i++)
	            printf(" %02x", data[i]);
	        printf("\n");
		}

//		if(xfer_length != r)
//			printf("rx length fail %d %d \n", xfer_length, r);


		if(compare_pattern(slave_data->xfer_buf, slave_data->pattern, slave_data->xfer_size + 1)) {
			printf("compare fail ----- \n");
			result = 1;
			break;
		}

		if(!continuous_flag) {
			loop_cnt--;
			if(!loop_cnt) break;
		}

    }

    close(pfd.fd);
	if (debug) printf("slave thread end \n");

	
	if(result) 
		return (void *)1;
	else
		return NULL;


}


int main(int argc, char *argv[])
{
	char option;

	pthread_t pthread_master_tx;
	pthread_t pthread_slave_rx;
	struct thread_data data_pthread_master_tx;
	struct thread_data data_pthread_slave_rx;

	void *master_ret, *slave_ret;
	int master_flag		= 0;
	int slave_flag		= 0;
	int loop_cnt 		= 0;
	int xfer_size		= 0;
	unsigned char pattern_buf[2*DEF_XFER_BUF_SIZE];
	unsigned char recv_buf[2*DEF_XFER_BUF_SIZE];

	data_pthread_master_tx.xfer_size = DEF_XFER_BUF_SIZE; 
	data_pthread_slave_rx.xfer_size = DEF_XFER_BUF_SIZE; 

//i2c-test -m /dev/i2c0 -s /sys/bus/i2c/devices/i2c-6/6-003a/slave-mqueue 
//			-a 0x3a -c 1 -l size
	test_pattern_prepare(pattern_buf, DEF_XFER_BUF_SIZE);

	printf("==== test pattern ==== \n");
	print_buf(pattern_buf, DEF_XFER_BUF_SIZE);
	printf("================= \n");	

	data_pthread_master_tx.pattern = pattern_buf;
	data_pthread_slave_rx.pattern = pattern_buf;

	while ((option = getopt_long(argc, argv, short_options, long_options, NULL)
		   ) != (char) - 1) {
		switch (option) {
		case 'h':
			usage(stdout, argc, argv);
			exit(EXIT_SUCCESS);
			break;
		case 'a':	//master for slave address
			data_pthread_master_tx.slave_addr = strtoul(optarg, 0, 0);
			data_pthread_slave_rx.slave_addr = strtoul(optarg, 0, 0);
			break;
		case 'm': 
			/* -m /dev/i2c0 */
			master_flag = 1;
			data_pthread_master_tx.xfer_buf = pattern_buf;
			strcpy(data_pthread_master_tx.filename, optarg);
			break; 
		case 's':
			/* -s /sys/bus/i2c/devices/i2c-6/6-003a/slave-mqueue */
			slave_flag = 1;
			data_pthread_slave_rx.xfer_buf = recv_buf;
			strcpy(data_pthread_slave_rx.filename, optarg);
			break;
		case 'c':	//count
			loop_cnt = strtoul(optarg, 0, 0);
			data_pthread_master_tx.loop_cnt = loop_cnt;
			data_pthread_slave_rx.loop_cnt = loop_cnt;
			break;
		case 'l':	//length
			xfer_size = strtoul(optarg, 0, 0);
			data_pthread_master_tx.xfer_size = xfer_size; 
			data_pthread_slave_rx.xfer_size = xfer_size; 
			break;
		case 'r':
			data_pthread_master_tx.random_flag = 1;
			data_pthread_slave_rx.random_flag = 1;
			random_pattern_prepare(pattern_buf, DEF_XFER_BUF_SIZE);
			break;
		case 'd':
			debug = 1;
			break;
		default:
			usage(stdout, argc, argv);
			exit(EXIT_FAILURE);
			break;
		}
	}

	if(loop_cnt == 0) {
		//if no loop cnt, will be continuous test
		data_pthread_master_tx.continuous_flag = 1;
		data_pthread_slave_rx.continuous_flag = 1;
	} else {
		data_pthread_master_tx.continuous_flag = 0;
		data_pthread_slave_rx.continuous_flag = 0;
	}
		
	if (!master_flag && !slave_flag) {
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}

	if (master_flag) {
		printf("master : [%s] : ", data_pthread_master_tx.filename);
		pthread_create(&(pthread_master_tx), NULL, i2c_master_thread,
					   &data_pthread_master_tx);
		printf("write slave address [0x%x]\n", data_pthread_master_tx.slave_addr);
	}

	if (slave_flag) {
		printf("slave : [%s]\n", data_pthread_slave_rx.filename);
		pthread_create(&(pthread_slave_rx), NULL, i2c_slave_thread,
					   &data_pthread_slave_rx);
	}

	if (master_flag) {
		pthread_join(pthread_master_tx, &master_ret);
		if (master_ret == PTHREAD_CANCELED)
			printf("The thread was canceled - ");
		if(debug) printf("Returned value %d - ", (int)master_ret);
	}
	
	if (slave_flag) {
		pthread_join(pthread_slave_rx, &slave_ret);
		 if (slave_ret == PTHREAD_CANCELED)
			printf("The thread was canceled - ");

		if(debug) printf("Returned value %d - ", (int)slave_ret);
	}

	if (master_ret || slave_ret) printf(" ================= Fail =================\n");
	else printf(" ================= Pass =================\n");

	return 0;
}
