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

#include <semaphore.h>
#include <time.h>

/*****************************************************************************/
#define I2C_S_BUF_SIZE  256
#define DEF_I2C_ADDR    0x04

#define DEF_THREAD_CH   12
#define DEF_PAIR0_DEV   0
#define DEF_PAIR1_DEV   1
#define DEF_PAIR0_ADDR  0x02
#define DEF_PAIR1_ADDR  0x03
#define DEF_PAIR2_ADDR  0x04
#define TIMEOUT 10


int debug = 0;

struct thread_data {
	int fd;
	int continuous_flag;
	int random_flag;
	int loop_cnt;
	int xfer_size;	
	unsigned char *xfer_buf;
	unsigned char *pattern;
	int address;
	int bus;
	sem_t *flag;
	struct i2c_rdwr_ioctl_data rdwr_msgs;
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

static const char short_options [] = "hmscprdie:z:l:b:a:u:";

static const struct option
	long_options [] = {
	{ "help",       no_argument,            NULL,   'h' },
	{ "master",     no_argument,            NULL,   'm' },
	{ "slave",      no_argument,            NULL,   's' },
	{ "continuous", no_argument,            NULL,   'c' },
	{ "bus",        required_argument,      NULL,   'b' },
	{ "tx_size",    required_argument,      NULL,   'z' },
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

static void print_autotest(int bus, char *message, char *err_message)
{
	printf("[AUTOTEST] %d %s :%s\n", bus, message, err_message);
}

static int compare_pattern(unsigned char *pattern0, unsigned char *pattern1,
						   int size)
{
	int i;
	for (i = 1; i < size + 1; i++) {
		if (pattern0[i + 1] != pattern1[i]) {
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

static int i2c_master_tx(int fd, struct i2c_rdwr_ioctl_data *rdwr_msgs,
						 unsigned char *buf, int size, int target_addr)
{
	int ret;
	int retry = 10;
	int i = 0;
	rdwr_msgs->nmsgs = 1;
	(rdwr_msgs->msgs[0]).len   = size;
	(rdwr_msgs->msgs[0]).addr  = target_addr;
	(rdwr_msgs->msgs[0]).flags = 0;
	(rdwr_msgs->msgs[0]).buf   = buf;
	ioctl(fd, I2C_SLAVE, target_addr);
	usleep(1000);
	for (i = 0; i < retry; i++) {
		ret = ioctl(fd, I2C_RDWR, (unsigned long) rdwr_msgs);
		if (ret >= 0)
			break;
		usleep(1000);
	}
	if (ret < 0) {
		printf("err[%d]\n", ret);
	}

	//ret = write(fd, buf, size);
	return ret;
}

static int i2c_slave_rx(int fd, struct i2c_rdwr_ioctl_data *rdwr_msgs)
{
	int ret;
	ret = ioctl(fd, I2C_SLAVE_RDWR, (unsigned long) rdwr_msgs);
	return ret;
}

static void i2c_slave_rx_prepare(int fd, struct i2c_rdwr_ioctl_data *rdwr_msgs,
								 unsigned char *buf, int size, int slave_addr)
{
	(rdwr_msgs->msgs[0]).len   = size;
	(rdwr_msgs->msgs[0]).addr  = slave_addr;
	(rdwr_msgs->msgs[0]).flags = 0;
	(rdwr_msgs->msgs[0]).buf   = buf;
}

void *i2c_master_thread(void *arg)
{
	struct thread_data *master_data = (struct thread_data *) arg;
	int loop_cnt        = master_data->loop_cnt;
	int continuous_flag = master_data->continuous_flag;
	int random_flag     = master_data->random_flag;
	int i = 0;
	int ret;
	int success_count = 0;

	while (1) {
		if (random_flag) {
			random_pattern_prepare(master_data->pattern,
								   master_data->buf_size);
		}
		printf("[i2c-%d][%d]TX pattern length = %d\n", master_data->bus , i,
			   master_data->buf_size);
		if (debug) {
			print_buf(master_data->pattern, master_data->buf_size);
		}

		ret = i2c_master_tx(master_data->fd, &master_data->rdwr_msgs,
							master_data->pattern, master_data->buf_size,
							master_data->address);
		if (ret >= 0) {
			success_count ++;
		} else {
			print_autotest(master_data->bus, "failure master", strerror(errno));
			exit(1);
		}


		i++;
		if (!continuous_flag) {
			if (i >= loop_cnt) {
				if (success_count == loop_cnt)
					print_autotest(master_data->bus, "success master", "");
				else
					print_autotest(master_data->bus, "failure master", "");
				break;
			}
		}
	}

	close(master_data->fd);
}

void *i2c_slave_thread(void *arg)
{
	struct thread_data *slave_data = (struct thread_data *) arg;
	int loop_cnt        = slave_data->loop_cnt;
	int continuous_flag = slave_data->continuous_flag;
	int random_flag     = slave_data->random_flag;
	int current_time;
	int i = 0;
	int recv_len;
	int success_count = 0;

	while (1) {
		i2c_slave_rx_prepare(slave_data->fd, &slave_data->rdwr_msgs,
							 slave_data->buf, slave_data->buf_size,
							 slave_data->address);
		current_time = time(NULL);
		while (1) {
			int ret = i2c_slave_rx(slave_data->fd, &slave_data->rdwr_msgs);
			if (ret >= 0) {
				recv_len = (&slave_data->rdwr_msgs.msgs[0])->len;

				printf("[i2c-%d][%d]RX pattern length = %d - 1\n",
					   slave_data->bus, i, recv_len);
				if (debug) {
					printf("address[%d]\n", slave_data->buf[0]);
					print_buf(slave_data->buf + 1, recv_len - 1);
				}
				if (!random_flag) {
					if (compare_pattern(slave_data->buf + 1,
										slave_data->pattern,
										recv_len - 1)) {
						success_count++;
					} else {
						print_autotest(slave_data->bus, "failure slave", "Compare failure");
						exit(1);
					}
				}
				break;
			}

			if (time(NULL) - current_time >= TIMEOUT) {
				print_autotest(slave_data->bus, "failure slave", "Recv Timeout");
				exit(1);
			}
		}
		i++;
		if (!continuous_flag) {
			if (i >= loop_cnt) {
				if (success_count == loop_cnt)
					print_autotest(slave_data->bus, "success slave", "");
				else
					print_autotest(slave_data->bus, "failure slave", "");
				break;
			}
		}
	}
	close(slave_data->fd);
}

void *i2c_echo0_thread(void *arg)
{
	struct thread_data *echo0_data = (struct thread_data *) arg;
	int loop_cnt        = echo0_data->loop_cnt;
	int continuous_flag = echo0_data->continuous_flag;
	int random_flag     = echo0_data->random_flag;
	int target_address  = echo0_data->address;
	int slave_address   = (echo0_data->bus * 2) + 1;
	int ret;
	int recv_len;
	int current_time;
	int success_count = 0;
	int i = 0;

	while (1) {
		if (random_flag)
			random_pattern_prepare(echo0_data->pattern,
								   echo0_data->buf_size);
		echo0_data->pattern[0] = slave_address;
		printf("[i2c-%d][%d]TX pattern length = %d\n", echo0_data->bus , i,
			   echo0_data->buf_size);
		if (debug) {
			print_buf(echo0_data->pattern, echo0_data->buf_size);
		}

		ret = i2c_master_tx(echo0_data->fd, &echo0_data->rdwr_msgs,
							echo0_data->pattern, echo0_data->buf_size,
							target_address);

		i2c_slave_rx_prepare(echo0_data->fd, &echo0_data->rdwr_msgs,
							 echo0_data->buf, echo0_data->buf_size,
							 slave_address);
		current_time = time(NULL);
		while (1) {
			ret = i2c_slave_rx(echo0_data->fd, &echo0_data->rdwr_msgs);
			if (ret >= 0) {
				recv_len = (&echo0_data->rdwr_msgs.msgs[0])->len;
				printf("[i2c-%d][%d]RX pattern length = %d - 1\n",
					   echo0_data->bus, i, recv_len);
				if (debug) {
					print_buf(echo0_data->buf + 1, recv_len - 1);
				}
				if (compare_pattern(echo0_data->pattern + 1 ,
									echo0_data->buf + 2,
									recv_len - 2)) {
					printf("       [%d]Compare success\n", i);
					success_count++;
				} else {
					printf("       [%d]Compare error\n", i);
					exit(EXIT_FAILURE);
				}
				break;
			}
			if (time(NULL) - current_time >= TIMEOUT) {
				print_autotest(echo0_data->bus, "failure echo0", "Recv Timeout");
				exit(1);
			}
		}

		i++;
		if (!continuous_flag) {
			if (i >= loop_cnt) {
				if (success_count == loop_cnt)
					print_autotest(echo0_data->bus, "success echo0", "");
				else
					print_autotest(echo0_data->bus, "failure echo0", "");
				break;
			}
		}
	}
	close(echo0_data->fd);
}

static int i2c_init(int bus, int nmsgs, struct i2c_rdwr_ioctl_data *rdwr_msgs)
{
	int fd;
	char dev_node[20];
	sprintf(dev_node, "/dev/i2c-%d", bus);
	fd = open(dev_node, O_RDWR);
	if (fd < 0) {
		printf("open %s failed \n", dev_node);
		exit(EXIT_FAILURE);
	}
	if (debug) {
		printf("dev_node open [%s]\n", dev_node);
	}

	rdwr_msgs->nmsgs = nmsgs;
	rdwr_msgs->msgs = (struct i2c_msg *)
					  malloc(rdwr_msgs->nmsgs * sizeof(struct i2c_msg));
	if (!rdwr_msgs->msgs) {
		perror("Memory alloc error");
		close(fd);
		exit(EXIT_FAILURE);
	}
	return fd;
}

int main(int argc, char *argv[])
{
	char option;

	pthread_t pthread_pair0;
	pthread_t pthread_pair1;
	struct thread_data data_pthread_pair0;
	struct thread_data data_pthread_pair1;
	sem_t flag;

	int disable_flag      = 0;
	int master_flag       = 0;
	int slave_flag        = 0;
	int continuous_flag   = 0;
	int random_flag       = 0;
	int pair_flag         = 0;
	int echo_mode         = -1;
	int multi_master_mode = -2;
	int loop = 1;
	int bus  = 0;
	int slave_addr = DEF_PAIR0_ADDR;
	int xfer_size  = I2C_S_BUF_SIZE - 1;
	unsigned char pattern_buf[I2C_S_BUF_SIZE];
	unsigned char recv_buf[I2C_S_BUF_SIZE + 1];

	while ((option = getopt_long(argc, argv, short_options, long_options, NULL)
		   ) != (char) - 1) {
		switch (option) {
		case 'h':
			usage(stdout, argc, argv);
			exit(EXIT_SUCCESS);
			break;
		case 'm':
			master_flag = 1;
			break;
		case 's':
			slave_flag = 1;
			break;
		case 'c':
			continuous_flag = 1;
			break;
		case 'l':
			loop = strtoul(optarg, 0, 0);
			break;
		case 'z':
			xfer_size = strtoul(optarg, 0, 0);
			break;
		case 'b':
			bus = strtoul(optarg, 0, 0);
			break;
		case 'p':
			pair_flag = 1;
			break;
		case 'e':
			echo_mode = strtoul(optarg, 0, 0);
			break;
		case 'r':
			random_flag = 1;
			break;
		case 'a':
			slave_addr = strtoul(optarg, 0, 0);
			break;
		case 'u':
			multi_master_mode = strtoul(optarg, 0, 0);
			break;
		case 'd':
			debug = 1;
			break;
		case 'i':
			disable_flag = 1;
			break;
		default:
			usage(stdout, argc, argv);
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!master_flag && !slave_flag && !pair_flag && (echo_mode == -1) &&
		(multi_master_mode == -2) && !disable_flag) {
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}

	if (master_flag && slave_flag) {
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}
	if (multi_master_mode != -2) {
		if (master_flag || slave_flag || (echo_mode != -1) || pair_flag) {
			usage(stdout, argc, argv);
			exit(EXIT_FAILURE);
		}
	}
	if ((echo_mode != -1) || pair_flag) {
		if (master_flag || slave_flag) {
			usage(stdout, argc, argv);
			exit(EXIT_FAILURE);
		}
	}
	if (disable_flag) {
		int flush_count = 0;
		struct i2c_rdwr_ioctl_data rdwr_msgs;
		int fd = i2c_init(bus, 1, &rdwr_msgs);

		while (1) {
			i2c_slave_rx_prepare(fd, &rdwr_msgs, recv_buf, xfer_size,
								 slave_addr);
			if (i2c_slave_rx(fd, &rdwr_msgs) < 0)
				break;
			else
				flush_count++;
		}

		printf("[i2c-%d]flush %d buffer and disable slave mode\n",
			   bus, flush_count);
		exit(EXIT_SUCCESS);
	}

	if (random_flag)
		random_pattern_prepare(pattern_buf, xfer_size);
	else
		test_pattern_prepare(pattern_buf, xfer_size);

	if (master_flag || slave_flag) {
		data_pthread_pair0.fd              = i2c_init(bus, 1,
											 &data_pthread_pair0.rdwr_msgs);
		data_pthread_pair0.continuous_flag = continuous_flag;
		data_pthread_pair0.random_flag     = random_flag;
		data_pthread_pair0.loop_cnt        = loop;
		data_pthread_pair0.buf             = recv_buf;
		data_pthread_pair0.buf_size        = xfer_size;
		data_pthread_pair0.pattern         = pattern_buf;
		data_pthread_pair0.flag            = &flag;
		data_pthread_pair0.address         = slave_addr;
		data_pthread_pair0.bus             = bus;
		if (master_flag) {
			printf("master mode\n");
			pthread_create(&(pthread_pair0), NULL, i2c_master_thread,
						   &data_pthread_pair0);
			pthread_join(pthread_pair0, NULL);
		} else if (slave_flag) {
			printf("slave mode\n");
			pthread_create(&(pthread_pair0), NULL, i2c_slave_thread,
						   &data_pthread_pair0);
			pthread_join(pthread_pair0, NULL);
		}
	} else if (pair_flag) {
		printf("pair mode\n");
		data_pthread_pair0.fd              = i2c_init(DEF_PAIR0_DEV, 1,
											 &data_pthread_pair0.rdwr_msgs);
		data_pthread_pair0.continuous_flag = continuous_flag;
		data_pthread_pair0.random_flag     = random_flag;
		data_pthread_pair0.loop_cnt        = loop;
		data_pthread_pair0.buf             = recv_buf;
		data_pthread_pair0.buf_size        = xfer_size;
		data_pthread_pair0.pattern         = pattern_buf;
		data_pthread_pair0.flag            = &flag;
		data_pthread_pair0.address         = slave_addr;
		data_pthread_pair0.bus             = bus;

		data_pthread_pair1.fd              = i2c_init(DEF_PAIR1_DEV, 1,
											 &data_pthread_pair1.rdwr_msgs);
		data_pthread_pair1.continuous_flag = continuous_flag;
		data_pthread_pair1.random_flag     = random_flag;
		data_pthread_pair1.loop_cnt        = loop;
		data_pthread_pair1.buf             = recv_buf;
		data_pthread_pair1.buf_size        = xfer_size;
		data_pthread_pair1.pattern         = pattern_buf;
		data_pthread_pair1.flag            = &flag;
		data_pthread_pair1.address         = slave_addr;
		data_pthread_pair1.bus             = bus + 1;

			pthread_create(&(pthread_pair1), NULL, i2c_slave_thread,
						   &data_pthread_pair1);
			pthread_create(&(pthread_pair0), NULL, i2c_master_thread,
						   &data_pthread_pair0);
			pthread_join(pthread_pair1, NULL);

	}
	return 0;
}
