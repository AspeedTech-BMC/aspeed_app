/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */


/*
Please get the JEDEC file format before you read the code
*/

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
#include "ast-jtag.h"

#define ERROR_OK                        (0)
#define ERROR_NO_CONFIG_FILE            (-2)
#define ERROR_BUF_TOO_SMALL             (-3)
#define ERROR_FAIL                      (-4)
#define ERROR_WAIT                      (-5)
#define ERROR_TIMEOUT_REACHED           (-6)

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };
int loglevel = LOG_WARN;

extern int mode;

static void
usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
			"Usage: %s [options]\n\n"
			"Options:\n"
			" -h | --help                   Print this message\n"
			" -d | --debug                  Set log level, default = 3\n"
			" -n | --node                   jtag device node\n"
			" -f | --frequency              frequency\n"
			" -p | --play                   play SVF file\n"
			" -s | --software               software mode\n"
			"",
			argv[0]);
}

static const char short_options [] = "hsd:n:f:p:";



static const struct option
	long_options [] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		required_argument,	NULL,	'd' },
	{ "node",		required_argument,	NULL,	'n' },
	{ "fequency",	required_argument,	NULL,	'f' },
	{ "play",		required_argument,	NULL,	'p' },
	{ "software",   no_argument,		NULL,	's' },
	{ 0, 0, 0, 0 }
};

/*********************************************************************************/

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


/*************************************************************************************/
int main(int argc, char *argv[])
{
	int i, ret;
	char option;
	char svf_name[100] = "";
	char dev_name[100] = "";
	int svf = 0;
	unsigned int freq = 0;
	unsigned int jtag_freq = 0;

	unsigned int dev_id;

	while ((option = getopt_long(argc, argv, short_options, long_options, NULL)) != (char) -1) {
		switch (option) {
		case 'h':
			usage(stdout, argc, argv);
			exit(EXIT_SUCCESS);
			break;
		case 'd':
			loglevel = atol(optarg);
			printf("loglevel %d\n", loglevel);
			break;
		case 'n':
			strcpy(dev_name, optarg);
			if (!strcmp(dev_name, "")) {
				printf("No dev file name!\n");
				usage(stdout, argc, argv);
				exit(EXIT_FAILURE);
			}
			break;
		case 'f':
			freq = atol(optarg);
			printf("frequency %d\n", freq);
			break;
		case 'p':
			svf = 1;
			strcpy(svf_name, optarg);
			if (!strcmp(svf_name, "")) {
				printf("No out file name!\n");
				usage(stdout, argc, argv);
				exit(EXIT_FAILURE);
			}
			break;
		case 's':
			mode = 1;
			break;
		default:
			usage(stdout, argc, argv);
			exit(EXIT_FAILURE);
		}
	}
	if (!svf){
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}

	if (ast_jtag_open(dev_name))
		exit(1);

	//show current ast jtag configuration
	jtag_freq = ast_get_jtag_freq();

	if (jtag_freq == 0) {
		perror("Jtag freq error !! \n");
		goto out;
	}

	if (freq) {
		ast_set_jtag_freq(freq);
		printf("JTAG Set Freq %d\n", freq);
	} else {
		printf("JTAG Freq %d\n", jtag_freq);
	}

	if (svf) {
		printf("Playing %s \n", svf_name);
		ret = handle_svf_command(svf_name);
		if (ret == ERROR_OK) {
			printf("Success!\n");
		} else {
			printf("Error: %d\n", ret);
		}
	}

out:
	ast_jtag_close();

	return 0;
}
