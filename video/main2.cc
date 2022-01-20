// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2021 Aspeed Technology Inc.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/mman.h>

#include "ikvm_video.hpp"
#include "regs-video.h"
#include "bmp.h"

#define JPEG_DATA_OFFSET	0x50

static const char opt_short [] = "c:shq:p:a:m:f:t:";
static const struct option opt_long [] = {
	{ "capture",	required_argument,	NULL,	'c' },
	{ "stream",	no_argument,		NULL,	's' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "quality",	required_argument,	NULL,	'q' },
	{ "subsample",	required_argument,	NULL,	'p' },
	{ "aspeed_fmt",	required_argument,	NULL,	'a' },
	{ "HQmode",	required_argument,	NULL,	'm' },
	{ "fps",	required_argument,	NULL,	'f' },
	{ "test",	required_argument,	NULL,	't' },
	{ 0, 0, 0, 0 }
};

static size_t width, height;

extern int connfd;
extern unsigned long *buffer;
extern int net_setup(void);

static void print_usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
		"Usage:\n"
		"  %s [OPTION]\n"
		"\n"
		"Options:\n"
		" -h | --help       Print this message\n"
		" -c | --capture    capture few frames\n"
		" -s | --stream     streaming to network\n"
		" -q | --quality    assign 0~11 jpeg quality\n"
		" -p | --subsample  420/444 jpeg subsampling\n"
		" -a | --aspeed_fmt 0 for standard jpeg; 1 for aspeed jpeg mode; 2 for partial jpeg\n"
		" -m | --HQmode     enable HQ mode\n"
		" -f | --fps        0 for no control; o/w new-fps = org-fps*fps/60 \n"
		" -t | --test       0 stop/run test;\n"
		"\n",
		argv[0]
		);
}

static void save2file(char *data, size_t size, const char *fileName)
{
	int fd = open(fileName, O_CREAT | O_WRONLY, 0644);

	if (fd < 0) {
		printf("%s file open failed\n", fileName);
		return;
	}

	if (write(fd, data, size) < 0) {
		printf("%s file write failed\n", fileName);
	}
	printf("Save to %s, size %d\n", fileName, size);
	close(fd);
}

static void loadFile(char *data, size_t size, const char *fileName)
{
	int fd = open(fileName, O_RDONLY);

	if (fd < 0) {
		printf("%s file open failed\n", fileName);
		return;
	}

	if (read(fd, data, size) < 0) {
		printf("%s file write failed\n", fileName);
	}
	close(fd);
}

static void transfer(ikvm::Video *v, unsigned char *socketbuffer)
{
	uint32_t count;
	uint32_t send_len;
	TRANSFER_HEADER Transfer_Header;
	bool firstframe;
	char* data = v->getData();

	if (data == nullptr)
		return;

	if (width == v->getWidth() && height == v->getHeight()) {
		firstframe = false;
	} else {
		firstframe = true;
		width = v->getWidth();
		height = v->getHeight();
	}

	Transfer_Header.Data_Length = v->getFrameSize();
	// Jammy: kvm sample no use?
	Transfer_Header.Blocks_Changed = 1;

	Transfer_Header.Frist_frame = firstframe;
	Transfer_Header.Compress_type = !v->getFormat();

//	if (VideoEngineInfo->INFData.DownScalingEnable == 1) {
//		Transfer_Header.User_Width = VideoEngineInfo->DestinationModeInfo.X;
//		Transfer_Header.User_Height = VideoEngineInfo->DestinationModeInfo.Y;
//	} else {
		Transfer_Header.User_Width = v->getWidth();
		Transfer_Header.User_Height = v->getHeight();
//	}
	Transfer_Header.RC4_Enable = 0;
	Transfer_Header.Y_Table = v->getQuality();
	Transfer_Header.Mode_420 = v->getSubsampling();
	Transfer_Header.Direct_Mode = 0;
	//Add for fixing the auto mode and RC4 bug
	Transfer_Header.Advance_Table = v->getHQuality() - 1;
	Transfer_Header.Differential_Enable = 0;
	Transfer_Header.VQ_Mode = 0;

	//send host header
	send (connfd, &Transfer_Header, 29, MSG_WAITALL);
	//recv client header
	do {
		count = recv(connfd, buffer, 29, MSG_WAITALL);
	} while (count != 29);

	//send frame
	do {
		send_len = send(connfd, (unsigned char *)data, Transfer_Header.Data_Length, MSG_WAITALL);
	} while (send_len != Transfer_Header.Data_Length);

	do {
		count = recv (connfd, socketbuffer, 29, MSG_WAITALL);
	} while (count != 29);
}

static void test0(int times)
{
	char data[0x200000];
	size_t length;
	ikvm::Video *video;
	int count = 0;

	video = new ikvm::Video("/dev/video0");
	video->start();
	video->getFrame();
	if (video->getData() != nullptr) {
		length = video->getFrameSize();
		memcpy(data, video->getData(), length);
		save2file(data, length, "golden.jpg");
	} else {
		printf("%s failed at grab golden\n", __func__);
		return;
	}
	video->stop();
	delete video;


	do {
		++count;
		video = new ikvm::Video("/dev/video0");
		video->start();
		video->getFrame();
		if (video->getData() != nullptr) {
			if (length != video->getFrameSize()) {
				printf("%s failed at %d, length doesn't match(%d<->%d)\n",
				       __func__, count, length, video->getFrameSize());
				return;
			}
			// skip header whose timestamp would change
			if (memcmp(data + JPEG_DATA_OFFSET, video->getData() + JPEG_DATA_OFFSET, length - JPEG_DATA_OFFSET) != 0) {
				printf("%s failed at %d, data match\n", __func__, count);
				save2file(video->getData(), length, "fail.jpg");
				return;
			}
		} else {
			printf("%s failed capture at %d\n", __func__, count);
		}
		video->stop();
		delete video;
	} while (--times);
}

static void test1(ikvm::Video *v)
{
	int rc = 0;
	int w, h;
	int bmp_w, bmp_h;
	unsigned char *buf = NULL;
	char data[0x200000];
	int count = 1;
	char filename[16];

	printf("In this test, it will load bmp, golden_#.bmp, for test.\n");
	printf("Please switch video driver to input from memory by sysfs.\n");
	printf("Please give the size of the bmp used.\n");
	printf("width  :");
	scanf("%d", &w);
	printf("height :");
	scanf("%d", &h);
	v->setInput(2);
	v->setInputSize(w, h);

	v->start();
	v->getInputBuffer(&buf);
	if (buf == MAP_FAILED)
		return;

	printf("\n-----Test Start-----\n");
	do {
		// prepare test data
		snprintf(filename, 16, "test_%d.bmp", count);
		rc = loadBMP(filename, buf, &bmp_w, &bmp_h);
		if (rc)
			break;

		if (bmp_w != w || bmp_h != h) {
			printf("bmp size(%d * %d) isn't match\n", bmp_w, bmp_h);
			break;
		}

		// prepare golden data
		snprintf(filename, 16, "golden_%d.jpg", count);
		loadFile(data, 0x200000, filename);

		printf("*%3d: ", count);
		// single-step trigger
		v->capture();
		if (v->getFrame() == 0) {
			if (memcmp(data + JPEG_DATA_OFFSET, v->getData() + JPEG_DATA_OFFSET, v->getFrameSize() - JPEG_DATA_OFFSET) != 0) {
				printf("NG, data mismatch\n");
				snprintf(filename, 16, "fail_%d.jpg", count);
				save2file(v->getData(), v->getFrameSize(), filename);
			} else
				printf("OK\n");
		} else {
			rc = 1;
			printf("NG, no new frame available\n");
		}
		count++;
	} while(1);
	v->stop();

	printf("\nTest Result: %s\n", rc ? "Pass" : "Fail");
}

static void test(ikvm::Video *v, int cases)
{
	if (cases == 0) {
		delete v;
		test0(100);
	} else if (cases == 1) {
		test1(v);
	}
}

static const char * const compress_mode_str[] = {"DCT Only",
	"DCT VQ mix 2-color", "DCT VQ mix 4-color"};
static const char * const format_str[] = {"Standard JPEG",
	"Aspeed JPEG", "Partial JPEG"};

int main_v2(int argc, char **argv) {

	char opt;
	uint32_t times = 0, quality = 0, fps = 0;
	bool is420 = false;
	int format = false;
	bool hq_enable = false;
	char *data;
	char fileName[16];
	bool is_streaming = false;
	size_t frameNumber = 0;
	ikvm::Video *video;
	unsigned char *socketbuffer;

	video = new ikvm::Video("/dev/video0");
	while ((opt = getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char) - 1) {
		switch (opt) {
			case 'm':
				hq_enable = strtoul(optarg, 0, 10);
				printf("aspeed HQ mode is %s\n", hq_enable ? "on" : "off");
				video->setHQMode(hq_enable);
				break;
			case 'a':
				format = strtoul(optarg, 0, 10);
				printf("aspeed fmt is %s\n", format_str[format]);
				video->setFormat(format);
				break;
			case 'q':
				quality = strtoul(optarg, 0, 10);
				if (quality > 11) {
					printf("quality(%d) invalid (0~11). Use default 4.\n",
					       quality);
					quality = 4;
				}
				printf("quality is %d\n", quality);
				video->setQuality(quality);
				break;
			case 'p':
				is420 = strncmp(optarg, "444", 3);
				printf("subsampling is %s\n", is420 ? "420" : "444");
				video->setSubsampling(is420);
				break;
			case 'f':
				fps = strtoul(optarg, 0, 10);
				if (fps > 60) {
					fps = 60;
				}
				printf("fps is %d\n", fps);
				video->setFrameRate(fps);
				break;
			case 's':
				is_streaming = true;
				break;
			case 'c':
				times = strtoul(optarg, 0, 10);
				is_streaming = false;
				break;
			case 'h':
				print_usage(stdout, argc, argv);
				return 0;
			case 't':
				test(video, strtoul(optarg, 0, 10));
				return 0;
			default:
				print_usage(stdout, argc, argv);
				return -1;
		}
	}

	if (is_streaming) {
		if (net_setup() != 0)
			return -1;

		socketbuffer = (unsigned char*)malloc ((size_t) 1024);
		video->start();
		while(1) {
			if (video->getFrame() == 0) {
				if ((video->getFrameNumber() != frameNumber + 1) && video->getFrameNumber())
					printf("%s: discontinuous frame number (%d -> %d)\n",
					       __func__,  frameNumber, video->getFrameNumber());

				frameNumber = video->getFrameNumber();
				transfer(video, socketbuffer);
			} else
				pr_dbg("no new frame available\n");

			if (video->needsResize())
			{
				video->resize();
				frameNumber = 0;
			}
		}
		video->stop();
		free(socketbuffer);
		free(buffer);
	} else {
		uint8_t count = 0;

		video->start();
		while (times--) {
			sprintf(fileName, "capture%d.jpg", ++count);

			video->getFrame();
			if ((data = video->getData()) != nullptr) {
				save2file(data, video->getFrameSize(), fileName);
			}
		}
		video->stop();
	}
	delete video;

	return 0;
}
