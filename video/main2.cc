#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>

#include "ikvm_video.hpp"
#include "regs-video.h"

static const char opt_short [] = "c:shq:p:a:m:f:";
static const struct option opt_long [] = {
	{ "capture",	required_argument,	NULL,	'c' },
	{ "stream",	no_argument,		NULL,	's' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "quality",	required_argument,	NULL,	'q' },
	{ "subsample",	required_argument,	NULL,	'p' },
	{ "aspeed_fmt",	required_argument,	NULL,	'a' },
	{ "HQmode",	required_argument,	NULL,	'm' },
	{ "fps",	required_argument,	NULL,	'f' },
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
		"\n",
		argv[0]
		);
}

static void save2file(char *data, size_t size, char *fileName)
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

static void transfer(ikvm::Video &v, unsigned char *socketbuffer)
{
	uint32_t count;
	uint32_t send_len;
	TRANSFER_HEADER Transfer_Header;
	bool firstframe;

	if (width == v.getWidth() && height == v.getHeight()) {
		firstframe = false;
	} else {
		firstframe = true;
		width = v.getWidth();
		height = v.getHeight();
	}

	Transfer_Header.Data_Length = v.getFrameSize();
	// Jammy: kvm sample no use?
	Transfer_Header.Blocks_Changed = 1;

	Transfer_Header.Frist_frame = firstframe;
	Transfer_Header.Compress_type = !v.getFormat();

//	if (VideoEngineInfo->INFData.DownScalingEnable == 1) {
//		Transfer_Header.User_Width = VideoEngineInfo->DestinationModeInfo.X;
//		Transfer_Header.User_Height = VideoEngineInfo->DestinationModeInfo.Y;
//	} else {
		Transfer_Header.User_Width = v.getWidth();
		Transfer_Header.User_Height = v.getHeight();
//	}
	Transfer_Header.RC4_Enable = 0;
	Transfer_Header.Y_Table = v.getQuality();
	Transfer_Header.Mode_420 = v.getSubsampling();
	Transfer_Header.Direct_Mode = 0;
	//Add for fixing the auto mode and RC4 bug
	Transfer_Header.Advance_Table = 0;
	Transfer_Header.Differential_Enable = 0;
	Transfer_Header.VQ_Mode = 0;

	//send host header
	send (connfd, &Transfer_Header, 29, MSG_WAITALL);
	//recv client header
	do {
		count = recv(connfd, buffer, 29, MSG_WAITALL);
	} while (count != 29);

	//send frame
	if(Transfer_Header.Compress_type) {
		do {
			send_len = send(connfd, (unsigned char *)v.getData(), Transfer_Header.Data_Length, MSG_WAITALL);
		} while (send_len != Transfer_Header.Data_Length);
	} else {
		do {
			send_len = send(connfd, (unsigned char *)v.getData(), Transfer_Header.Data_Length * 4, MSG_WAITALL);
		} while (send_len != Transfer_Header.Data_Length * 4);
	}

	do {
		count = recv (connfd, socketbuffer, 29, MSG_WAITALL);
	} while (count != 29);
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
	ikvm::Video video("/dev/video0");
	unsigned char *socketbuffer;

	while ((opt = getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char) - 1) {
		switch (opt) {
			case 'm':
				hq_enable = strtoul(optarg, 0, 10);
				printf("aspeed HQ mode is %s\n", hq_enable ? "on" : "off");
				video.setHQMode(hq_enable);
				break;
			case 'a':
				format = strtoul(optarg, 0, 10);
				printf("aspeed fmt is %s\n", format_str[format]);
				video.setFormat(format);
				break;
			case 'q':
				quality = strtoul(optarg, 0, 10);
				if (quality > 11) {
					printf("quality(%d) invalid (0~11). Use default 4.\n",
					       quality);
					quality = 4;
				}
				printf("quality is %d\n", quality);
				video.SetQuality(quality);
				break;
			case 'p':
				is420 = strncmp(optarg, "444", 3);
				printf("subsampling is %s\n", is420 ? "420" : "444");
				video.setSubsampling(is420);
				break;
			case 'f':
				fps = strtoul(optarg, 0, 10);
				if (fps > 60) {
					fps = 60;
				}
				printf("fps is %d\n", fps);
				video.setFrameRate(fps);
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
			default:
				print_usage(stdout, argc, argv);
				return -1;
		}
	}

	if (is_streaming) {
		if (net_setup() != 0)
			return -1;

		socketbuffer = (unsigned char*)malloc ((size_t) 1024);
		while(1) {
			video.start();
			if (video.getFrame() == 0) {
				if ((video.getFrameNumber() != frameNumber + 1) && video.getFrameNumber())
					printf("%s: discontinuous frame number (%d -> %d)\n",
					       __func__,  frameNumber, video.getFrameNumber());

				frameNumber = video.getFrameNumber();
				transfer(video, socketbuffer);
			}

			if (video.needsResize())
			{
				video.resize();
				frameNumber = 0;
			}
		}
		video.stop();
		free(socketbuffer);
		free(buffer);
	} else {
		uint8_t count = 0;

		while (times--) {
			sprintf(fileName, "capture%d.jpg", ++count);

			video.start();
			video.getFrame();
			if ((data = video.getData()) != nullptr) {
				save2file(data, video.getFrameSize(), fileName);
			}
		}
		video.stop();
	}

	return 0;
}
