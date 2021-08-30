#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/socket.h>

#include "ikvm_video.hpp"

#define PORT 1234

#define    BYTE                     unsigned char
#define    ULONG                    unsigned long
#define    USHORT                   unsigned short
#define    UCHAR                    unsigned char

typedef struct _TRANSFER_HEADER {
	ULONG     Data_Length;
	ULONG     Blocks_Changed;
	USHORT    User_Width;
	USHORT    User_Height;
	BYTE	  Frist_frame;		// 1: first frame 
	BYTE	  Compress_type;	//0:aspeed mode, 1:jpeg mode
	BYTE	  Trigger_mode;	//0:capture, 1: compression, 2: buffer
	BYTE	  Data_format;	//0:DCT, 1:DCTwVQ2 color, 2:DCTwVQ4 color
	BYTE      RC4_Enable;
	BYTE      RC4_Reset;	//no use
	BYTE      Y_Table;
	BYTE      UV_Table;
	BYTE      Mode_420;
	BYTE      Direct_Mode;
	BYTE      VQ_Mode;
	BYTE      Disable_VGA;
	BYTE      Differential_Enable;
	BYTE      Auto_Mode;
	BYTE      VGA_Status;
	BYTE      RC4State;
	BYTE      Advance_Table;
} TRANSFER_HEADER, *PTRANSFER_HEADER;

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

int connfd;
unsigned long *buffer, Frame = 0;
size_t width, height;

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

int net_setup(void)
{
	struct sockaddr_in addr_svr;
	struct sockaddr_in addr_cln;
	socklen_t sLen = sizeof(addr_cln);

	int sockfd;
	int sndbuf = 0x100000;

	buffer = (unsigned long *)malloc (1024);

	bzero(&addr_svr, sizeof(addr_svr));
	addr_svr.sin_family= AF_INET;
	addr_svr.sin_port= htons(PORT);
	addr_svr.sin_addr.s_addr = INADDR_ANY;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if( sockfd == -1){
		perror("call socket \n");
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, 0x100000);

	//bind
	if (bind(sockfd, (struct sockaddr *)&addr_svr, sizeof(addr_svr)) == -1) {
		perror("call bind \n");
		return -1;
	}

	//listen
	if (listen(sockfd, 10) == -1) {
		perror("call listen \n");
		return -1;
	}

	printf("Accepting connections ...\n");

	connfd = accept(sockfd, (struct sockaddr *)&addr_cln, &sLen);
	if (connfd == -1) {
		perror("call accept\n");
		return -1;
	}

	printf("Client connect ...\n");
	return 0;
}

void save2file(char *data, size_t size, char *fileName)
{
	int fd = open(fileName, O_CREAT | O_WRONLY);

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

void transfer(ikvm::Video &v)
{
       	unsigned char *socketbuffer = (unsigned char *)malloc (1024);
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

int main(int argc, char **argv) {

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

		while(1) {
			video.start();
			video.getFrame();
			if (video.getFrameNumber() != frameNumber + 1)
				printf("%s: discontinuous frame number (%d -> %d)\n",
				       __func__,  frameNumber, video.getFrameNumber());
			frameNumber = video.getFrameNumber();

			transfer(video);

			if (video.needsResize())
			{
				video.resize();
			}
		}
		video.stop();
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
