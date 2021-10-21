/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <time.h>

#include "regs-video.h"

#include "video.h"

//#define NON_AUTO
//#define CRT
//#define CONFIG_AST_VIDEO_DEBUG

#ifdef CONFIG_AST_VIDEO_DEBUG
	#define VIDEO_DBG(fmt, args...) printf("%s(): " fmt, __FUNCTION__, ## args)
#else
	#define VIDEO_DBG(fmt, args...)
#endif

#define JPEG_PERIOD 100


//Transfer to client RC4 Reset State
//char buffer[1024];
unsigned char *socketbuffer;

unsigned long Video_Status = 0;		//VGA mode change 

void *stream_virt_addr;
unsigned char *jpeg_virt_addr;


unsigned long framecount = 0;
unsigned char firstframe = 0;

int fbfd = 0;

//  RC4 keys. Current keys are fedcba98765432210
unsigned char EncodeKeys[256];


extern int video_fd;
extern int connfd;
extern unsigned long *buffer;
extern int net_setup(void);

static void VideoCapture(PVIDEO_ENGINE_INFO VideoEngineInfo)
{
	u32 data;
	TRANSFER_HEADER Transfer_Header;
	u32 send_len;
	struct ast_mode_detection mode_detection;
	struct ast_scaling set_scaling;
	struct ast_video_config video_config;
#ifdef CRT
	struct fb_var_screeninfo vinfo;
#endif

	u8 jpeg_encode = 0;
	char encrypt_key_cmd[512];
	struct ast_auto_mode auto_mode;
#ifdef NON_AUTO
	struct ast_capture_mode capture_mode;
	struct ast_compression_mode compression_mode;
#endif

	set_scaling.enable = VideoEngineInfo->INFData.DownScalingEnable;
	set_scaling.x = VideoEngineInfo->DestinationModeInfo.X;
	set_scaling.y = VideoEngineInfo->DestinationModeInfo.Y;

	sprintf(encrypt_key_cmd,"echo %s > /sys/devices/platform/apb/1e700000.video/compress0_encrypt_key",EncodeKeys);
//	printf("encrypt_key '%s' \n", EncodeKeys);
//	ast_video_set_encryption_key(EncodeKeys);

init:
	if (Video_Status == 1) {
		framecount = 0;
		firstframe = 1;

		ast_video_reset();
#ifdef CRT
		/* Get variable screen information */
		if (ioctl(fbfd, FBIOGET_VSCREENINFO, &vinfo) == -1) {
			printf("Error reading variable information.\n");
			exit(3);
		}
		VideoEngineInfo->SourceModeInfo.X = vinfo.xres;
		VideoEngineInfo->SourceModeInfo.Y = vinfo.yres;		
		printf("fb source x %d, y %d \n", vinfo.xres, vinfo.yres);
		//prepare for crt
		ast_video_set_crt_compression(&vinfo);		
#else
#if 1
		ast_video_vga_mode_detection(&mode_detection);
		printf("mode detect - x : %d, y : %d \n", mode_detection.src_x, mode_detection.src_y);

		VideoEngineInfo->SourceModeInfo.X = mode_detection.src_x;
		VideoEngineInfo->SourceModeInfo.Y = mode_detection.src_y;
#else
		ModeDetection(VideoEngineInfo);
		if(VideoEngineInfo->NoSignal == 0) {
			if (VideoEngineInfo->INFData.Input_Signale == 2) {
				AutoPhase_Adjust (VideoEngineInfo);
			}
			AutoPosition_Adjust (VideoEngineInfo);
		}
#endif
#endif

		if(VideoEngineInfo->FrameHeader.RC4Enable == 1) {
//			printf("%s\n",encrypt_key_cmd);
			system(encrypt_key_cmd);
			system("echo 1 > /sys/devices/platform/apb/1e700000.video/compress0_encrypt_en"); 
//			ast_video_set_encryption(1);
		}
		Video_Status = 0;
	} else {
		framecount++;
//		printf("framecount %d firstframe %d \n", framecount, firstframe);
#if 1
		if(VideoEngineInfo->INFData.JPEG_FILE) {
			if(framecount % JPEG_PERIOD== 0) {
//				printf("trigger jpeg \n");
				//encode jpeg 
				jpeg_encode = 1;
			}
		}
#else
		jpeg_encode = 1;
#endif
		if(jpeg_encode) {
#if 1
			video_config.engine = 0;
			video_config.rc4_enable = 0;
			video_config.compression_mode = VideoEngineInfo->FrameHeader.CompressionMode;
			video_config.AutoMode = 1;
			video_config.compression_format = 1;
			video_config.YUV420_mode = VideoEngineInfo->FrameHeader.Mode420;
			video_config.Visual_Lossless = 0;
			video_config.Y_JPEGTableSelector = 4;	//fix test and try
			ast_video_eng_config(&video_config);

#else
			if(firstframe) {
				video_config.engine = 0;
				video_config.rc4_enable = 0;
				video_config.compression_mode = VideoEngineInfo->FrameHeader.CompressionMode;
				video_config.AutoMode = 1;
				video_config.compression_format = 1;
				video_config.YUV420_mode = VideoEngineInfo->FrameHeader.Mode420;
				video_config.Visual_Lossless = 0;
				video_config.Y_JPEGTableSelector = 4;	//fix test and try
				ast_video_eng_config(&video_config);

				set_scaling.engine = 0;
				ast_video_set_scaling(&set_scaling);
			}
#endif
#ifdef NON_AUTO
			capture_mode.engine_idx = 0;
			capture_mode.differential = 0;
			capture_mode.mode_change = 0;

			compression_mode.mode_change = 0;
#else
			//JPEG ENCODE .....
			auto_mode.engine_idx = 0;
			auto_mode.differential = 0; 
			auto_mode.mode_change = 0;
#endif
			ast_video_auto_mode_trigger(&auto_mode);
			Video_Status = auto_mode.mode_change;
			if(Video_Status) {
				printf("go init \n");
				goto init;					
			}
			Transfer_Header.Data_Length = auto_mode.total_size;

			Transfer_Header.Compress_type = 1;
//			Transfer_Header.Data_Length = ReadMMIOLong(0x1e700278);
//			printf("send JPEG size %d \n",Transfer_Header.Data_Length);
		} else {
			jpeg_encode = 0;
			//encode frame
			//encode frame
#ifdef NON_AUTO
			capture_mode.engine_idx = 0;
#else
			auto_mode.engine_idx = 0;
#endif
			if(firstframe) {
				//need reconfig video for full frame 
				video_config.engine = 0;
				video_config.rc4_enable = VideoEngineInfo->FrameHeader.RC4Enable;
				video_config.compression_mode = VideoEngineInfo->FrameHeader.CompressionMode;
				video_config.AutoMode = 1;
				video_config.compression_format = 0;
				video_config.YUV420_mode = VideoEngineInfo->FrameHeader.Mode420;
				video_config.Visual_Lossless = VideoEngineInfo->FrameHeader.Visual_Lossless;		
				video_config.Y_JPEGTableSelector = VideoEngineInfo->FrameHeader.Y_JPEGTableSelector;
				ast_video_eng_config(&video_config);

				set_scaling.engine = 0;
				ast_video_set_scaling(&set_scaling);
//===============================================================				
//				printf("diff %d , count %d \n", firstframe, framecount);
#ifdef NON_AUTO
				capture_mode.differential = 0;
#else
				auto_mode.differential = 0;
#endif
			} else {
//				printf("diff %d , count %d \n", firstframe, framecount);	
				
#ifdef NON_AUTO
				capture_mode.differential = 1;
#else
				auto_mode.differential = 1;
#endif
			}

#ifdef NON_AUTO
			capture_mode.engine_idx = 0;
			capture_mode.mode_change = 0;
			compression_mode.engine_idx = 0;
			compression_mode.mode_change = 0;
			ast_video_capture_mode_trigger(&capture_mode);
			Video_Status = capture_mode.mode_change;
			if(Video_Status) {
				printf("go init \n");
				goto init;
			}

			ast_video_compression_mode_trigger(&compression_mode);
			auto_mode.total_size = compression_mode.total_size;
			auto_mode.block_count = compression_mode.block_count;
			auto_mode.mode_change = capture_mode.mode_change;
			Video_Status = auto_mode.mode_change;
			if(Video_Status) {
				printf("go init \n");
				goto init;
			}
#else
			auto_mode.mode_change = 0;
			ast_video_auto_mode_trigger(&auto_mode);

			Video_Status = auto_mode.mode_change;
			if(Video_Status) {
				printf("go init \n");
				goto init;
			}

#endif
//			printf("trigger done %d \n", framecount);
			Transfer_Header.Data_Length = auto_mode.total_size;
//			printf("%d \n", Transfer_Header.Data_Length);
			Transfer_Header.Blocks_Changed = auto_mode.block_count;

			Transfer_Header.Frist_frame = firstframe;		  			
			Transfer_Header.Compress_type = 0;

//			Transfer_Header.Data_Length = ReadMMIOLong (COMPRESS_DATA_COUNT_REGISTER);
//			Transfer_Header.Blocks_Changed = (ReadMMIOLong (COMPRESS_BLOCK_COUNT_REGISTER) & 0xFFFF0000) >> 16;
			if (VideoEngineInfo->INFData.DownScalingEnable == 1) {
				Transfer_Header.User_Width = VideoEngineInfo->DestinationModeInfo.X;
				Transfer_Header.User_Height = VideoEngineInfo->DestinationModeInfo.Y;
			} else {
				Transfer_Header.User_Width = VideoEngineInfo->SourceModeInfo.X;
				Transfer_Header.User_Height = VideoEngineInfo->SourceModeInfo.Y;
			}
			Transfer_Header.RC4_Enable = VideoEngineInfo->FrameHeader.RC4Enable;
			Transfer_Header.Y_Table = VideoEngineInfo->FrameHeader.Y_JPEGTableSelector;
			Transfer_Header.Mode_420 = VideoEngineInfo->FrameHeader.Mode420;
			Transfer_Header.Direct_Mode = VideoEngineInfo->FrameHeader.DirectMode;
			//Add for fixing the auto mode and RC4 bug
//			Transfer_Header.Auto_Mode = VideoEngineInfo->INFData.AutoMode;
			Transfer_Header.Advance_Table = VideoEngineInfo->FrameHeader.AdvanceTableSelector;
			Transfer_Header.Differential_Enable = VideoEngineInfo->INFData.DifferentialSetting;
			Transfer_Header.VQ_Mode = VideoEngineInfo->INFData.VQMode;

			if(Transfer_Header.Data_Length == 0) {
				printf("************************************************************* size = 0 \n");
				Video_Status = 1;
				goto init;
			}
//			printf("prepare send size %d \n",Transfer_Header.Data_Length*4);
		}

		//send host header	 
//		printf("send host header \n");
		send (connfd, &Transfer_Header, 29, MSG_WAITALL);
		//recv client header
		do {
		data = recv(connfd, buffer, 29, MSG_WAITALL);
		} while (data != 29);
		//send frame 
//		printf("send frame \n");
		if(Transfer_Header.Compress_type) {
			do {
//				send_len = send(connfd, (unsigned char *)jpeg_virt_addr, Transfer_Header.Data_Length, MSG_WAITALL);
				send_len = send(connfd, (unsigned char *)stream_virt_addr, Transfer_Header.Data_Length, MSG_WAITALL);
			} while (send_len != Transfer_Header.Data_Length);
			jpeg_encode = 0;
			firstframe = 1;	//next will be full frame 
		} else {
			do {
				send_len = send(connfd, (unsigned char *)stream_virt_addr, Transfer_Header.Data_Length * 4, MSG_WAITALL);
			} while (send_len != Transfer_Header.Data_Length * 4);
			firstframe = 0;
		}
//	    printf("Frist_frame = %d,  send fram size %d , change %d, rc4 = %d, diff = %d \n",Transfer_Header.Frist_frame, Transfer_Header.Data_Length, Transfer_Header.Blocks_Changed, VideoEngineInfo->FrameHeader.RC4Enable, VideoEngineInfo->INFData.DifferentialSetting);		
		do {
		data = recv (connfd, socketbuffer, 29, MSG_WAITALL);
		} while (data != 29);
		///Check Client 
//		printf("Check Client \n");
		if ((VideoEngineInfo->FrameHeader.Y_JPEGTableSelector != socketbuffer[18]) || 
				(VideoEngineInfo->FrameHeader.Mode420 != socketbuffer[20]) || 
//				(VideoEngineInfo->INFData.DirectMode != socketbuffer[21]) || //can't change for direct or sync mode 
//				(VideoEngineInfo->INFData.AutoMode != socketbuffer[25]) || // can't change for auto mode 
				(VideoEngineInfo->INFData.VQMode != socketbuffer[22]) || 
				(VideoEngineInfo->INFData.DifferentialSetting != socketbuffer[24])) {

			printf ("Client Set Change \n");
			Video_Status = 1;
			VideoEngineInfo->FrameHeader.Y_JPEGTableSelector = socketbuffer[18];
			VideoEngineInfo->FrameHeader.Mode420 = socketbuffer[20];
//			VideoEngineInfo->INFData.DirectMode = socketbuffer[21];			
			VideoEngineInfo->INFData.VQMode = socketbuffer[22];
			VideoEngineInfo->INFData.DifferentialSetting = socketbuffer[24];
#if 0
			if (VideoEngineInfo->INFData.AutoMode != socketbuffer[25]) {
			printf ("AutoMode Changed\n");
			VideoEngineInfo->INFData.AutoMode = socketbuffer[25];
			Video_Status = 1;
			}
#endif
		}

#if 0
		int vga_enable;

		if (socketbuffer[23] == 1) {	
			vga_enable = 0;
			ast_video_set_vga_display(&vga_enable);
			printf("Disable VGA \n");		
		} else { 
			vga_enable =	1;
			ast_video_set_vga_display(&vga_enable);
			printf("Enable VGA \n");				  
		}
#endif
//		printf("end \n");
	}

}

static int GetINFData(PVIDEO_ENGINE_INFO VideoEngineInfo)
{
	char	string[81], name[80], StringToken[256];
	u32	i;
	FILE	*fp;

	if(!system("grep -r AST-G5 /proc/cpuinfo")) {
		VideoEngineInfo->INFData.AST2500 = 1;
	} else {
		VideoEngineInfo->INFData.AST2500 = 0;
	}
	
	fp = fopen("video.inf", "rb");

	if(fp == NULL) {
		printf("video.inf not find...");
		return 1;
	}
		
	while (fgets (string, 80, fp) != NULL) {
		sscanf(string, "%[^=] = %s", name, StringToken);
		printf("%s ", string);
////////////////////////////////////////////////////////////////////////////////////////////////////
//New Configuration
		if (strcmp (name, "INPUT_SOURCE") == 0) {
			VideoEngineInfo->INFData.Input_Signale = (u8)(atoi(StringToken));
		}
////////////////////////////////////////////////////////////////////////////////////////////////////
		if (strcmp (name, "COMPRESS_MODE") == 0) {
			VideoEngineInfo->FrameHeader.CompressionMode = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "Y_JPEG_TABLESELECTION") == 0) {
		    VideoEngineInfo->FrameHeader.Y_JPEGTableSelector = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_YUVTABLE_MAPPING") == 0) {
		    VideoEngineInfo->FrameHeader.JPEGYUVTableMapping = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_SCALE_FACTOR") == 0) {
		    VideoEngineInfo->FrameHeader.JPEGScaleFactor = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "DOWN_SCALING_ENABLE") == 0) {
		    VideoEngineInfo->INFData.DownScalingEnable = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "DIFFERENTIAL_SETTING") == 0) {
		    VideoEngineInfo->INFData.DifferentialSetting = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "DESTINATION_X") == 0) {
		    VideoEngineInfo->DestinationModeInfo.X = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "DESTINATION_Y") == 0) {
		    VideoEngineInfo->DestinationModeInfo.Y = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "RC4_ENABLE") == 0) {
		    VideoEngineInfo->FrameHeader.RC4Enable = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "RC4_KEYS") == 0) {
		    for (i = 0; i < strlen (StringToken); i++) {
		        EncodeKeys[i] = StringToken[i];
		    }
		}
		if (strcmp (name, "ANALOG_DIFFERENTIAL_THRESHOLD") == 0) {
		    VideoEngineInfo->INFData.AnalogDifferentialThreshold = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "DIGITAL_DIFFERENTIAL_THRESHOLD") == 0) {
		    VideoEngineInfo->INFData.DigitalDifferentialThreshold = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_ADVANCE_TABLESELECTION") == 0) {
		    VideoEngineInfo->FrameHeader.AdvanceTableSelector = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_ADVANCE_SCALE_FACTOR") == 0) {
		    VideoEngineInfo->FrameHeader.AdvanceScaleFactor = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_VISUAL_LOSSLESS") == 0) {
		    VideoEngineInfo->FrameHeader.Visual_Lossless = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "SHARP_MODE_SELECTION") == 0) {
		    VideoEngineInfo->FrameHeader.SharpModeSelection = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "AUTO_MODE") == 0) {
		    VideoEngineInfo->INFData.AutoMode = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "DIRECT_MODE") == 0) {
		    VideoEngineInfo->INFData.DirectMode = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "DELAY_CONTROL") == 0) {
		    VideoEngineInfo->INFData.DelayControl = (USHORT)(atoi(StringToken));
		}
		if (strcmp (name, "MODE_420") == 0) {
		    VideoEngineInfo->FrameHeader.Mode420 = (u8)(atoi(StringToken));
		    if (VideoEngineInfo->FrameHeader.Visual_Lossless == 1) {
		    	VideoEngineInfo->FrameHeader.Mode420 = 0;
		    }
		}
		if (strcmp (name, "VQ_MODE") == 0) {
		    VideoEngineInfo->INFData.VQMode = (u8)(atoi(StringToken));
		}
		if (strcmp (name, "JPEG_FILE") == 0) {
			
		    VideoEngineInfo->INFData.JPEG_FILE = (u8)(atoi(StringToken));
		printf("JPEG = %d \n",VideoEngineInfo->INFData.JPEG_FILE);
		}

	}

	fclose (fp);
	return 0;
}


#define VIDEO_MEM_SIZE                          0x2800000		/* 40 MB */
#define VIDEO_JPEG_OFFSET                       0x2300000

int main_v1()
{
	VIDEO_ENGINE_INFO   VideoEngineInfo;

	memset(&VideoEngineInfo, 0, sizeof(VideoEngineInfo));

#ifdef CRT
	fbfd = open("/dev/fb0", O_RDWR);
	if (!fbfd) {
		printf("Error: cannot open framebuffer device.\n");
		exit(1);
	}
	printf("The framebuffer device was opened successfully.\n");
#endif

	socketbuffer = (unsigned char*)malloc ((size_t) 1024);

	net_setup();

	if(ast_video_open() < 0)
		exit(1);

	stream_virt_addr = ast_video_mmap_stream_addr();
	jpeg_virt_addr = (unsigned char*)ast_video_mmap_jpeg_addr();

	if(GetINFData(&VideoEngineInfo)) {
		ast_video_close();
		exit(1);
	}

	Video_Status = 1;

	while(1) {
		VideoCapture(&VideoEngineInfo);
	}

	free (buffer);

	ast_video_close();

    return 1;
}
