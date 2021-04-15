/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "video.h"

//#define VIDEO_DEBUG 

int video_fd; 
void *video_stream_addr;
void *video_jpeg_addr;

int ast_video_open(void)
{
	video_fd = open("/dev/ast-video", O_RDWR);
	if(video_fd == -1) {
		perror("Can't open /dev/ast-video, please install driver!! \n");
		return -1;
	}
	return 0;
}

void ast_video_close(void)
{
	close(video_fd);
}

void ast_video_reset(void) {	
	if (ioctl(video_fd, AST_VIDEO_RESET, NULL) < 0) {
		printf("AST_VIDEO_RESET fail\n");
	}
}		

void ast_video_get_vga_signal(unsigned char *signal)
{
	if (ioctl(video_fd, AST_VIDEO_IOC_GET_VGA_SIGNAL, signal) < 0) {
		printf("AST_VIDEO_IOC_GET_VGA_SIGNAL fail\n");
	}
}

void *ast_video_mmap_stream_addr(void)
{
	unsigned long video_mem_size; 
	if (ioctl(video_fd, AST_VIDEO_GET_MEM_SIZE_IOCRX, &video_mem_size) < 0) {
		printf("AST_VIDEO_GET_MEM_SIZE_IOCRX fail\n");
		return NULL;
	} else {
#ifdef VIDEO_DEBUG		
		printf("video memory size = %ldMB \n", video_mem_size/(1024 * 1024));
#endif		
		video_stream_addr = mmap(0, video_mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, video_fd, 0);
		return video_stream_addr;
	}
}

void *ast_video_mmap_jpeg_addr(void)
{
	unsigned long video_jpeg_offset; 
	if (ioctl(video_fd, AST_VIDEO_GET_JPEG_OFFSET_IOCRX, &video_jpeg_offset) < 0) {
		printf("AST_VIDEO_GET_JPEG_OFFSET_IOCRX fail\n");
		return NULL;
	} else {
#ifdef VIDEO_DEBUG			
		printf("video jpeg offset from %ldMB \n", video_jpeg_offset/(1024 * 1024));
#endif		
		video_jpeg_addr = video_stream_addr + video_jpeg_offset;
		return video_jpeg_addr;
	}
}

void ast_video_eng_config(struct ast_video_config* video_config)
{
	if (ioctl(video_fd, AST_VIDEO_ENG_CONFIG, video_config) < 0) {
		printf("AST_VIDEO_ENG_CONFIG fail\n");
	}
}

void ast_video_vga_mode_detection(struct ast_mode_detection* mode_detection)
{
	if (ioctl(video_fd, AST_VIDEO_VGA_MODE_DETECTION, mode_detection) < 0) {
		printf("AST_VIDEO_VGA_MODE_DETECTION fail\n");
	}
}

void ast_video_set_scaling(struct ast_scaling* set_scaling)
{
	if (ioctl(video_fd, AST_VIDEO_SET_SCALING, set_scaling) < 0) {
		printf("AST_VIDEO_SET_SCALING fail\n");
	}
}

void ast_video_auto_mode_trigger(struct ast_auto_mode* auto_mode)
{
	if (ioctl(video_fd, AST_VIDEO_AUTOMODE_TRIGGER, auto_mode) < 0) {
		printf("AST_VIDEO_AUTOMODE_TRIGGER fail\n");
	} 
}

void ast_video_capture_mode_trigger(struct ast_capture_mode* capture_mode)
{
	if (ioctl(video_fd, AST_VIDEO_CAPTURE_TRIGGER, capture_mode) < 0) {
		printf("AST_VIDEO_CAPTURE_TRIGGER fail\n");
	} 
}

void ast_video_compression_mode_trigger(struct ast_compression_mode* compression_mode)
{
	if (ioctl(video_fd, AST_VIDEO_COMPRESSION_TRIGGER, compression_mode) < 0) {
		printf("AST_VIDEO_COMPRESSION_TRIGGER fail\n");
	} 
}

void ast_video_set_vga_display(int *vga_enable) {	
	if (ioctl(video_fd, AST_VIDEO_SET_VGA_DISPLAY, vga_enable) < 0) {
		printf("AST_VIDEO_SET_VGA_DISPLAY fail\n");
	}
}		

void ast_video_set_encryption(int enable) {
	if (ioctl(video_fd, AST_VIDEO_SET_ENCRYPTION, enable) < 0) {
		printf("AST_VIDEO_SET_ENCRYPTION fail\n");
	}
}

void ast_video_set_encryption_key(unsigned char *key) {
	if (ioctl(video_fd, AST_VIDEO_SET_ENCRYPTION_KEY, key) < 0) {
		printf("AST_VIDEO_SET_ENCRYPTION_KEY fail\n");
	}
}

void ast_video_set_crt_compression(	struct fb_var_screeninfo *vinfo) {	
	if (ioctl(video_fd, AST_VIDEO_SET_CRT_COMPRESSION, vinfo) < 0) {
		printf("AST_VIDEO_SET_CRT_COMPRESSION fail\n");
	}
}
