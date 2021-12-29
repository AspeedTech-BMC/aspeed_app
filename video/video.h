/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2021 Aspeed Technology Inc. */

#include <linux/fb.h>

/*************************************************************************************/
//VR08[2]
typedef enum ast_video_source {
	VIDEO_SOURCE_INT_VGA = 0,
	VIDEO_SOURCE_INT_CRT,
	VIDEO_SOURCE_EXT_ADC,
	VIDEO_SOURCE_EXT_DIGITAL,
} video_source;
/*************************************************************************************/
//video engine initial
struct video_eng_config {
	video_source		input_source;
	unsigned char		DifferentialSetting;		
	unsigned char		Auto_Mode;		//force 1:auto,  0:capture and compress 
	unsigned char		Mode_420;
	unsigned char		Direct_Mode;	//no use : auto switch by driver detection --> TODO Sync_Mode 0: Auto direct 1:Force sync
//TODO ~~ GRAY mode
	//encryption
	unsigned char		RC4_Enable;
	unsigned char		encrypt_key[256];

	unsigned char		Y_Table;
	
	//Visual_Lossless enable	
	unsigned char		Visual_Lossless;
	unsigned char		Advance_Table;

	//scaling on/off
	unsigned char		scaling;
	unsigned short	User_Width;
	unsigned short	User_Height;	

	//JPEG config
	unsigned char		Jpeg_en;
	unsigned char		Jpeg_Mode_420;

	unsigned char		Jpeg_Y_Table;
	
	//Visual_Lossless enable	
	unsigned char		Jpeg_Visual_Lossless;
	unsigned char		Jpeg_Advance_Table;

	//scaling on/off
	unsigned char		Jpeg_scaling;	
	unsigned short	Jpeg_User_Width;
	unsigned short	Jpeg_User_Height;		
};

//video [stream/frame mode info]
struct ast_video_info {
	unsigned char		full_frame;
	unsigned long		Data_Length;
	unsigned long		Blocks_Changed;	
};

struct ast_video_config
{
	unsigned char	engine;					//0: engine 0, engine 1
	unsigned char	compression_mode; 		//0:DCT, 1:DCT_VQ mix VQ-2 color, 2:DCT_VQ mix VQ-4 color		9:
	unsigned char	compression_format;		//0:ASPEED 1:JPEG	
	unsigned char	capture_format;			//0:CCIR601-2 YUV, 1:JPEG YUV, 2:RGB for ASPEED mode only, 3:Gray 
	unsigned char	rc4_enable;				//0:disable 1:enable
	unsigned char 	EncodeKeys[256];		

	unsigned char	YUV420_mode;			//0:YUV444, 1:YUV420
	unsigned char	Visual_Lossless;
	unsigned char	Y_JPEGTableSelector;
	unsigned char	AdvanceTableSelector;
	unsigned char	AutoMode;
};

struct ast_auto_mode
{
	unsigned char	engine_idx;					//set 0: engine 0, engine 1
	unsigned char	differential;					//set 0: full, 1:diff frame
	unsigned char	mode_change;				//get 0: no, 1:change
	unsigned long	total_size;					//get 
	unsigned long	block_count;					//get 
};

struct ast_scaling
{
	unsigned char		engine;					//0: engine 0, engine 1
	unsigned char		enable;
	unsigned short	x;
	unsigned short	y;
};

struct ast_capture_mode {
	unsigned char	engine_idx;					//set 0: engine 0, engine 1
	unsigned char	differential;					//set 0: full, 1:diff frame
	unsigned char	mode_change;				//get 0: no, 1:change
};

struct ast_compression_mode {
	unsigned char	engine_idx;					//set 0: engine 0, engine 1
	unsigned char	mode_change;				//get 0: no, 1:change
	unsigned long	total_size;					//get
	unsigned long	block_count;					//get
};

struct fbinfo
{
	unsigned short	x;
	unsigned short	y;
	unsigned char		color_mode;	//0:NON, 1:EGA, 2:VGA, 3:15bpp, 4:16bpp, 5:32bpp
	unsigned long		PixelClock;
};

struct ast_mode_detection
{
	unsigned char		result;		//0: pass, 1: fail
	unsigned short	src_x;
	unsigned short	src_y;
};

/*************************************************************************************/
#define VIDEOIOC_BASE       'V'

#define AST_VIDEO_RESET							_IO(VIDEOIOC_BASE, 0x0)
#define AST_VIDEO_IOC_GET_VGA_SIGNAL			_IOR(VIDEOIOC_BASE, 0x1, unsigned char)
#define AST_VIDEO_GET_MEM_SIZE_IOCRX			_IOR(VIDEOIOC_BASE, 0x2, unsigned long)
#define AST_VIDEO_GET_JPEG_OFFSET_IOCRX		_IOR(VIDEOIOC_BASE, 0x3, unsigned long)
#define AST_VIDEO_VGA_MODE_DETECTION			_IOWR(VIDEOIOC_BASE, 0x4, struct ast_mode_detection*)

#define AST_VIDEO_ENG_CONFIG					_IOW(VIDEOIOC_BASE, 0x5, struct ast_video_config*)
#define AST_VIDEO_SET_SCALING					_IOW(VIDEOIOC_BASE, 0x6, struct ast_scaling*)

#define AST_VIDEO_AUTOMODE_TRIGGER			_IOWR(VIDEOIOC_BASE, 0x7, struct ast_auto_mode*)
#define AST_VIDEO_CAPTURE_TRIGGER				_IOWR(VIDEOIOC_BASE, 0x8, struct ast_capture_mode*)
#define AST_VIDEO_COMPRESSION_TRIGGER		_IOWR(VIDEOIOC_BASE, 0x9, struct ast_compression_mode*)

#define AST_VIDEO_SET_VGA_DISPLAY				_IOW(VIDEOIOC_BASE, 0xa, int)
#define AST_VIDEO_SET_ENCRYPTION				_IOW(VIDEOIOC_BASE, 0xb, int)
#define AST_VIDEO_SET_ENCRYPTION_KEY			_IOW(VIDEOIOC_BASE, 0xc, unsigned char*)
#define AST_VIDEO_SET_CRT_COMPRESSION		_IOW(VIDEOIOC_BASE, 0xd, struct fb_var_screeninfo*)
/*************************************************************************************/
int ast_video_open(void);
void ast_video_close(void);
void ast_video_reset(void);
void ast_video_get_vga_signal(unsigned char *signal);
void *ast_video_mmap_stream_addr(void);
void *ast_video_mmap_jpeg_addr(void);
void ast_video_vga_mode_detection(struct ast_mode_detection* mode_detection);
void ast_video_set_scaling(struct ast_scaling* set_scaling);
void ast_video_eng_config(struct ast_video_config* video_config);
void ast_video_auto_mode_trigger(struct ast_auto_mode* auto_mode);
void ast_video_capture_mode_trigger(struct ast_capture_mode* capture_mode);
void ast_video_compression_mode_trigger(struct ast_compression_mode* compression_mode);
void ast_video_set_vga_display(int *vga_enable);
int ast_video_compression_trigger(struct ast_video_info *video_info);
void ast_video_set_encryption(int enable);
void ast_video_set_encryption_key(unsigned char *key);
void ast_video_set_crt_compression(	struct fb_var_screeninfo *vinfo);
