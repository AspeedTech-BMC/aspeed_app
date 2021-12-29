/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2021 Aspeed Technology Inc.
 */
#ifndef _VIDEO_IOCTL_H
#define _VIDEO_IOCTL_H

#include <linux/types.h>

#define RVAS_MAGIC				('b')
#define CMD_IOCTL_TURN_LOCAL_MONITOR_ON		_IOR(RVAS_MAGIC, \
		IOCTL_TURN_LOCAL_MONITOR_ON, RvasIoctl)
#define CMD_IOCTL_TURN_LOCAL_MONITOR_OFF	_IOR(RVAS_MAGIC, \
		IOCTL_TURN_LOCAL_MONITOR_OFF, RvasIoctl)
#define CMD_IOCTL_IS_LOCAL_MONITOR_ENABLED	_IOR(RVAS_MAGIC, \
		IOCTL_IS_LOCAL_MONITOR_ENABLED, RvasIoctl)
#define CMD_IOCTL_GET_VIDEO_GEOMETRY		_IOWR(RVAS_MAGIC, \
		IOCTL_GET_VIDEO_GEOMETRY, RvasIoctl)
#define CMD_IOCTL_WAIT_FOR_VIDEO_EVENT		_IOWR(RVAS_MAGIC, \
		IOCTL_WAIT_FOR_VIDEO_EVENT, RvasIoctl)
#define CMD_IOCTL_GET_GRC_REGIESTERS		_IOWR(RVAS_MAGIC, \
		IOCTL_GET_GRC_REGIESTERS, RvasIoctl)
#define CMD_IOCTL_READ_SNOOP_MAP		_IOWR(RVAS_MAGIC, IOCTL_READ_SNOOP_MAP, RvasIoctl)
#define CMD_IOCTL_READ_SNOOP_AGGREGATE		_IOWR(RVAS_MAGIC, \
		IOCTL_READ_SNOOP_AGGREGATE, RvasIoctl)
#define CMD_IOCTL_FETCH_VIDEO_TILES		_IOWR(RVAS_MAGIC, \
		IOCTL_FETCH_VIDEO_TILES, RvasIoctl)
#define CMD_IOCTL_FETCH_VIDEO_SLICES		_IOWR(RVAS_MAGIC, \
		IOCTL_FETCH_VIDEO_SLICES, RvasIoctl)
#define CMD_IOCTL_RUN_LENGTH_ENCODE_DATA	_IOWR(RVAS_MAGIC, \
		IOCTL_RUN_LENGTH_ENCODE_DATA, RvasIoctl)
#define CMD_IOCTL_FETCH_TEXT_DATA		_IOWR(RVAS_MAGIC, IOCTL_FETCH_TEXT_DATA, RvasIoctl)
#define CMD_IOCTL_FETCH_MODE13_DATA		_IOWR(RVAS_MAGIC, \
		IOCTL_FETCH_MODE13_DATA, RvasIoctl)
#define CMD_IOCTL_NEW_CONTEXT			_IOWR(RVAS_MAGIC, IOCTL_NEW_CONTEXT, RvasIoctl)
#define CMD_IOCTL_DEL_CONTEXT			_IOWR(RVAS_MAGIC, IOCTL_DEL_CONTEXT, RvasIoctl)
#define CMD_IOCTL_ALLOC				_IOWR(RVAS_MAGIC, IOCTL_ALLOC, RvasIoctl)
#define CMD_IOCTL_FREE				_IOWR(RVAS_MAGIC, IOCTL_FREE, RvasIoctl)
#define CMD_IOCTL_SET_TSE_COUNTER			_IOWR(RVAS_MAGIC, \
		IOCTL_SET_TSE_COUNTER, RvasIoctl)
#define CMD_IOCTL_GET_TSE_COUNTER			_IOWR(RVAS_MAGIC, \
		IOCTL_GET_TSE_COUNTER, RvasIoctl)
#define CMD_IOCTL_VIDEO_ENGINE_RESET		_IOWR(RVAS_MAGIC, \
		IOCTL_VIDEO_ENGINE_RESET, RvasIoctl)
//jpeg
#define CMD_IOCTL_SET_VIDEO_ENGINE_CONFIG		_IOW(RVAS_MAGIC, \
		IOCTL_SET_VIDEO_ENGINE_CONFIG, VideoConfig*)
#define CMD_IOCTL_GET_VIDEO_ENGINE_CONFIG		_IOW(RVAS_MAGIC, \
		IOCTL_GET_VIDEO_ENGINE_CONFIG, VideoConfig*)
#define CMD_IOCTL_GET_VIDEO_ENGINE_DATA	_IOWR(RVAS_MAGIC, \
		IOCTL_GET_VIDEO_ENGINE_DATA, MultiJpegConfig*)

typedef enum {
	IOCTL_TURN_LOCAL_MONITOR_ON = 20, //REMOTE VIDEO GENERAL IOCTL
	IOCTL_TURN_LOCAL_MONITOR_OFF,
	IOCTL_IS_LOCAL_MONITOR_ENABLED,

	IOCTL_GET_VIDEO_GEOMETRY = 40, // REMOTE VIDEO
	IOCTL_WAIT_FOR_VIDEO_EVENT,
	IOCTL_GET_GRC_REGIESTERS,
	IOCTL_READ_SNOOP_MAP,
	IOCTL_READ_SNOOP_AGGREGATE,
	IOCTL_FETCH_VIDEO_TILES,
	IOCTL_FETCH_VIDEO_SLICES,
	IOCTL_RUN_LENGTH_ENCODE_DATA,
	IOCTL_FETCH_TEXT_DATA,
	IOCTL_FETCH_MODE13_DATA,
	IOCTL_NEW_CONTEXT,
	IOCTL_DEL_CONTEXT,
	IOCTL_ALLOC,
	IOCTL_FREE,
	IOCTL_SET_TSE_COUNTER,
	IOCTL_GET_TSE_COUNTER,
	IOCTL_VIDEO_ENGINE_RESET,
	IOCTL_SET_VIDEO_ENGINE_CONFIG,
	IOCTL_GET_VIDEO_ENGINE_CONFIG,
	IOCTL_GET_VIDEO_ENGINE_DATA,
} HARD_WARE_ENGINE_IOCTL;

typedef void *RVASContext;
typedef void *RVASMemoryHandle;

typedef enum tagGraphicsModeType {
	InvalidMode = 0, TextMode = 1, VGAGraphicsMode = 2, AGAGraphicsMode = 3
} GraphicsModeType;

typedef enum tagRVASStatus {
	SuccessStatus = 0,
	GenericError = 1,
	MemoryAllocError = 2,
	InvalidMemoryHandle = 3,
	CannotMapMemory = 4,
	CannotUnMapMemory = 5,
	TimedOut = 6,
	InvalidContextHandle = 7,
	CaptureTimedOut = 8,
	CompressionTimedOut = 9,
	HostSuspended
} RVASStatus;

typedef enum tagSelectedByteMode {
	AllBytesMode = 0,
	SkipMode = 1,
	PlanarToPackedMode,
	PackedToPackedMode,
	LowByteMode,
	MiddleByteMode,
	TopByteMode
} SelectedByteMode;

typedef enum tagDataProccessMode {
	NormalTileMode = 0,
	FourBitPlanarMode = 1,
	FourBitPackedMode = 2,
	AttrMode = 3,
	AsciiOnlyMode = 4,
	FontFetchMode = 5,
	SplitByteMode = 6
} DataProccessMode;

typedef enum tagResetEngineMode {
	ResetAll = 0,
	ResetRvasEngine = 1,
	ResetVeEngine = 2
} ResetEngineMode;

typedef struct tagVideoGeometry {
	u16 wScreenWidth;
	u16 wScreenHeight;
	u16 wStride;
	u8 byBitsPerPixel;
	u8 byModeID;
	GraphicsModeType gmt;
} VideoGeometry;

typedef struct tagEventMap {
	u32 bPaletteChanged :1;
	u32 bATTRChanged :1;
	u32 bSEQChanged :1;
	u32 bGCTLChanged :1;
	u32 bCRTCChanged :1;
	u32 bCRTCEXTChanged :1;
	u32 bPLTRAMChanged :1;
	u32 bXCURCOLChanged :1;
	u32 bXCURCTLChanged :1;
	u32 bXCURPOSChanged :1;
	u32 bDoorbellA :1;
	u32 bDoorbellB :1;
	u32 bGeometryChanged :1;
	u32 bSnoopChanged :1;
	u32 bTextFontChanged :1;
	u32 bTextATTRChanged :1;
	u32 bTextASCIIChanged :1;
} EventMap;

typedef struct tagFetchMap {
	//in parameters
	bool bEnableRLE;
	u8 bTextAlignDouble; // 0 - 8 byte, 1 - 16 byte
	u8 byRLETripletCode;
	u8 byRLERepeatCode;
	DataProccessMode dpm;
	//out parameters
	u32 dwFetchSize;
	u32 dwFetchRLESize;
	u32 dwCheckSum;
	bool bRLEFailed;
	u8 rsvd[3];
} FetchMap;

typedef struct tagSnoopAggregate {
	u64 qwRow;
	u64 qwCol;
} SnoopAggregate;

typedef struct tagFetchRegion {
	u16 wTopY;
	u16 wLeftX;
	u16 wBottomY;
	u16 wRightX;
} FetchRegion;

typedef struct tagFetchOperation {
	FetchRegion fr;
	SelectedByteMode sbm;
	u32 dwFetchSize;
	u32 dwFetchRLESize;
	u32 dwCheckSum;
	bool bRLEFailed;
	bool bEnableRLE;
	u8 byRLETripletCode;
	u8 byRLERepeatCode;
	u8 byVGATextAlignment; //0-8bytes, 1-16bytes.
} FetchOperation;

typedef struct tagFetchVideoTilesArg {
	VideoGeometry vg;
	u32 dwTotalOutputSize;
	u32 cfo;
	FetchOperation pfo[4];
} FetchVideoTilesArg;

typedef struct tagFetchVideoSlicesArg {
	VideoGeometry vg;
	u32 dwSlicedSize;
	u32 dwSlicedRLESize;
	u32 dwCheckSum;
	bool bEnableRLE;
	bool bRLEFailed;
	u8 byRLETripletCode;
	u8 byRLERepeatCode;
	u8 cBuckets;
	u8 abyBitIndexes[24];
	u32 cfr;
	FetchRegion pfr[4];
} FetchVideoSlicesArg;

typedef struct tagRVASBuffer {
	void *pv;
	size_t cb;
} RVASBuffer;


typedef struct tagRvasIoctl {
	RVASStatus rs;
	RVASContext rc;
	RVASBuffer rvb;
	RVASMemoryHandle rmh;
	RVASMemoryHandle rmh1;
	RVASMemoryHandle rmh2;
	u32 rmh_mem_size;
	u32 rmh1_mem_size;
	u32 rmh2_mem_size;
	VideoGeometry vg;
	EventMap em;
	SnoopAggregate sa;
	union {
		u32 tse_counter;
		u32 req_mem_size;
		u32 encode;
		u32 time_out;
	};
	u32 rle_len;  // RLE Length
	u32 rle_checksum;
	FetchMap tfm;
	u8 flag;
	u8 lms;
	u8 resetMode;
	u8 rsvd[1];
} RvasIoctl;


//
// Video Engine
//

#define MAX_MULTI_FRAME_CT (32)

typedef struct tagAstVideoConfig {
	u8 engine;	//0: engine 0 - normal engine, engine 1 - VM legacy engine
	u8 compression_mode;	//0:DCT, 1:DCT_VQ mix VQ-2 color, 2:DCT_VQ mix VQ-4 color 9:
	u8 compression_format;	//0:ASPEED 1:JPEG
	u8 capture_format;	//0:CCIR601-2 YUV, 1:JPEG YUV, 2:RGB for ASPEED mode only, 3:Gray
	u8 rc4_enable;		//0:disable 1:enable
	u8 YUV420_mode;		//0:YUV444, 1:YUV420
	u8 Visual_Lossless;
	u8 Y_JPEGTableSelector;
	u8 AdvanceTableSelector;
	u8 AutoMode;
	u8 rsvd[2];
	RVASStatus rs;
} VideoConfig;

typedef struct tagMultiJpegFrame {
	u32 dwSizeInBytes;			// Image size in bytes
	u32 dwOffsetInBytes;			// Offset in bytes
	u16 wXPixels;					// In: X coordinate
	u16 wYPixels;					// In: Y coordinate
	u16 wWidthPixels;				// In: Width for Fetch
	u16 wHeightPixels;			// In: Height for Fetch
} MultiJpegFrame;

typedef struct tagMultiJpegConfig {
	unsigned char multi_jpeg_frames;				// frame count
	MultiJpegFrame frame[MAX_MULTI_FRAME_CT];	// The Multi Frames
	RVASMemoryHandle aStreamHandle;
	RVASStatus rs;
} MultiJpegConfig;

#endif // _VIDEO_IOCTL_H
