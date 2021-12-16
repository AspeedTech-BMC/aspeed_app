/*
 * Copyright 2020 Aspeed Technology Inc.
 */
typedef unsigned long u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define    BYTE                     unsigned char
#define    INT                      int
#define    VOID                     void
#define    BOOLEAN                  unsigned short

#ifndef Windows
#define    ULONG                    unsigned long
#define    USHORT                   unsigned short
#define    UCHAR                    unsigned char
#endif


#ifndef  _STRUCTURE_INFO
#define  _STRUCTURE_INFO

typedef struct _VIDEO_MODE_INFO
{
    USHORT    X;
    USHORT    Y;
    USHORT    ColorDepth;
    USHORT    RefreshRate;
    BYTE      ModeIndex;
} VIDEO_MODE_INFO, *PVIDEO_MODE_INFO;

typedef struct _VQ_INFO {
    BYTE    Y[16];
    BYTE    U[32];
    BYTE    V[32];
    BYTE    NumberOfY;
    BYTE    NumberOfUV;
    BYTE    NumberOfInner;
    BYTE    NumberOfOuter;
} VQ_INFO, *PVQ_INFO;

typedef struct _HUFFMAN_TABLE {
    ULONG  HuffmanCode[32];
} HUFFMAN_TABLE, *PHUFFMAN_TABLE;

typedef struct _FRAME_HEADER {
    ULONG     StartCode;	//0
    ULONG     FrameNumber;	///4
    USHORT    HSize;		//8
    USHORT    VSize;
    ULONG     Reserved[2];	//12 13 14
    BYTE      DirectMode;		//15    
    BYTE      CompressionMode;		//15
    BYTE      JPEGScaleFactor;		//16
    BYTE      Y_JPEGTableSelector;	//18 [[[[
    BYTE      JPEGYUVTableMapping;
    BYTE      SharpModeSelection;
    BYTE      AdvanceTableSelector;
    BYTE      AdvanceScaleFactor;
    ULONG     NumberOfMB;
    BYTE      VQ_YLevel;
    BYTE      VQ_UVLevel;
    VQ_INFO   VQVectors;
    BYTE      RC4Enable;
    BYTE      Mode420;
    BYTE      Visual_Lossless;
} FRAME_HEADER, *PFRAME_HEADER;

typedef struct _INF_DATA {
	unsigned char AST2500;
	unsigned char Input_Signale;	//0: internel vga, 1, ext digital, 2, ext analog
	unsigned char Trigger_Mode;	//0: capture, 1, ext digital, 2, ext analog
    BYTE    DownScalingEnable;
    BYTE    DifferentialSetting;
    USHORT  AnalogDifferentialThreshold;
    USHORT  DigitalDifferentialThreshold;
    BYTE    AutoMode;
    BYTE    DirectMode;		//0: force sync mode 1: auto direct mode 
    USHORT  DelayControl;
    BYTE    VQMode;
BYTE JPEG_FILE;
} INF_DATA, *PINF_DATA;

typedef struct _COMPRESS_DATA {
    ULONG   SourceFrameSize;
    ULONG   CompressSize;
    ULONG   HDebug;
    ULONG   VDebug;
} COMPRESS_DATA, *PCOMPRESS_DATA;

//VIDEO Engine Info
typedef struct _VIDEO_ENGINE_INFO {
    INF_DATA           INFData;
    VIDEO_MODE_INFO    SourceModeInfo;
    VIDEO_MODE_INFO    DestinationModeInfo;
    VQ_INFO            VQInfo;
    FRAME_HEADER       FrameHeader;
    COMPRESS_DATA      CompressData;
    BYTE               ChipVersion;
    BYTE               NoSignal;
} VIDEO_ENGINE_INFO, *PVIDEO_ENGINE_INFO;

typedef struct {
    USHORT    HorizontalTotal;
    USHORT    VerticalTotal;
    USHORT    HorizontalActive;
    USHORT    VerticalActive;
    BYTE      RefreshRate;
    double    HorizontalFrequency;
    USHORT    HSyncTime;
    USHORT    HBackPorch;
    USHORT    VSyncTime;
    USHORT    VBackPorch;
    USHORT    HLeftBorder;
    USHORT    HRightBorder;
    USHORT    VBottomBorder;
    USHORT    VTopBorder;
} VESA_MODE;

typedef struct {
    USHORT    HorizontalActive;
    USHORT    VerticalActive;
    USHORT    RefreshRate;
    BYTE      ADCIndex1;
    BYTE      ADCIndex2;
    BYTE      ADCIndex3;
    BYTE      ADCIndex5;
    BYTE      ADCIndex6;
    BYTE      ADCIndex7;
    BYTE      ADCIndex8;
    BYTE      ADCIndex9;
    BYTE      ADCIndexA;
    BYTE      ADCIndexF;
    BYTE      ADCIndex15;
    int       HorizontalShift;
    int       VerticalShift;
} ADC_MODE;

typedef struct {
    USHORT    HorizontalActive;
    USHORT    VerticalActive;
    USHORT    RefreshRateIndex;
    double    PixelClock;
} INTERNAL_MODE;

typedef struct _TRANSFER_HEADER {
	ULONG     Data_Length;
	ULONG     Blocks_Changed;
	USHORT    User_Width;
	USHORT    User_Height;
	BYTE	Frist_frame;		// 1: first frame 
	BYTE	Compress_type;	//0:aspeed mode, 1:jpeg mode
	BYTE	Trigger_mode;	//0:capture, 1: compression, 2: buffer
	BYTE	Data_format;	//0:DCT, 1:DCTwVQ2 color, 2:DCTwVQ4 color
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



//  RC4 structure
struct rc4_state
{
    int x;
    int y;
    int m[256];
};

#endif
