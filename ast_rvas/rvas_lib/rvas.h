/*
 * This file is part of the ASPEED Linux Device Driver for ASPEED Baseboard Management Controller.
 * Refer to the README file included with this package for driver version and adapter compatibility.
 *
 * Copyright (C) 2019-2021 ASPEED Technology Inc. All rights reserved.
 *
 * the file COPYING included with this package.
 */


#ifndef __RVAS_API_H_
#define __RVAS_API_H_

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#include "video_ioctl.h"

#define DEBUG (0)
//#define USE_FILE_LOG

#undef min
#define min(x, y) ((x) < (y) ? (x) : (y))

int OpenLog(const char*);
void CloseLog(void);
#ifdef USE_FILE_LOG
void Log(const char*, ...);
void LogInfo(const char*, ...);
#else
#define Log(fmt, args...) do { if (DEBUG) { printf("Client: %s: " fmt, __FUNCTION__, ## args); } } while (0)
#define LogInfo(fmt, args...) do { if (DEBUG) { printf(fmt, ## args); } } while (0)
#endif // USE_FILE_LOG
void DisplayBuffer(void*, u32);

RVASStatus Initialize(void);
RVASStatus Shutdown(void);
RVASStatus NewContext(RVASContext* aNewContextPtr);
RVASStatus DeleteContext(RVASContext aContext);
RVASStatus Alloc(size_t aLengthInBytes, void** aBufferPtr,RVASMemoryHandle* aMemoryHandlePtr); // in:rvb, out:rmh
RVASStatus Free(RVASMemoryHandle aMemoryHandle); // in:rmh, out:rvb

RVASStatus LocalMonitorOn(void);
RVASStatus LocalMonitorOff(void);
RVASStatus IsLocalMonitorOn(bool* pbMonitorIsOn);

RVASStatus GetVideoGeometry(VideoGeometry* aGeometryPtr); // out:vg
void display_event_map(const EventMap* pem);
RVASStatus WaitForVideoEvent(RVASContext aContext, EventMap anEventMap,EventMap* aMapPtr, u32 aTimeoutInMs); // in:rc, em, dw, out:em,
RVASStatus GetGRCRegisters(RVASMemoryHandle aMemoryHandle); // in:rc, gm, out:rmh
RVASStatus ReadSnoopMap(RVASContext aContext, RVASMemoryHandle aMemoryHandle, bool bClear);
RVASStatus ReadSnoopAggregate(RVASContext aContext,SnoopAggregate* anAggregatePtr, bool bClear); // in:rc, b, out:sa

RVASStatus FetchVideoTiles( RVASContext rc, RVASMemoryHandle aMemoryHandleFVTA,
        RVASMemoryHandle aMemoryHandleOutput,
        RVASMemoryHandle aMemoryHandleTemp); // This aMemoryHandleTemp buffer need to be the same size as output buffer

// in:rmh(descriptors), rmh2(video data out), out:dw(checksum), dw2(rle count)
RVASStatus FetchVideoSlices(RVASContext rc, RVASMemoryHandle aMemoryHandleFSA,
    RVASMemoryHandle aMemoryHandleNonRLE, RVASMemoryHandle aMemoryHandleRLE);

RVASStatus FetchTextData(RVASContext rc, VideoGeometry aGeometry,
    FetchMap *paTextMap, RVASMemoryHandle aMemoryHandleNonRLE,
    RVASMemoryHandle aMemoryHandleRLE); // in:vg, tfm, rmh, out:dw

//mode 13
RVASStatus FetchVGAGraphicsData(RVASContext rc, VideoGeometry aGeometry,
    FetchMap *paVideoMap,
        RVASMemoryHandle aMemoryHandleNonRLE, RVASMemoryHandle aMemoryHandleRLE); // in:vg, tfm, rmh, out:dw

// in:rmh(descriptors), rmh2(video data out), out:dw(checksum), dw2(rle count)
RVASStatus RunLengthEncode(RVASMemoryHandle aMemoryHandleIn,
        RVASMemoryHandle aMemoryHandleOut, u8 byRLETripletCode,
        u8 byRLERepeatCode, u32* aRLECountPtr, u32* aCheckSumPtr); //out:dw

// Set Tile Snoop Interrupt Count Register (TSICR)
RVASStatus SetTSECounter(u32 value); //out:dw

// Get Tile Snoop Interrupt Count Register (TSICR)
u32 GetTSECounter(void); //out:dw

// Reset the Video Engine
RVASStatus ResetVideoEngine(ResetEngineMode resetMode); //out:dw

// Get the Video Engine Config
RVASStatus GetVideoEngineConfig(VideoConfig* ast_config); //out:dw

// Set the Video Engine Config
RVASStatus SetVideoEngineConfig(const VideoConfig* ast_config); //out:dw

// Get the Video Engine Data
RVASStatus GetVideoEngineJPEGData(MultiJpegConfig*  ast_multi); //RVASMemoryHandle aMemoryHandle); //out:dw

#endif //__RVAS_API_H_
