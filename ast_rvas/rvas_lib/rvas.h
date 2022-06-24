/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2021 Aspeed Technology Inc.
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

int OpenLog(const char *name);
void CloseLog(void);
#ifdef USE_FILE_LOG
void Log(const char*, ...);
void LogInfo(const char*, ...);
#else
#define Log(fmt, args...) do { if (DEBUG) { printf("Client: %s: " fmt, __FUNCTION__, ## args); } } while (0)
#define LogInfo(fmt, args...) do { if (DEBUG) { printf(fmt, ## args); } } while (0)
#endif // USE_FILE_LOG
void DisplayBuffer(void*, u32);

enum RVASStatus Initialize(void);
enum RVASStatus Shutdown(void);
enum RVASStatus NewContext(void **aNewContextPtr);
enum RVASStatus DeleteContext(void *aContext);
enum RVASStatus Alloc(size_t aLengthInBytes, void **aBufferPtr, void **aMemoryHandlePtr);
// in:rvb, out:rmh
enum RVASStatus Free(void *aMemoryHandle); // in:rmh, out:rvb

enum RVASStatus LocalMonitorOn(void);
enum RVASStatus LocalMonitorOff(void);
enum RVASStatus IsLocalMonitorOn(bool *pbMonitorIsOn);

enum RVASStatus GetVideoGeometry(struct VideoGeometry *aGeometryPtr); // out:vg
void display_event_map(const struct EventMap *pem);
enum RVASStatus WaitForVideoEvent(void *aContext, struct EventMap anEventMap,
		struct EventMap *aMapPtr, u32 aTimeoutInMs); // in:rc, em, dw, out:em,
enum RVASStatus GetGRCRegisters(void *aMemoryHandle); // in:rc, gm, out:rmh
enum RVASStatus ReadSnoopMap(void *aContext, void *aMemoryHandle, bool bClear);
enum RVASStatus ReadSnoopAggregate(void *aContext, struct SnoopAggregate *anAggregatePtr,
		bool bClear); // in:rc, b, out:sa

enum RVASStatus FetchVideoTiles(void *rc, void *aMemoryHandleFVTA,
		void *aMemoryHandleOutput,
		void *aMemoryHandleTemp);
// This aMemoryHandleTemp buffer need to be the same size as output buffer

// in:rmh(descriptors), rmh2(video data out), out:dw(checksum), dw2(rle count)
enum RVASStatus FetchVideoSlices(void *rc, void *aMemoryHandleFSA,
	void *aMemoryHandleNonRLE, void *aMemoryHandleRLE);

enum RVASStatus FetchTextData(void *rc, struct VideoGeometry aGeometry,
	struct FetchMap *paTextMap, void *aMemoryHandleNonRLE,
	void *aMemoryHandleRLE); // in:vg, tfm, rmh, out:dw

//mode 13
enum RVASStatus FetchVGAGraphicsData(void *rc, struct VideoGeometry aGeometry,
	struct FetchMap *paVideoMap,
	void *aMemoryHandleNonRLE, void *aMemoryHandleRLE); // in:vg, tfm, rmh, out:dw

// in:rmh(descriptors), rmh2(video data out), out:dw(checksum), dw2(rle count)
enum RVASStatus RunLengthEncode(void *aMemoryHandleIn,
	void *aMemoryHandleOut, u8 byRLETripletCode,
	u8 byRLERepeatCode, u32 *aRLECountPtr, u32 *aCheckSumPtr); //out:dw

// Set Tile Snoop Interrupt Count Register (TSICR)
enum RVASStatus SetTSECounter(u32 value); //out:dw

// Get Tile Snoop Interrupt Count Register (TSICR)
u32 GetTSECounter(void); //out:dw

// Reset the Video Engine
enum RVASStatus ResetVideoEngine(enum ResetEngineMode resetMode); //out:dw

// Get the Video Engine Config
enum RVASStatus GetVideoEngineConfig(struct VideoConfig *ast_config); //out:dw

// Set the Video Engine Config
enum RVASStatus SetVideoEngineConfig(const struct VideoConfig *ast_config); //out:dw

// Get the Video Engine Data
enum RVASStatus GetVideoEngineJPEGData(struct MultiJpegConfig *ast_multi);
//void*aMemoryHandle); //out:dw

#endif //__RVAS_API_H_
