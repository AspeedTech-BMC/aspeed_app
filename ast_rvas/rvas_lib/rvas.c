/*
 * Copyright © 2019-2021 ASPEED Technology. All rights reserved. ASPEED CONFIDENTIAL. Unpublished
 * work. Copying, access, use or distribution requires an applicable license approved by ASPEED.
 */

//
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>

#include "rvas.h"


#define INVALID_HANDLE           (-1)
#define MEM_MAP_ADDR_MASK        (0xfff)
#define MEM_MAP_TABLE_INCR       (8)

typedef struct tagMemMap {
   RVASMemoryHandle rmh;
   void* pvMemory;
   u32 dwLength;
} MemMap;


int dev_fd = INVALID_HANDLE;
int mem_fd = INVALID_HANDLE;
sem_t sMutex;
sem_t sMemMutex;
MemMap** ppmmMemoryMap = NULL;
u32 dwMemMapSize = 0;

FILE* pfLogOut = NULL;

void ClearMemMap (void);
MemMap* GetMemMap (const RVASMemoryHandle);
MemMap* NewMemMap (void);
bool RemoveMemMap (const RVASMemoryHandle);


int OpenLog (const char* szLogFile) {
   int b_ret = 1;

   return b_ret;
}

void CloseLog (void) {
#ifdef DEBUG
	if (pfLogOut && (pfLogOut != stdout)) {
		fclose(pfLogOut);
	}

	pfLogOut = NULL;
#endif // DEBUG
}

#ifdef USE_FILE_LOG
void Log (const char* format, ...) {
#ifdef DEBUG
	if (pfLogOut) {
		va_list args;
		va_start(args, format);
		vfprintf(pfLogOut, format, args);
		va_end(args);
	}
#endif // DEBUG
}

void LogInfo(const char *format, ...) {
#ifdef DEBUG
	if (pfLogOut) {
		va_list args;
		va_start(args, format);
		vfprintf(pfLogOut, format, args);
		va_end(args);
	}
#endif // DEBUG
}

#endif // USE_FILE_LOG

void DisplayBuffer (void* pvBuf, u32 theLength) {
   u32 cbOnThisLine;
   u32 iByte;
   u32 iLine;
   char c;
   u8* theBuffer = (u8*) pvBuf;

   for (iLine = 0; iLine < (theLength + 15) / 16; ++iLine) {
      cbOnThisLine = min(16, theLength - (iLine << 4));

      for (iByte = 0; iByte < 16; iByte++) {
         if (iByte < cbOnThisLine) {
				LogInfo("%2.2x ",
				        theBuffer[(iLine << 4) + iByte]);
         }
         else {
				LogInfo(".. ");
         }
      }

		LogInfo(" - ");

      for (iByte = 0; iByte < 16; ++iByte) {
         if (iByte < cbOnThisLine) {
            c = theBuffer[(iLine << 4) + iByte];

            if ((c >= 32) && (c <= 127)) {
					LogInfo("%c", c);
            }
            else {
					LogInfo(".");
            }
         }
         else {
				LogInfo(".");
         }
      }

		LogInfo("\n");
   }
}

RVASStatus Initialize( void ){
	Log("Start\n");
   if (dev_fd < 0) {
		Log("Opening /dev/rvas...\n");
      dev_fd =  open("/dev/rvas",O_RDWR);
		Log("dev_fd: %d\n", dev_fd);

      if( dev_fd < 0 ){
         printf("Could not open file: /dev/rvas errno: %d\n", errno);
         dev_fd = INVALID_HANDLE;
         exit(-1);
      }
		Log("sMutex...\n");
      sem_init( &sMutex, 0, 1 );
   }

	if (mem_fd < 0) {
		Log("Opening /dev/mem...\n");
		mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
		Log("mem_fd: %d\n", mem_fd);
		if (mem_fd < 0) {
			printf("Could not open file: /dev/mem errno: %d\n",
			        errno);
			mem_fd = INVALID_HANDLE;
			exit(-1);
		}
		Log("sMemMutex...\n");
		sem_init(&sMemMutex, 0, 1);
		ppmmMemoryMap = NULL;
		dwMemMapSize = 0;
	}
	Log("End\n");

   return 0;
}

RVASStatus Shutdown( void ){

   if(dev_fd >= 0){
      close(dev_fd);
      dev_fd = INVALID_HANDLE;
   }
	if (mem_fd >= 0) {
		close(mem_fd);
		mem_fd = INVALID_HANDLE;
	}
   sem_destroy(&sMutex);
   ClearMemMap();
   sem_destroy(&sMemMutex);

   return SuccessStatus;
}

void ClearMemMap (void) {
   u32 dw_index;

   sem_wait(&sMemMutex);

   for (dw_index = 0; dw_index < dwMemMapSize; ++dw_index) {
      if (ppmmMemoryMap[dw_index]) {
         free(ppmmMemoryMap[dw_index]);
      }
   }

   if (ppmmMemoryMap) {
      free(ppmmMemoryMap);
      ppmmMemoryMap = NULL;
   }

   dwMemMapSize = 0;

   sem_post(&sMemMutex);
}

MemMap* GetMemMap (const RVASMemoryHandle crmh) {
   MemMap* pmm = NULL;
   u32 dw_index = 0;

   sem_wait(&sMemMutex);

   while (!pmm && (dw_index < dwMemMapSize)) {
      if (ppmmMemoryMap[dw_index] &&
         (ppmmMemoryMap[dw_index]->rmh == crmh)) {
         pmm = ppmmMemoryMap[dw_index];
      }
      else {
         ++dw_index;
      }
   }

   sem_post(&sMemMutex);

   return pmm;
}

MemMap* NewMemMap (void) {
   u32 dw_new_table_sz;
   MemMap** ppmm_new_table;
   MemMap* pmm = NULL;
   u32 dw_index = 0;
   bool b_found = false;
   bool b_mem_err = false;

   sem_wait(&sMemMutex);

   while (!b_found && (dw_index < dwMemMapSize)) {
      if (!(ppmmMemoryMap[dw_index])) {
         b_found = true;
      }
      else {
         ++dw_index;
      }
   }

   if (!b_found) {
      dw_new_table_sz = dwMemMapSize + MEM_MAP_TABLE_INCR;
      ppmm_new_table = (MemMap**) malloc(dw_new_table_sz * sizeof(MemMap*));

      if (ppmm_new_table) {
         memset(ppmm_new_table, 0, dw_new_table_sz * sizeof(MemMap*));

         if (ppmmMemoryMap) {
            memcpy(ppmm_new_table, ppmmMemoryMap,
               dwMemMapSize * sizeof(MemMap*));
            free(ppmmMemoryMap);
         }

         ppmmMemoryMap = ppmm_new_table;
         dwMemMapSize = dw_new_table_sz;
      }
      else {
         b_mem_err = true;
      }
   }

   if (!b_mem_err) {
      pmm = (MemMap*) malloc(sizeof(MemMap));

      if (pmm) {
         memset(pmm, 0, sizeof(MemMap));
         ppmmMemoryMap[dw_index] = pmm;
      }
   }

   sem_post(&sMemMutex);

   return pmm;
}

bool RemoveMemMap (const RVASMemoryHandle crmh) {
   bool b_found = false;
   u32 dw_index = 0;

   sem_wait(&sMemMutex);

   while (!b_found && (dw_index < dwMemMapSize)) {
      if (ppmmMemoryMap[dw_index] &&
         (ppmmMemoryMap[dw_index]->rmh == crmh)) {
         free(ppmmMemoryMap[dw_index]);
         ppmmMemoryMap[dw_index] = NULL;
         b_found = true;
      }
      else {
         ++dw_index;
      }
   }

   sem_post(&sMemMutex);

   return b_found;
}

RVASStatus NewContext( RVASContext* aNewContextPtr ){
	int 					iResult;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
	sem_wait(&sMutex);
   iResult = ioctl(dev_fd, CMD_IOCTL_NEW_CONTEXT, (unsigned long)&ri);
	sem_post(&sMutex);

   if( iResult != 0){
      printf("Failed to create context: %d, dev %d\n", iResult, dev_fd);
      perror("user space ioctl \n");
      return iResult;
   }

   *aNewContextPtr = ri.rc;
   return ri.rs;
}

RVASStatus DeleteContext( RVASContext aContext ){
	int 					iResult;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
   ri.rc = aContext;
   iResult = ioctl(dev_fd, CMD_IOCTL_DEL_CONTEXT, &ri);

   if( iResult != 0){
      printf("Failed to delete context: %d\n", iResult);
      return iResult;
   }
   return ri.rs;
}

RVASStatus Alloc( size_t aLengthInBytes, void** aBufferPtr, RVASMemoryHandle* aMemoryHandlePtr ){
	int iResult;
	MemMap* pmm;
	u32* dw_phys;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
   *aBufferPtr = NULL;

   /// Setup ri to pass into ioctl
   if( aLengthInBytes == 0 ){
		printf("Invalid memory allocation size %#x\n",aLengthInBytes);
		return	GenericError;
   }
   ri.req_mem_size = aLengthInBytes;
   iResult = ioctl(dev_fd, CMD_IOCTL_ALLOC, &ri);

   if (iResult != 0) {
      printf("Failed to alloc memory: %d\n", iResult);
      return iResult;
   }
   *aMemoryHandlePtr = ri.rmh;
   dw_phys = (u32*) ri.rvb.pv;

   *aBufferPtr = mmap( *aBufferPtr, ri.rvb.cb, PROT_READ | PROT_WRITE,
   	MAP_SHARED, dev_fd, ((off_t) dw_phys) & (~MEM_MAP_ADDR_MASK));

	Log("Alloc phys %p : virt %p : size %#x\n", dw_phys, *aBufferPtr, aLengthInBytes);

   if (*aBufferPtr == MAP_FAILED) {
      printf("Could not map physical address to virtual address. errno: %d\n", errno);
      perror("mmap error:");
      ri.rs = CannotMapMemory;
   }
   else {
      pmm = NewMemMap();
      Log( "pmm: %p\n", pmm );

      if (pmm) {
         pmm->rmh = ri.rmh;
         pmm->pvMemory = *aBufferPtr;
		pmm->dwLength = ri.rvb.cb;
      }
      else {
         ri.rs = MemoryAllocError;
      }
   }
   return ri.rs;
}

RVASStatus Free( RVASMemoryHandle aMemoryHandle ){
	int 					iResult;
	MemMap* pmm;
	RvasIoctl ri;
	Log("Start\n");

	memset(&ri, 0, sizeof(ri));
   pmm = GetMemMap(aMemoryHandle);

   if (!pmm) {
      return InvalidMemoryHandle;
   }

	//Log("Free virt 0x%x : size 0x%x\n", (u32)pmm->pvMemory, pmm->dwLength );

   if (munmap(pmm->pvMemory, pmm->dwLength) != 0) {
      return CannotUnMapMemory;
   }

   RemoveMemMap(aMemoryHandle);
   /// Setup ri to pass into ioctl
   ri.rmh = aMemoryHandle;
   iResult = ioctl(dev_fd, CMD_IOCTL_FREE, &ri);

   if( iResult != 0){
      printf("Failed to free memory: %d\n", iResult);
      return iResult;
   }

   return ri.rs;
}

RVASStatus LocalMonitorOn( ){
	int 					iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
   iResult = ioctl(dev_fd, CMD_IOCTL_TURN_LOCAL_MONITOR_ON, &ri);

   if( iResult != 0){
      printf("Failed to turn on local monitor: %d\n", iResult);
      return iResult;
   }
   return ri.rs;
}

RVASStatus LocalMonitorOff( ){
	int 					iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
   iResult = ioctl(dev_fd, CMD_IOCTL_TURN_LOCAL_MONITOR_OFF, &ri);

   if( iResult != 0){
      printf("Failed to turn off local monitor: %d\n", iResult);
      return iResult;
   }
   return ri.rs;
}

RVASStatus IsLocalMonitorOn( bool* pbMonitorIsOn ){
	int 					iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
   iResult = ioctl(dev_fd, CMD_IOCTL_IS_LOCAL_MONITOR_ENABLED, &ri);
   *pbMonitorIsOn = ri.lms;

   if( iResult != 0){
      printf("Failed to retrieve monitor status: %d\n", iResult);
      return iResult;
   }

   return ri.rs;
}

RVASStatus WaitForVideoEvent( RVASContext aContext, EventMap anEventMap, EventMap* aMapPtr, u32 aTimeoutInMs ){
	int 					iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
 	// in:rc, em, dw, out:em,
	ri.rc = aContext;
	ri.em = anEventMap;
	ri.time_out = aTimeoutInMs;

	Log("RVAS->WaitForVideoEvent\n");
	iResult = ioctl(dev_fd, CMD_IOCTL_WAIT_FOR_VIDEO_EVENT, &ri);
	//Log("EVENTMAP [%x]\n", *((u32*)&ri.em) );

	if( iResult != 0){
	  printf("can't WaitForVideoEvent: %d\n", iResult);
	  return iResult;
	}

   if( ri.rs == TimedOut ){
      Log("Debug: RVAS->TimedOut\n");
		*aMapPtr = ri.em;
   }
   if( ri.rs != SuccessStatus ){
      Log("WaitForVideoEvent error: %d\n", ri.rs);
      aMapPtr = NULL;
   }
   else {
	   Log( "Library: WaitForVideoEvent: ri.em=\n" );
	   display_event_map( &( ri.em ) );
	   *aMapPtr = ri.em;
	}
	return ri.rs;
}

void display_event_map( const EventMap* pem ) {
   Log( "Library EM:\n");
   Log( "*************************\n");
	Log("  bATTRChanged=      %u\n", pem->bATTRChanged);
	Log("  bCRTCChanged=      %u\n", pem->bCRTCChanged);
	Log("  bCRTCEXTChanged=   %u\n", pem->bCRTCEXTChanged);
	Log("  bDoorbellA=        %u\n", pem->bDoorbellA);
	Log("  bDoorbellB=        %u\n", pem->bDoorbellB);
	Log("  bGCTLChanged=      %u\n", pem->bGCTLChanged);
   Log( "  bGeometryChanged=  %u\n", pem->bGeometryChanged );
	Log("  bPLTRAMChanged=    %u\n", pem->bPLTRAMChanged);
	Log("  bPaletteChanged=   %u\n", pem->bPaletteChanged);
	Log("  bSEQChanged=       %u\n", pem->bSEQChanged);
   Log( "  bSnoopChanged=     %u\n", pem->bSnoopChanged );
	Log("  bTextASCIIChanged= %u\n", pem->bTextASCIIChanged);
	Log("  bTextATTRChanged=  %u\n", pem->bTextATTRChanged);
	Log("  bTextFontChanged=  %u\n", pem->bTextFontChanged);
	Log("  bXCURCOLChanged=   %u\n", pem->bXCURCOLChanged);
	Log("  bXCURCTLChanged=   %u\n", pem->bXCURCTLChanged);
	Log("  bXCURPOSChanged=   %u\n", pem->bXCURPOSChanged);
   Log( "*************************\n");
}


RVASStatus GetVideoGeometry( VideoGeometry* aGeometryPtr ){ // out:vg
	int 		iResult = SuccessStatus;
	RvasIoctl	ri;

	memset(&ri, 0, sizeof(ri));
	//Log("-----------static library------------\n");
  	memset(&ri, 0x0, sizeof(RvasIoctl));
	iResult = ioctl(dev_fd, CMD_IOCTL_GET_VIDEO_GEOMETRY, &ri);

	if( iResult != 0){
	  printf("can't GetVideoGeometry: %d\n", iResult);
	  return iResult;
	}

#if 0
	Log("GetVideoGeometry:\n");
	Log("Video geometry:\n");
	Log("++++++++++++++\n");
	Log("byBitsPerPixel:   %u\n", ri.vg.byBitsPerPixel);
	Log("gmt:              %d\n", ri.vg.gmt);
	Log("wScreenHeight:    %u\n", ri.vg.wScreenHeight);
	Log("wScreenWidth:     %u\n", ri.vg.wScreenWidth);
	Log("wStride:          %u\n", ri.vg.wStride);
	Log("++++++++++++++\n");
	Log("iResult: %d ri.rs: %d\n", iResult, ri.rs);
#endif

	if( ri.rs != SuccessStatus ){
		memset(aGeometryPtr, 0, sizeof(VideoGeometry));
	}
	else {
		memcpy(aGeometryPtr, &ri.vg, sizeof(VideoGeometry));
#if 0
		Log("w: %u\n", aGeometryPtr->wScreenWidth);
		Log("h: %u\n", aGeometryPtr->wScreenHeight);
		Log("bpp: %u\n", aGeometryPtr->byBitsPerPixel);
		Log("gmt: %d\n", aGeometryPtr->gmt);
#endif
	}

	return ri.rs;
}

RVASStatus GetGRCRegisters( RVASMemoryHandle aMemoryHandle ){
	int 					iResult = SuccessStatus;
	RvasIoctl 				ri;
	MemMap* 				pmm;

	memset(&ri, 0, sizeof(ri));
 	// in:rc, gm, out:rmh
	pmm = GetMemMap(aMemoryHandle);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
	ri.rmh = aMemoryHandle;

	iResult = ioctl(dev_fd, CMD_IOCTL_GET_GRC_REGIESTERS, &ri);

	if( iResult != 0){
	  printf("can't GetGRCRegisters: %d\n", iResult);
	  return iResult;
	}

	if( ri.rs != SuccessStatus ){
		aMemoryHandle = NULL;
	}

	return ri.rs;
}



RVASStatus ReadSnoopMap( RVASContext aContext, RVASMemoryHandle aMemoryHandle, bool bClear ){
	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandle);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
 	/// in:rc, rmh, b
	ri.rc = aContext;
	ri.rmh = aMemoryHandle;
	ri.flag = bClear;

	iResult = ioctl(dev_fd, CMD_IOCTL_READ_SNOOP_MAP, &ri);

	if( iResult != 0){
	  printf("can't ReadSnoopMap: %d\n", iResult);
	  return iResult;
	}

	return ri.rs;
}

RVASStatus ReadSnoopAggregate( RVASContext aContext, SnoopAggregate* anAggregatePtr, bool bClear ){
	int 					iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
 	// in:rc, b, out:sa
	ri.rc = aContext;
	ri.flag = bClear;

	iResult = ioctl(dev_fd, CMD_IOCTL_READ_SNOOP_AGGREGATE, &ri);

	if( iResult != 0){
	  printf("can't ReadSnoopAggregate: %d\n", iResult);
	  return iResult;
	}

	if( ri.rs != SuccessStatus ){
		anAggregatePtr = NULL;
	}
	else {
		memcpy(anAggregatePtr, &ri.sa, sizeof(SnoopAggregate));
	}
	return ri.rs;
}

//
// Fetch Video
//

RVASStatus FetchVideoTiles( RVASContext rc, RVASMemoryHandle aMemoryHandleFVTA, RVASMemoryHandle aMemoryHandleOut,
   RVASMemoryHandle aMemoryHandleTemp ) {
	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandleFVTA);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
    // in:rmh(descriptors), rmh2(video data out)
    ri.rc = rc;
	ri.rmh = aMemoryHandleFVTA;
	ri.rmh1 = aMemoryHandleOut;
	ri.rmh2 = aMemoryHandleTemp;
	Log("Calling...\n");

	iResult = ioctl(dev_fd, CMD_IOCTL_FETCH_VIDEO_TILES, &ri);

	if( iResult != 0){
	  printf("can't FetchVideoTiles: %d\n", iResult);
	  return iResult;
	}
	return ri.rs;
}


RVASStatus FetchVideoSlices(RVASContext rc, RVASMemoryHandle aMemoryHandleFSA,
    RVASMemoryHandle aMemoryHandleNonRLE, RVASMemoryHandle aMemoryHandleRLE)
{

	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandleFSA);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
   // in:rmh(descriptors), rmh2(video data out), out:dw(checksum), dw1(rle count)
	ri.rc = rc;
	ri.rmh = aMemoryHandleFSA;
	ri.rmh1 = aMemoryHandleNonRLE;
	ri.rmh2 = aMemoryHandleRLE;
	Log("Calling...\n");

	iResult = ioctl(dev_fd, CMD_IOCTL_FETCH_VIDEO_SLICES, &ri);

	if( iResult != 0){
	  printf("can't FetchVideoSlices: %d\n", iResult);
	  return iResult;
	}
	return ri.rs;
}



RVASStatus RunLengthEncode( RVASMemoryHandle aMemoryHandleIn, RVASMemoryHandle aMemoryHandleOut, u8  byRLETripletCode,  u8  byRLERepeatCode, u32* aRLECountPtr, u32* aCheckSumPtr ){
	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandleIn);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
   // in:rmh, rmh1, dw (repeat code), out:dw1, dw2
	ri.rmh = aMemoryHandleIn;
	ri.rmh1 = aMemoryHandleOut;
	ri.encode = (byRLETripletCode<<24)|(byRLERepeatCode<<16);

	iResult = ioctl(dev_fd, CMD_IOCTL_RUN_LENGTH_ENCODE_DATA, &ri);
	if( iResult != 0){
	  printf("can't RunLengthEncode: %d\n", iResult);
	  return iResult;
	}
	if( ri.rs != SuccessStatus ){
		aRLECountPtr = NULL;
		aMemoryHandleOut = NULL;
		aMemoryHandleIn = NULL;
	}
	else {
		*aCheckSumPtr = ri.rle_checksum;
		*aRLECountPtr = ri.rle_len;
	}
	return ri.rs;
}


RVASStatus FetchTextData(RVASContext rc, VideoGeometry aGeometry,
    FetchMap *paTextMap, RVASMemoryHandle aMemoryHandleNonRLE,
    RVASMemoryHandle aMemoryHandleRLE)
{
	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandleNonRLE);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
   // in:vg, tfm, rmh, out:dw
	ri.rc = rc;
	ri.vg = aGeometry;
	memcpy(&ri.tfm, paTextMap,sizeof(FetchMap) );
	ri.rmh = aMemoryHandleNonRLE;
	ri.rmh1 = aMemoryHandleRLE;


	iResult = ioctl(dev_fd, CMD_IOCTL_FETCH_TEXT_DATA, &ri);

	if( iResult != 0){
	  printf("can't FetchTextData: %d\n", iResult);
	  return iResult;
	}else{
		paTextMap->dwFetchSize = ri.tfm.dwFetchSize;
		paTextMap->dwFetchRLESize = ri.tfm.dwFetchRLESize;
		paTextMap->dwCheckSum = ri.tfm.dwCheckSum;
		paTextMap->bRLEFailed = ri.tfm.bRLEFailed;
	}
	return ri.rs;
}


RVASStatus FetchVGAGraphicsData(RVASContext rc, VideoGeometry aGeometry,
    FetchMap *paVideoMap, RVASMemoryHandle aMemoryHandleNonRLE,
    RVASMemoryHandle aMemoryHandleRLE)
{
	int 		iResult = SuccessStatus;
	RvasIoctl 	ri;
	MemMap* 	pmm;

	memset(&ri, 0, sizeof(ri));
	pmm = GetMemMap(aMemoryHandleNonRLE);

	if (!pmm) {
		return InvalidMemoryHandle;
	}
	ri.rmh_mem_size = pmm->dwLength;
	// in:vg, tfm, rmh, out:dw
	ri.rc = rc;
	ri.vg = aGeometry;
	//ri.tfm = aVideoMap;
	memcpy(&ri.tfm, paVideoMap,sizeof(FetchMap) );
	ri.rmh = aMemoryHandleNonRLE;
	ri.rmh1 = aMemoryHandleRLE;

	iResult = ioctl(dev_fd, CMD_IOCTL_FETCH_MODE13_DATA, &ri);
	if( iResult != 0){
	  printf("can't FetchTextData: %d\n", iResult);
	  return iResult;
	}else{
		paVideoMap->dwFetchSize = ri.tfm.dwFetchSize;
		paVideoMap->dwFetchRLESize = ri.tfm.dwFetchRLESize;
		paVideoMap->dwCheckSum = ri.tfm.dwCheckSum;
		paVideoMap->bRLEFailed = ri.tfm.bRLEFailed;
		memcpy(paVideoMap, &ri.tfm, sizeof(FetchMap) );
	}
	return ri.rs;
}


// Set Tile Snoop Interrupt Count Register (TSICR)
RVASStatus SetTSECounter(u32 value)
{
	int iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
	ri.tse_counter = value;
	iResult = ioctl(dev_fd, CMD_IOCTL_SET_TSE_COUNTER, &ri);

	if (iResult != 0) {
		printf("can't SetTSECounter: %d\n", iResult);
		return iResult;
	}

	return ri.rs;
}

// Get Tile Snoop Interrupt Count Register (TSICR)
u32 GetTSECounter(void)
{
	int iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
	iResult = ioctl(dev_fd, CMD_IOCTL_GET_TSE_COUNTER, &ri);

	if ((iResult != 0) || (ri.rs != SuccessStatus)) {
		printf("can't GetTSECounter: %d rs: %d\n", iResult, ri.rs);
		return 0;
	}
	return ri.tse_counter;
}

// Reset the Video Engine
RVASStatus ResetVideoEngine(ResetEngineMode resetMode)
{
	int iResult = SuccessStatus;
	RvasIoctl ri;

	memset(&ri, 0, sizeof(ri));
	ri.resetMode = resetMode;
	iResult = ioctl(dev_fd, CMD_IOCTL_VIDEO_ENGINE_RESET, &ri);

	if (iResult != 0) {
		printf("can't ResetVideoEngine: %d\n", iResult);
		return iResult;
	}

	return ri.rs;
}

// Get the Video Engine Config
RVASStatus GetVideoEngineConfig(VideoConfig* ast_config){
	int iResult = SuccessStatus;
	RVASStatus rs;

	iResult = ioctl(dev_fd, CMD_IOCTL_GET_VIDEO_ENGINE_CONFIG, ast_config);

	rs = ast_config->rs;

	if (iResult != 0) {
		printf("can't GetVideoEngineConfig: %d\n", iResult);
		return iResult;
	}

	return rs;
}

// Set the Video Engine Config
RVASStatus SetVideoEngineConfig(const VideoConfig* ast_config) {
	int iResult = SuccessStatus;
	RVASStatus rs;


	iResult = ioctl(dev_fd, CMD_IOCTL_SET_VIDEO_ENGINE_CONFIG, ast_config);

	rs = ast_config->rs;

	if (iResult != 0) {
		printf("can't SetVideoEngineConfig: %d\n", iResult);
		return iResult;
	}

	return rs;
}

// Get the Video Engine Data
RVASStatus GetVideoEngineJPEGData(MultiJpegConfig*  ast_multi) {
	int iResult = SuccessStatus;
	RVASStatus rs;

	iResult = ioctl(dev_fd, CMD_IOCTL_GET_VIDEO_ENGINE_DATA, ast_multi);

	rs = ast_multi->rs;

	if (iResult != 0) {
		printf("can't GetVideoEngineJPEGData: %d\n", iResult);
		return iResult;
	}

	return rs;
}

