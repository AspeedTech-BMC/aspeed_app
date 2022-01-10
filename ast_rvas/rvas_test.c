// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2021 Aspeed Technology Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>

#include "rvas.h"

static const char Copyright[] = "Copyright (c) 2010-2027 ASPEED Technology. All rights reserved.";

//#define TEST_MONITOR_STATUS
//#define TEST_WAIT_FOR_VIDEO_EVENT
#define TEST_SNOOP
//#define TEST_TSE_COUNTER

typedef enum tagTestState {
   TS_SNOOPMAP_NO_CLEAR = 0,
   TS_SNOOPMAP_CLEAR = 1,
   TS_SNOOP_AGGREGATE_NO_CLEAR = 2,
   TS_SNOOP_AGGREGATE_CLEAR = 3,
   TS_MEMORY = 4,
   TS_RESET = 5,
   TS_TERMINATE = 6,
} TestState;

#define TIME_LIMIT_IN_SECS (10)
#define BILLION (1000000000)

const char szLogFile[] = "";

void time_diff(const struct timespec* start, const struct timespec* end,
        struct timespec* res);
int main (int, char**);

void time_diff(const struct timespec* start, const struct timespec* end,
        struct timespec* res)
{
	if ((end->tv_nsec - start->tv_nsec) < 0) {
		res->tv_sec = end->tv_sec - start->tv_sec - 1;
		res->tv_nsec = BILLION + end->tv_nsec - start->tv_nsec;
	} else {
		res->tv_sec = end->tv_sec - start->tv_sec;
		res->tv_nsec = end->tv_nsec - start->tv_nsec;
	}
}

int main (int argc, char** argv) {
   u64* pqw_snoop_map = NULL;
   u32 dw_iter;
   RVASStatus rs;
   RVASContext rc;
   void* pv_buf = NULL;
   void* pv_buf_mem;
   RVASMemoryHandle rmh;
   RVASMemoryHandle rmh_mem;
   SnoopAggregate sa;
   u32 dw_allocate_sz;
   u32 dw_set_val;
   u32 dw_mem_disp_sz;
	u32 dw_sz = 0x500000;
   TestState ts_state;
   bool b_clear;
#if defined(TEST_MONITOR_STATUS) || defined(TEST_WAIT_FOR_VIDEO_EVENT)
   int command = 0;
#endif

   // Testing Wait For Video Event
#ifdef TEST_TSE_COUNTER
   u32 dw_frame_ct;
   u32 dw_tse_counter;
   float f_avg_frames;
   u32 time_to_run_secs = TIME_LIMIT_IN_SECS;
   EventMap    anEm;
   EventMap    receivedEM;
   u32       dwTimeoutInMs=1000;
	struct timespec start_time;
	struct timespec end_time;
	struct timespec res_time;
#endif
#ifdef TEST_WAIT_FOR_VIDEO_EVENT
   u32       dwMask = 0;
#endif
   // Testing Wait For Video Event

   printf("%s\n", Copyright);
	Log("Opening log...\n");
   if (!OpenLog(szLogFile)) {
      printf("Failed to start logging\n");
      return EXIT_FAILURE;
   }

   Log("Start of RVAS test\n");
   rs = Initialize();
	Log("After Initialize\n");

   if (rs != SuccessStatus) {
      Log("Initialized RVAS failed: %d\n", rs);
      return EXIT_FAILURE;
   }

   Log("Initialized RVAS session\n");
   rs = NewContext(&rc);

   if (rs != SuccessStatus) {
      Log("Getting new context failed: %d\n", rs);
      return EXIT_FAILURE;
   }

   Log("Got RVAS context. rc: 0x%8.8x\n", (u32) rc);
   rs = Alloc(dw_sz, &pv_buf, &rmh);

   if (rs != SuccessStatus) {
      Log("Allocating memory failed: %d\n", rs);
      return EXIT_FAILURE;
   }
#ifdef TEST_SNOOP
   pqw_snoop_map = (u64*) pv_buf;
   Log("Got Memory handle. rmh: 0x%8.8x pqw_snoop_map: 0x%8.8x\n", (u32) rmh,
      (u32) pqw_snoop_map);

   do {
      Log("\nTest Options:\n");
      Log("   0 - SnoopMap (no clear)           1 - SnoopMap (clear)\n");
      Log("   2 - SnoopAggregate (no clear)     3 - SnoopAggregate (clear)\n");
      Log("   4 - Memory                        5 - Reset RVAS Driver\n");
      Log("   <Any Other> - Quit\n");
      scanf("%d", (int*) &ts_state);

      switch (ts_state) {
         case TS_SNOOPMAP_NO_CLEAR:
         case TS_SNOOPMAP_CLEAR:
            b_clear = ts_state == TS_SNOOPMAP_CLEAR;

            if (b_clear) {
               Log("Clear SnoopMap: true\n");
            }
            else {
               Log("Clear SnoopMap: false\n");
            }

            rs = ReadSnoopMap(rc, rmh, b_clear);

            if (rs != SuccessStatus) {
               Log("Reading SnoopMap failed: %d\n", rs);
               return EXIT_FAILURE;
            }

            for (dw_iter = 0; dw_iter < 64; ++dw_iter) {
               Log("SnoopMap[%u]: 0x%16.16llx\n", dw_iter,
                  pqw_snoop_map[dw_iter]);
            }
            break;

         case TS_SNOOP_AGGREGATE_NO_CLEAR:
         case TS_SNOOP_AGGREGATE_CLEAR:
            b_clear = ts_state == TS_SNOOP_AGGREGATE_CLEAR;

            if (b_clear) {
               Log("Clear SnoopAggregate: true\n");
            }
            else {
               Log("Clear SnoopAggregate: false\n");
            }

            rs = ReadSnoopAggregate(rc, &sa, b_clear);

            if (rs != SuccessStatus) {
               Log("Reading SnoopAggregate failed: %d\n", rs);
               return EXIT_FAILURE;
            }

            Log("SnoopAggregate rows: 0x%16.16llx\n", sa.qwRow);
            Log("SnoopAggregate cols: 0x%16.16llx\n", sa.qwCol);
            break;

         case TS_MEMORY:
            pv_buf_mem = NULL;
            Log("Enter number of bytes to allocate\n");
            Log("Enter value to set\n");
            Log("[Bytes] [Set]\n");
            scanf("%u %u", &dw_allocate_sz, &dw_set_val);
            dw_set_val &= 0xff;
            dw_mem_disp_sz = dw_allocate_sz < 16 ? dw_allocate_sz : 16;
            Log("Allocating %u bytes with set value: %u (0x%2.2x)\n",
               dw_allocate_sz, dw_set_val, dw_set_val);
            rs = Alloc(dw_allocate_sz, &pv_buf_mem, &rmh_mem);

            if (rs != SuccessStatus) {
               Log("Allocating memory failed: %d\n", rs);
               return EXIT_FAILURE;
            }

            Log("Got Memory handle. rmh_mem: 0x%8.8x pv_buf_mem: 0x%8.8x\n",
               (u32) rmh_mem, (u32) pv_buf_mem);
            Log("\nMemory Before:\n");
            DisplayBuffer(pv_buf_mem, dw_mem_disp_sz);
            memset(pv_buf_mem, dw_set_val, dw_allocate_sz);
            Log("\nMemory After:\n");
            DisplayBuffer(pv_buf_mem, dw_mem_disp_sz);
            rs = Free(rmh_mem);

            if (rs != SuccessStatus) {
               Log("Freeing memory failed: %d\n", rs);
               return EXIT_FAILURE;
            }
            break;
         case TS_RESET:
            Log("Reseting RVAS Driver...\n");
            ResetVideoEngine(ResetRvasEngine);
            Log("Reset complete for RVAS Driver\n");
            break;
         default:
            ts_state = TS_TERMINATE;
            break;
      }
   } while (ts_state != TS_TERMINATE);
#endif
#if 1
   rs = Free(rmh);

   if (rs != SuccessStatus) {
      Log("Freeing memory failed: %d\n", rs);
      return EXIT_FAILURE;
   }
#endif
   Log("Freed the Memory handle.\n");

#ifdef TEST_MONITOR_STATUS
   printf("Test monitor on/off\n");

   while( command<3 ){
	   printf("Enter 0-off, 1-on, 2-status, 3-exit test\n");
	   scanf("%d", &command);
	   switch( command ){
		case 0:
	 		printf("turn off local monitor\n");
	   		rs = LocalMonitorOff( );
			if (rs != SuccessStatus) {
			  Log("LocalMonitorOff failed: %d\n", rs);
			  return EXIT_FAILURE;
		    }
		    break;
		case 1:
			printf("turn on local monitor\n");
		    rs = LocalMonitorOn( );
			if (rs != SuccessStatus) {
			  Log("LocalMonitorOn failed: %d\n", rs);
			  return EXIT_FAILURE;
		    }
		    break;
		case 2:
			{
				bool bLocalMonitorOn = false;
		    	printf("get local monitor status\n");
				rs = IsLocalMonitorOn(&bLocalMonitorOn);
		    	if( rs == SuccessStatus ){
		       		if( bLocalMonitorOn ){
						printf("Local monitor setting is ON\n");
					}
					else{
						printf("Local monitor setting is OFF\n");
					}
				}else{
					Log("IsLocalMonitorOn failed: %d\n", rs);
			  		return EXIT_FAILURE;
				}
			}
			break;
		default:
			break;
		}
	}
#endif
#ifdef TEST_WAIT_FOR_VIDEO_EVENT
   printf("Testing Wait for Video Event\n");
   memset( &anEm, 0x0, sizeof(EventMap) );
   rs = TimedOut;
   dwTimeoutInMs = 5000;


   while(command<5){
      printf("Enter Command\n");
		printf("Enter 0 to retrieve changes without waiting\n");
		printf("Enter 1 to wait for event with 1 second timeout\n");
      printf("Enter 2 to set Event Map\n");
      printf("Enter 3 to set timeout value\n");
      printf("Enter 4 to print out Event Map and Returned Event Map\n");
      scanf("%d", &command);
      switch(command){
         case 0:
            rs = WaitForVideoEvent( rc, anEm, &receivedEM, 0 );
            Log("Status:[%d]\n", rs);
            break;
         case 1:
            {
               bool bModeStable = false;
               while( !bModeStable ) { // Assume mode is unstable and wait for event will determine if stable
                  rs = WaitForVideoEvent( rc, anEm, &receivedEM, 10000 );
                  printf("Event Map Received[%#x]\n", receivedEM);
                  if( !receivedEM.bGeometryChanged )
                     bModeStable = true;
               }
            }
            Log("Status:[%d]\n", rs);
            break;
         case 2:
            printf("Enter mask in 4 byte hex format:");
            scanf("%x", &dwMask);
            printf("dwMask[%#x]\n", dwMask);
            memcpy( (void*)&anEm, (void*)&dwMask, sizeof(dwMask) );
            break;
         case 3:
            printf("Enter timeout value in ms:");
            scanf("%u", &dwTimeoutInMs);
            printf("Timeout value in ms: %u\n", dwTimeoutInMs);
            break;
         case 4:
            Log("Event Map Sent To Wait for Video Event\n");
            Log("bPaletteChanged [%d]\n", anEm.bPaletteChanged);
            Log("bATTRChanged [%d]\n", anEm.bATTRChanged);
            Log("bSEQChanged [%d]\n", anEm.bSEQChanged);
            Log("bGCTLChanged [%d]\n", anEm.bGCTLChanged);
            Log("bGeometryChanged [%d]\n", anEm.bCRTCChanged);
            Log("bCRTCEXTChanged [%d]\n", anEm.bCRTCEXTChanged);
            Log("bPLTRAMChanged [%d]\n", anEm.bPLTRAMChanged);
            Log("bXCURCOLChanged [%d]\n", anEm.bXCURCOLChanged);
            Log("bXCURCTLChanged [%d]\n", anEm.bXCURCTLChanged);
            Log("bXCURPOSChanged [%d]\n", anEm.bXCURPOSChanged);
            Log("bDoorbellA [%d]\n", anEm.bDoorbellA);
            Log("bDoorbellB [%d]\n", anEm.bDoorbellB);
            Log("bGeometryChanged [%d]\n", anEm.bGeometryChanged);
            Log("bSnoopChanged [%d]\n", anEm.bSnoopChanged);
            Log("bTextFontChanged [%d]\n", anEm.bTextFontChanged);
            Log("bTextATTRChanged [%d]\n", anEm.bTextATTRChanged);
            Log("bTextASCIIChanged [%d]\n", anEm.bTextASCIIChanged);

            if ( rs == SuccessStatus ) {
                  Log("\nEvent Map returned from Wait for Video Event\n");
                  Log("bPaletteChanged [%d]\n", receivedEM.bPaletteChanged);
                  Log("bATTRChanged [%d]\n", receivedEM.bATTRChanged);
                  Log("bSEQChanged [%d]\n", receivedEM.bSEQChanged);
                  Log("bGCTLChanged [%d]\n", receivedEM.bGCTLChanged);
                  Log("bGeometryChanged [%d]\n", receivedEM.bCRTCChanged);
                  Log("bCRTCEXTChanged [%d]\n", receivedEM.bCRTCEXTChanged);
                  Log("bPLTRAMChanged [%d]\n", receivedEM.bPLTRAMChanged);
                  Log("bXCURCOLChanged [%d]\n", receivedEM.bXCURCOLChanged);
                  Log("bXCURCTLChanged [%d]\n", receivedEM.bXCURCTLChanged);
                  Log("bXCURPOSChanged [%d]\n", receivedEM.bXCURPOSChanged);
                  Log("bDoorbellA [%d]\n", receivedEM.bDoorbellA);
                  Log("bDoorbellB [%d]\n", receivedEM.bDoorbellB);
                  Log("bGeometryChanged [%d]\n", receivedEM.bGeometryChanged);
                  Log("bSnoopChanged [%d]\n", receivedEM.bSnoopChanged);
                  Log("bTextFontChanged [%d]\n", receivedEM.bTextFontChanged);
                  Log("bTextATTRChanged [%d]\n", receivedEM.bTextATTRChanged);
                  Log("bTextASCIIChanged [%d]\n", receivedEM.bTextASCIIChanged);
                  memset(&receivedEM, 0x0, sizeof(EventMap));
            }
            else if( rs == TimedOut ){
               Log("Timed out\n");
            }
            else {
               Log("WaitForVideoEvent failed\n");
            }
            break;
      }
   }
#endif
#ifdef TEST_TSE_COUNTER
	printf("Testing TSE Counter\n");
	memset(&anEm, 0x0, sizeof(EventMap));
	memset(&receivedEM, 0x0, sizeof(EventMap));
	anEm.bSnoopChanged = 1;
	rs = TimedOut;
	dwTimeoutInMs = 10;
	dw_tse_counter = 0;
	time_to_run_secs = TIME_LIMIT_IN_SECS;
	printf(
	        "Enter TSE Counter Amount in Hex. Time in ms in digits. Time to run in seconds. Enter 0 0 0 to stop.\n");
	scanf("%x %u %u", &dw_tse_counter, &dwTimeoutInMs, &time_to_run_secs);

	while (dw_tse_counter) {
		clock_gettime(CLOCK_REALTIME, &start_time);
		dw_frame_ct = 0;
		rs = SetTSECounter(dw_tse_counter);

		if (rs != SuccessStatus) {
			printf("Unable to set the TSE Counter.\n");
			return EXIT_FAILURE;
		}

		do {
			rs = WaitForVideoEvent(rc, anEm, &receivedEM,
			        dwTimeoutInMs);

			if (rs == SuccessStatus) {
				if (receivedEM.bSnoopChanged) {
					++dw_frame_ct;
				}
			}
			else if (rs == TimedOut) {
				// Do nothing without timed out status
			} else {
				printf("WaitForVideoEvent failed rs: %d\n", rs);
				return EXIT_FAILURE;
			}

			clock_gettime(CLOCK_REALTIME, &end_time);
			time_diff(&start_time, &end_time, &res_time);
		} while (res_time.tv_sec < time_to_run_secs);

		f_avg_frames = (float) dw_frame_ct / (float) time_to_run_secs;
		printf(
		        "Average Frame Per Second: %f Frame Count: %u Time: %u Timed Out ms: %u TSE Counter: %#x\n",
		        f_avg_frames, dw_frame_ct, time_to_run_secs,
		        dwTimeoutInMs, dw_tse_counter);
		printf(
		        "Enter TSE Counter Amount in Hex. Time in ms in digits. Time to run in seconds. Enter 0 0 0 to stop.\n");
		scanf("%x %u %u", &dw_tse_counter, &dwTimeoutInMs,
		        &time_to_run_secs);
	}
#endif

   rs = DeleteContext(rc);

   if (rs != SuccessStatus) {
      Log("Deleting context failed: %d\n", rs);
      return EXIT_FAILURE;
   }

   Log("Deleted RVAS context\n");
   rs = Shutdown();

   if (rs != SuccessStatus) {
      Log("Shutdown RVAS failed: %d\n", rs);
      return EXIT_FAILURE;
   }

   Log("End of RVAS test\n");
   CloseLog();

   return EXIT_SUCCESS;
}
