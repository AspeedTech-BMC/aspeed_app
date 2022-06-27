// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2021 Aspeed Technology Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sem.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <semaphore.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

#include "rvas.h"

#define REPEAT_CODE (0xAA)
#define TRIPLET_CODE (0x55)

#define MAX_TEXT_DATA_SIZE			(8192)

void testVideoGeometry( void );

static const char Copyright[ ] = "Copyright (c) 2019-2021 ASPEED Technology Inc. All rights reserved.";

#define Test_testTextMode
#define Test_testSnoopMap
#define Test_testGRCERegister
#define Test_testVideoFetchMode
#define Test_testVideoSlicing
#define Test_testVideoJPEG

#ifdef Test_testTextMode
int testTextMode( void );
#endif

#ifdef Test_testGRCERegister
int testGRCERegister( void );
#endif

#ifdef Test_testSnoopMap
int testSnoopMap( void );
#endif

#ifdef Test_testVideoFetchMode
int testVideoFetchMode( void );
#endif

#ifdef Test_testVideoSlicing
int testVideoSlicing( void );
int testMultiVideoSlicing( void );
#endif

#ifdef Test_testTFEEncoding
int testTFEEncoding( void );
#endif

#ifdef Test_testVideoJPEG
int testVideoJPEG( void );
#endif

int testMode13( void );

int main( void ) {
	int iResult = EXIT_SUCCESS;
	VideoGeometry aGeometryPtr;
	int command = 0;
	RVASStatus rs;
	printf( "%s\n", Copyright );

	rs = Initialize( );

	if ( rs != SuccessStatus ) {
		printf( "Failed to Initialize RVAS: %d\n", rs );
		return EXIT_FAILURE;
	}

	//
	//testVideoGeometry();

	//printf("CAll video geometry RVAS\n");
	rs = GetVideoGeometry( &aGeometryPtr );

	if ( rs != SuccessStatus ) {
		printf( "Failed to get Video Geometry: %d\n", rs );
		return EXIT_FAILURE;
	}

	printf( "ri.vg.wScreenWidth: %d\n", aGeometryPtr.wScreenWidth );
	printf( "ri.vg.wScreenHeight: %d\n", aGeometryPtr.wScreenHeight );
	printf( "ri.vg.byBitsPerPixel: %d\n", aGeometryPtr.byBitsPerPixel );
	printf( "ri.vg.byModeID: %d\n", aGeometryPtr.byModeID );
	printf( "ri.vg.gmt: %d\n", aGeometryPtr.gmt );
	printf( "ri.vg.wStride: %d\n", aGeometryPtr.wStride );

	while ( command < 7 ) {
		printf(
		   "Enter 0 - GRCE, 1 - TEXT Mode\n2 - MGA: Fetch, 3 - MGA: Single SLICING\n4 - VGA Graphic mode(Mode 13),"
		   " 5 - Encoding Fetch\n6 - Multiple BSE Frames\n"
		   "7 - Multi-Jpeg \nAnything else to exit\n" );
		scanf( "%d", &command );
		switch ( command ) {
			case 0:
				printf( "TEST::********Test GRC**********\n" );
				testGRCERegister( );
				printf( "TEST::End GRCE test\n" );
				break;
			case 1:
				printf( "TEST::********Test text mode**********\n" );
				if ( aGeometryPtr.gmt == TextMode ) {
					printf( "In TEXT MODE\n" );
					testTextMode( );
				}
				break;
			case 2:
				printf( "TEST::********Test MGA - FETCH**********\n" );
				if ( aGeometryPtr.gmt == AGAGraphicsMode ) {
					printf( "In MGA GRAPHIC MODE\n" );
					testVideoFetchMode( );
					printf( "TEST::End FETCH test\n" );
				}
				break;
			case 3:
				printf( "TEST::********Test MGA - SLICING**********\n" );
				if ( aGeometryPtr.gmt == AGAGraphicsMode ) {
					printf( "In MGA GRAPHIC MODE\n" );
					testVideoSlicing( );
					printf( "TEST::End SLICING test\n" );
				}
				break;
			case 4:
				printf( "TEST::********Test vga graphics mode mode 13**********\n" );
				if ( aGeometryPtr.gmt == VGAGraphicsMode ) {
					printf( "In VGA GRAPHIC MODE\n" );
					testMode13( );
				}
				break;
			case 5:
				printf( "TEST::********Fetch encoding**********\n" );

				///testTFEEncoding();
				break;
			case 6:
				if ( aGeometryPtr.gmt == AGAGraphicsMode ) {
					printf( "In MGA GRAPHIC MODE\n" );
					testMultiVideoSlicing( );
					printf( "TEST::End Multiple SLICING test\n" );
				}
				break;
			case 7:
				if ( aGeometryPtr.gmt == AGAGraphicsMode ) {
					printf( "In MGA GRAPHIC MODE: JPEG test\n" );
					testVideoJPEG( );
					printf( "TEST::End Multiple JPEG compression test\n" );
				}
				break;
			default:
				printf( "EXIT!!\n" );
				break;
		} // switch
	}	// while

	printf( "TEST::********before shutdown**********\n" );
	Shutdown( );
	printf( "TEST::Exit App\n" );

	return iResult;
}

void testVideoGeometry( void ) {
	VideoGeometry aGeometryPtr;
	printf( "CAll video geometry RVAS\n" );
	GetVideoGeometry( &aGeometryPtr );

	printf( "ri.vg.wScreenWidth: %d\n", aGeometryPtr.wScreenWidth );
	printf( "ri.vg.wScreenHeight: %d\n", aGeometryPtr.wScreenHeight );
	printf( "ri.vg.byBitsPerPixel: %d\n", aGeometryPtr.byBitsPerPixel );
}

#ifdef Test_testTextMode
int testTextMode( void ) {
	int iResult = 0;

	int iter;
	FetchMap tfm;
	VideoGeometry aGeometry;
	u32* pdwlocalBuffer;
	u32* pdwlocalBufferRLE;
	RVASMemoryHandle mhLB = 0;
	RVASMemoryHandle mhLBRLE = 0;
	u32 dwSize = MAX_TEXT_DATA_SIZE;
	u32 dwRLE = 0;
	RVASStatus rs;
	RVASContext rc;

	rs = NewContext( &rc );

	if ( rs != SuccessStatus ) {
		printf( "Getting new context failed: %d\n", rs );
		return EXIT_FAILURE;
	}

	GetVideoGeometry( &aGeometry );

	tfm.bEnableRLE = 0;
	tfm.byRLETripletCode = 0x00;
	tfm.byRLERepeatCode = 0x00;

	printf( "Please enter 0-disable RLE,1-enable RLE\n" );
	scanf( "%d", &dwRLE );
	if ( dwRLE ) {
		tfm.bEnableRLE = 1;
		tfm.byRLETripletCode = TRIPLET_CODE;
		tfm.byRLERepeatCode = REPEAT_CODE;
	}

	rs = Alloc( dwSize, (void*) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLB );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for TFE Fetch Text: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	if ( tfm.bEnableRLE ) {
		rs = Alloc( dwSize, (void*) &pdwlocalBufferRLE, (RVASMemoryHandle*) &mhLBRLE );

		if ( rs != SuccessStatus ) {
			printf( "Allocating memory failed for TFE RLE Text: %d\n", rs );
			exit( EXIT_FAILURE );
		}
	}
	printf( "\n\nIt's text mode!\n" );
	{
		int command = 0;
		printf( "Please enter 0-Attr Ascii,1-Font,2-Acsii only,other-exit this test\n" );
		scanf( "%d", &command );
		switch ( command ) {
			case 0:
				tfm.dpm = AttrMode;
				printf( "-------------Fetch text mode Attr ----------\n" );
				break;
			case 1:
				tfm.dpm = FontFetchMode;
				printf( "-------------Fetch text mode Font-----------\n" );
				break;
			case 2:
				tfm.dpm = AsciiOnlyMode;
				printf( "-------------Fetch text Ascii only-----------\n" );
				break;
			default:
				break;
		}
	}
	FetchTextData( rc, aGeometry, &tfm, mhLB, mhLBRLE );
	if ( tfm.bEnableRLE && !tfm.bRLEFailed ) {
		printf( "-------RLE data--------\n" );
		for ( iter = 0; iter < ( ( tfm.dwFetchRLESize + 3 ) >> 2 ); iter++ ) {
			printf( "0x%x, ", pdwlocalBufferRLE[ iter ] );
			if ( ( iter % 4 ) == 0 )
				printf( "\n" );
		}
	} else {

		printf( "-------Non RLE data--------\n" );
		printf( "-------Fetch size %d--------\n", tfm.dwFetchSize );
		for ( iter = 0; iter < ( tfm.dwFetchSize >> 2 ); iter++ ) {
			printf( "0x%x, ", pdwlocalBuffer[ iter ] );
			if ( ( iter % 4 ) == 0 )
				printf( "\n" );
		}
	}

	Free( mhLB );
	Free( mhLBRLE );
	rs = DeleteContext( rc );

	if ( rs != SuccessStatus ) {
		printf( "Deleting context failed: %d\n", rs );
		return EXIT_FAILURE;
	}

	printf( "Deleted RVAS context\n" );
	rs = Shutdown( );

	if ( rs != SuccessStatus ) {
		printf( "Shutdown RVAS failed: %d\n", rs );
		return EXIT_FAILURE;
	}

	return iResult;
}
#endif

//
//
//
#ifdef Test_testTFEEncoding
int testTFEEncoding( void ) {
	int iResult = 0;
	int iter;
	u32 dwCheckSum = 0;
	u32 dwRLECount = 0;
	u32* pdwlocalBuffer;
	u32* pdwlocalBufferRLE;
	RVASMemoryHandle mhLBIn;
	RVASMemoryHandle mhLBRLE;
	u32 dw_sz = 0x1000;

	Alloc( dw_sz, (void*)&pdwlocalBuffer, (RVASMemoryHandle*)&mhLBIn);
	Alloc( dw_sz, (void*)&pdwlocalBufferRLE, (RVASMemoryHandle*)&mhLBRLE);
	printf("\n\nTest Fetch Encoding\n");

	memset((void*)pdwlocalBuffer, 0x11, 0x500);
	memset((void*)(pdwlocalBuffer+0x140), 0x22, 0x500);

	RunLengthEncode( mhLBIn, mhLBRLE, 0x55, 0xaa, &dwRLECount, &dwCheckSum );

	printf("RLE COUNT: %d\n", dwRLECount );
	printf("Checksum: %d \n", dwCheckSum );
	printf("-----------------data----------------\n");
	for( iter = 0; iter< (dw_sz>>2); iter++ ) {
		printf("0x%x, ", pdwlocalBuffer[iter]);
		if((iter%16) == 0 )
		printf("\n");
	}
	printf("\n------RLE DATA------n");

	for( iter = 0; iter< (dwRLECount>>2); iter++ ) {
		printf("0x%x, ", pdwlocalBufferRLE[iter]);
		if((iter%16) == 0 )
		printf("\n");
	}

	printf("-----------------END data-------------\n");

	Free(mhLBIn);
	Free(mhLBRLE);
	return iResult;
}
#endif
//
//
//
#define RLE
#define SKIP

#ifdef Test_testVideoFetchMode
int testVideoFetchMode( void ) {

	int iResult = 0;
	int iter;
	FetchVideoTilesArg* pfvt = NULL;

	// FetchOperation				fo[2];
	// u32							dwCheckSum = 0;
	// u32							dwRLECount = 0;
	// u32							dwNonRLECount = 0;
	u32* pdwlocalBuffer = NULL;
	u32* pdwTmpBuffer = NULL;

	RVASMemoryHandle mhLBFVTA = NULL;
	RVASMemoryHandle mhLBOut = NULL;
	RVASMemoryHandle mhLBTmp = NULL;

	// int 							mem_handle_cached;
	// u32*				   	pdwVirtAddr = NULL;
	u32 dw_sz = 4096 * 3;
	RVASStatus rs;
	RVASContext rc = NULL;

	printf( "\n\nTEST FETCH::Fetching...!\n" );

	rs = NewContext( &rc );

	if ( rs != SuccessStatus ) {
		printf( "Getting new context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = Alloc( dw_sz, (void**) &pfvt, &mhLBFVTA );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for TFE Fetch parameters: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf( "Debug: pfvt: %p mhLBFVTA: %p\n", pfvt, mhLBFVTA );
	rs = Alloc( dw_sz, (void**) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLBOut );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for RLE Buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf( "Debug: pdwlocalBuffer: %p mhLBOut: %p\n", pdwlocalBuffer, mhLBOut );
	rs = Alloc( dw_sz, (void**) &pdwTmpBuffer, (RVASMemoryHandle*) &mhLBTmp );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for temporary buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf( "Debug: pdwTmpBuffer: %p mhLBTmp: %p\n", pdwTmpBuffer, mhLBTmp );
	memset( (void*) pfvt, 0x00, sizeof(FetchVideoTilesArg) );
	// set up an operation
	pfvt->pfo[ 0 ].bEnableRLE = 0;
	pfvt->pfo[ 0 ].sbm = AllBytesMode;

	pfvt->pfo[ 1 ].bEnableRLE = 0;
	pfvt->pfo[ 1 ].byRLETripletCode = TRIPLET_CODE;
	pfvt->pfo[ 1 ].byRLERepeatCode = REPEAT_CODE;
	pfvt->pfo[ 1 ].sbm = AllBytesMode;

	pfvt->pfo[ 0 ].fr.wTopY = 0;
	pfvt->pfo[ 0 ].fr.wLeftX = 0;
	pfvt->pfo[ 0 ].fr.wBottomY = 31;
	pfvt->pfo[ 0 ].fr.wRightX = 31;

	pfvt->pfo[ 1 ].fr.wTopY = 0;
	pfvt->pfo[ 1 ].fr.wLeftX = 32;
	pfvt->pfo[ 1 ].fr.wBottomY = 31;
	pfvt->pfo[ 1 ].fr.wRightX = 63;

	// set up a tile
	rs = GetVideoGeometry( &pfvt->vg );

	if ( rs != SuccessStatus ) {
		printf( "Failed for to get video geometry: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf( "TEST FETCH: width %d \n", pfvt->vg.wScreenWidth );
	printf( "TEST FETCH: Height %d \n", pfvt->vg.wScreenHeight );
	printf( "TEST FETCH: BitsPerPixel %d \n", pfvt->vg.byBitsPerPixel );

	pfvt->cfo = 1;

#ifdef SKIP
	{
		int skipMode = 0;
		pfvt->pfo[ 0 ].sbm = AllBytesMode;
		pfvt->pfo[ 1 ].sbm = AllBytesMode;
		printf( "Testing skipping mode\n" );
		printf( "Please enter 0- keep low byte,1- keep middle byte, 2- keep top byte, other-skip this test\n" );
		scanf( "%d", &skipMode );
		switch ( skipMode ) {
			case 0:
				pfvt->pfo[ 0 ].sbm = LowByteMode;
				pfvt->pfo[ 0 ].sbm = LowByteMode;
				break;
			case 1:
				pfvt->pfo[ 0 ].sbm = MiddleByteMode;
				pfvt->pfo[ 0 ].sbm = MiddleByteMode;
				break;
			case 2:
				pfvt->pfo[ 0 ].sbm = TopByteMode;
				pfvt->pfo[ 0 ].sbm = TopByteMode;
				break;
			default:
				break;
		}
	}
#endif

	rs = FetchVideoTiles( rc, mhLBFVTA, mhLBOut, mhLBTmp );

	if ( rs != SuccessStatus ) {
		printf( "Failed to Fetch the Tiles\n" );
	}

	printf( "Total Count 0x%x\n", pfvt->dwTotalOutputSize );
	printf( "\n\nNON RLE COUNT: \n" );
	printf( "   pfvt->pfo[0].0x%x\n", pfvt->pfo[ 0 ].dwFetchSize );
	printf( "   pfvt->pfo[1].0x%x\n", pfvt->pfo[ 1 ].dwFetchRLESize );
	printf( "\n\n RLE COUNT: \n" );
	printf( "   pfvt->pfo[0].0x%x\n", pfvt->pfo[ 0 ].dwFetchSize );
	printf( "   pfvt->pfo[1].0x%x\n", pfvt->pfo[ 1 ].dwFetchRLESize );

	printf( "-----------------data----------------\n" );
	for ( iter = 0; iter < ( dw_sz >> 8 ); iter++ ) {
		printf( "0x%x, ", pdwlocalBuffer[ iter ] );
		if ( ( iter % 16 ) == 0 )
			printf( "\n" );
	}

	printf( "-----------------END data-------------\n" );
	Free( mhLBFVTA );
	Free( mhLBOut );
	Free( mhLBTmp );
	rs = DeleteContext( rc );

	if ( rs != SuccessStatus ) {
		printf( "Deleting context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	return iResult;
}

#endif

#ifdef Test_testVideoSlicing

int testVideoSlicing( void ) {
	int iResult = 0;
	int iter;
	FetchVideoSlicesArg* pfvsa = NULL;
	u32* pdwlocalBuffer = NULL;
	u32* pdwlocalBufferRLE = NULL;
	RVASMemoryHandle mhLBFVSA = NULL;
	RVASMemoryHandle mhLB = NULL;
	RVASMemoryHandle mhLBRLE = NULL;
	u32 dwSize = 4096 * 3;
	RVASStatus rs;
	RVASContext rc = NULL;

	printf( "\n\nTEST FETCH::Fetching...!\n" );

	rs = NewContext( &rc );

	if ( rs != SuccessStatus ) {
		printf( "Getting new context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = Alloc( sizeof(FetchVideoSlicesArg), (void**) &pfvsa, (RVASMemoryHandle*) &mhLBFVSA );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE Fetch parameters: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	Alloc( dwSize, (void**) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLB );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE Buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	Alloc( dwSize, (void**) &pdwlocalBufferRLE, (RVASMemoryHandle*) &mhLBRLE );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE RLE Buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf( "\n\nTest Video Slicing\n" );

	memset( (void*) pfvsa, 0x00, sizeof(FetchVideoSlicesArg) );

	// set up a region
	pfvsa->pfr[ 0 ].wTopY = 0;
	pfvsa->pfr[ 0 ].wLeftX = 0;
	pfvsa->pfr[ 0 ].wBottomY = 31;
	pfvsa->pfr[ 0 ].wRightX = 31;

	pfvsa->pfr[ 1 ].wTopY = 0;
	pfvsa->pfr[ 1 ].wLeftX = 32;
	pfvsa->pfr[ 1 ].wBottomY = 31;
	pfvsa->pfr[ 1 ].wRightX = 63;

	// set up a tile
	GetVideoGeometry( &pfvsa->vg );
	pfvsa->cfr = 1;
	pfvsa->cBuckets = 3;
	pfvsa->abyBitIndexes[ 0 ] = 7;
	pfvsa->abyBitIndexes[ 1 ] = 15;
	pfvsa->abyBitIndexes[ 2 ] = 23;

#ifdef RLE
	pfvsa->bEnableRLE = 1;
	pfvsa->byRLETripletCode = TRIPLET_CODE;
	pfvsa->byRLERepeatCode = REPEAT_CODE;
#endif

	FetchVideoSlices( rc, mhLBFVSA, mhLB, mhLBRLE );

	printf( "\n\nNON RLE COUNT: 0x%x\n", pfvsa->dwSlicedSize );
	printf( "\n\n RLE COUNT: 0x%x\n\n", pfvsa->dwSlicedRLESize );

	printf( "-----------------data----------------\n" );
	for ( iter = 0; iter < ( pfvsa->dwSlicedSize >> 2 ); iter++ ) {
		printf( "0x%x, ", pdwlocalBuffer[ iter ] );
		if ( ( iter % 16 ) == 0 )
			printf( "\n" );
	}
	printf( "\n------RLE DATA------n" );

	for ( iter = 0; iter < ( pfvsa->dwSlicedRLESize >> 2 ); iter++ ) {

		printf( "0x%x, ", pdwlocalBufferRLE[ iter ] );
		if ( ( iter % 16 ) == 0 )
			printf( "\n" );
	}

	printf( "-----------------END data-------------\n" );

	Free( mhLBFVSA );
	Free( mhLB );
	Free( mhLBRLE );
	rs = DeleteContext( rc );

	if ( rs != SuccessStatus ) {
		printf( "Deleting context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	return iResult;
}

int testMultiVideoSlicing( void ) {
	int iResult = 0;
	u32 num_fetches = 2;
	u32 fetch_iter = 0;
	FetchVideoSlicesArg* pfvsa = NULL;
	u32* pdwlocalBuffer = NULL;
	u32* pdwlocalBufferRLE = NULL;
	RVASMemoryHandle mhLBFVSA = NULL;
	RVASMemoryHandle mhLB = NULL;
	RVASMemoryHandle mhLBRLE = NULL;
	u32 dwSize = 4096 * 3;
	RVASContext rc = NULL;
	RVASStatus rs;
	int iter;

	printf( "\n\nTEST Multi FETCH::Fetching...!\n" );
	printf( "\n\nTest Video Slicing\n" );

	rs = NewContext( &rc );

	if ( rs != SuccessStatus ) {
		printf( "Getting new context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = Alloc( sizeof(FetchVideoSlicesArg), (void**) &pfvsa, (RVASMemoryHandle*) &mhLBFVSA );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE Fetch parameters: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	Alloc( dwSize, (void**) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLB );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE Buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	Alloc( dwSize, (void**) &pdwlocalBufferRLE, (RVASMemoryHandle*) &mhLBRLE );

	if ( rs != SuccessStatus ) {
		printf( "Allocating memory failed for BSE RLE Buffer: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	while ( fetch_iter < num_fetches ) {
		printf( "\n\nFetching %u of %u\n", fetch_iter, num_fetches );

		memset( (void*) pfvsa, 0x00, sizeof(FetchVideoSlicesArg) );

		// set up a region
		pfvsa->pfr[ 0 ].wTopY = 0;
		pfvsa->pfr[ 0 ].wLeftX = 0;
		pfvsa->pfr[ 0 ].wBottomY = 31;
		pfvsa->pfr[ 0 ].wRightX = 31;

		pfvsa->pfr[ 1 ].wTopY = 0;
		pfvsa->pfr[ 1 ].wLeftX = 32;
		pfvsa->pfr[ 1 ].wBottomY = 31;
		pfvsa->pfr[ 1 ].wRightX = 63;

		// set up a tile
		GetVideoGeometry( &pfvsa->vg );
		pfvsa->cfr = 1;
		pfvsa->cBuckets = 3;
		pfvsa->abyBitIndexes[ 0 ] = 7;
		pfvsa->abyBitIndexes[ 1 ] = 15;
		pfvsa->abyBitIndexes[ 2 ] = 23;

#ifdef RLE
		pfvsa->bEnableRLE = 1;
		pfvsa->byRLETripletCode = TRIPLET_CODE;
		pfvsa->byRLERepeatCode = REPEAT_CODE;
#endif

		FetchVideoSlices( rc, mhLBFVSA, mhLB, mhLBRLE );

		printf( "\n\nNON RLE COUNT: 0x%x\n", pfvsa->dwSlicedSize );
		printf( "\n\n RLE COUNT: 0x%x\n\n", pfvsa->dwSlicedRLESize );

		printf( "-----------------data----------------\n" );
		for ( iter = 0; iter < ( pfvsa->dwSlicedSize >> 2 ); iter++ ) {
			printf( "0x%x, ", pdwlocalBuffer[ iter ] );
			if ( ( iter % 16 ) == 0 )
				printf( "\n" );
		} // for
		printf( "\n------RLE DATA------n" );

		for ( iter = 0; iter < ( pfvsa->dwSlicedRLESize >> 2 ); iter++ ) {

			printf( "0x%x, ", pdwlocalBufferRLE[ iter ] );
			if ( ( iter % 16 ) == 0 )
				printf( "\n" );

			printf( "-----------------END data-------------\n" );
		} // for

		++fetch_iter;
	} // while

	rs = Free( mhLBFVSA );

	if ( rs != SuccessStatus ) {
		printf( "Freeing mhLBFVSA memory failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = Free( mhLB );

	if ( rs != SuccessStatus ) {
		printf( "Freeing mhLB memory failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = Free( mhLBRLE );

	if ( rs != SuccessStatus ) {
		printf( "Freeing mhLBRLE memory failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	rs = DeleteContext( rc );

	if ( rs != SuccessStatus ) {
		printf( "Deleting context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	return iResult;
}

#endif

int testGRCERegister( void ) {
	int iResult = 0;
	u32* pdwlocalBuffer;
	RVASMemoryHandle mhLB = (RVASMemoryHandle) 0x5a5a5a5a;
	;
	int iter;
	u32 dw_sz = 0x500;

	Alloc( dw_sz, (void*) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLB );
	GetGRCRegisters( mhLB );

	printf( "-------data--------\n" );
	for ( iter = 0; iter < ( dw_sz >> 2 ); iter++ ) {
		printf( "0x%x, ", pdwlocalBuffer[ iter ] );
		if ( ( iter % 8 ) == 0 )
			printf( "\n" );
	} // print

	Free( mhLB );
	return iResult;
}

#ifdef Test_testSnoopMap
//
//
//
int testSnoopMap( void ) {
	int iResult = 0;

	return iResult;
}

int testMode13( void ) {
	int iResult = 0;

	int iter;
	FetchMap tfm;
	VideoGeometry aGeometry;
	u32* pdwlocalBuffer;
	u32* pdwlocalBufferRLE;
	RVASMemoryHandle mhLB = 0;
	RVASMemoryHandle mhLBRLE = 0;
	u32 dwCommand = 0;
	u32 dwBufSize = 0;
	RVASStatus rs;
	RVASContext rc;

	tfm.bEnableRLE = 0;
	tfm.byRLETripletCode = 0x00;
	tfm.byRLERepeatCode = 0x00;
	tfm.dpm = FourBitPackedMode;

	rs = NewContext( &rc );

	if ( rs != SuccessStatus ) {
		printf( "Getting new context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	GetVideoGeometry( &aGeometry );
	dwBufSize = aGeometry.wScreenWidth * aGeometry.wScreenHeight;
	if ( aGeometry.gmt != VGAGraphicsMode ) {
		printf( "Not in Mode 13\n" );
		return -1;
	}
	printf( "Please enter 0-no RLE,1-with RLE\n" );
	scanf( "%d", &dwCommand );
	if ( dwCommand ) {
		tfm.bEnableRLE = 1;
		tfm.byRLETripletCode = TRIPLET_CODE;
		tfm.byRLERepeatCode = REPEAT_CODE;
	}
	Alloc( dwBufSize, (void*) &pdwlocalBuffer, (RVASMemoryHandle*) &mhLB );
	if ( tfm.bEnableRLE ) {
		Alloc( dwBufSize, (void*) &pdwlocalBufferRLE, (RVASMemoryHandle*) &mhLBRLE );
	}
	FetchVGAGraphicsData( rc, aGeometry, &tfm, mhLB, mhLBRLE );

	if ( tfm.bEnableRLE && !tfm.bRLEFailed ) {
		printf( "-------RLE data--------\n" );
		for ( iter = 0; iter < ( ( tfm.dwFetchRLESize + 3 ) >> 2 ); iter++ ) {
			printf( "0x%x, ", pdwlocalBufferRLE[ iter ] );
			if ( ( iter % 4 ) == 0 )
				printf( "\n" );
		}
	} else {
		printf( "-------Node RLE data--------\n" );
		for ( iter = 0; iter < ( tfm.dwFetchSize >> 2 ); iter++ ) {
			printf( "0x%x, ", pdwlocalBuffer[ iter ] );
			if ( ( iter % 4 ) == 0 )
				printf( "\n" );
		}
	}

	Free( mhLB );
	Free( mhLBRLE );
	rs = DeleteContext( rc );

	if ( rs != SuccessStatus ) {
		printf( "Deleting context failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	return iResult;
}

#endif

#ifdef Test_testVideoJPEG

#define COMPRESS_ITERATIONS 	(1)
#define FRAME_COUNT 				(32)

void video_init( void )
{
	u8 yuv = 0; // 0 - yuv444, 1 - uv420
	u8 jpegTableIndex = 4;
   VideoConfig video_config;

	video_config.compression_format = 1;//mode 1: jpeg mode; 0: aspeed mode
	video_config.engine = 0;
	video_config.rc4_enable = 0;
	video_config.compression_mode = 0;
	video_config.AutoMode = 0;
	video_config.YUV420_mode = yuv;
	video_config.Visual_Lossless = 0;
	video_config.Y_JPEGTableSelector = jpegTableIndex;
	SetVideoEngineConfig(&video_config);

}

void get_video_engine_config(void){
	VideoConfig video_config = {0};

	GetVideoEngineConfig(&video_config);

	if(video_config.rs != SuccessStatus) {
		printf (" GetVideoEngineConfig error:! %d\n", video_config.rs);
	}
	else {
		printf (" GetVideoEngineConfig successful!\n");
		printf("video engine: %#x\n", video_config.engine );
		printf("video compression_format: %#x\n", video_config.compression_format );
		printf("video capture_format: %#x\n", video_config.capture_format );
		printf("video compression_mode: %#x\n", video_config.compression_mode );
		printf("video YUV420_mode: %#x\n", video_config.YUV420_mode );
		printf("video AutoMode: %#x\n", video_config.AutoMode );
		printf("video rc4_enable: %#x\n", video_config.rc4_enable );
		printf("video Visual_Lossless: %#x\n", video_config.Visual_Lossless );
		printf("video Y_JPEGTableSelector: %#x\n", video_config.Y_JPEGTableSelector );
		printf("video AdvanceTableSelector: %#x\n", video_config.AdvanceTableSelector );
	}
}


RVASStatus multi_jpeg_compression(int framecount)
{
	char jpeg_file[50];
	FILE *fpjpg;
	MultiJpegConfig multi_jpeg;
	RVASStatus rs;
	RVASMemoryHandle mhStreamLB = 0;
	u32* pdwlocalStreamBuffer;
	u32 dwBufSize = 0x400000; // 4Mbytes
	int i = 0;

	rs = Alloc( dwBufSize, (void*) &pdwlocalStreamBuffer, (RVASMemoryHandle*) &mhStreamLB );
	if ( rs != SuccessStatus ) {
		printf( "Getting jpeg destination buffer failed: %d\n", rs );
		exit( EXIT_FAILURE );
	}

	printf("multi_jpeg_compression \n");

	multi_jpeg.aStreamHandle =  mhStreamLB;

#ifdef TWO_FRAME_TEST
	multi_jpeg.multi_jpeg_frames = 2;	//use bcd flag for jpeg count
	multi_jpeg.frame[0].wXPixels = 128;
	multi_jpeg.frame[0].wYPixels = 128;
	multi_jpeg.frame[0].wWidthPixels = 128;
	multi_jpeg.frame[0].wHeightPixels = 128;

	multi_jpeg.frame[1].wXPixels = 256;
	multi_jpeg.frame[1].wYPixels = 256;
	multi_jpeg.frame[1].wWidthPixels = 128;
	multi_jpeg.frame[1].wHeightPixels = 128;
#else
	multi_jpeg.multi_jpeg_frames = 32;
	u16 wWidth = 32, wHeight = 32;
	for( u8 iY = 0; iY< 2; iY++) {
		for( u8 iX = 0; iX < 16; iX ++ ) {
			multi_jpeg.frame[i].wXPixels = iX * wWidth;
			multi_jpeg.frame[i].wYPixels = iY * wHeight;
			multi_jpeg.frame[i].wWidthPixels = wWidth;
			multi_jpeg.frame[i].wHeightPixels = wHeight;
			i ++;
		}
	}
#endif
	//x, y = 0
	GetVideoEngineJPEGData(&multi_jpeg);

	if(multi_jpeg.rs != SuccessStatus)
		printf (" GetVideoEngineJPEGData error:! %d\n", multi_jpeg.rs);
	else {
		printf (" GetVideoEngineJPEGData successful!\n");

		for(i = 0; i < multi_jpeg.multi_jpeg_frames; i++) {

			if(!multi_jpeg.frame[i].dwSizeInBytes) {
				printf("ERROR: no data has been generated!!!!!!!!!!\n");
				break;
			}

			sprintf(jpeg_file, "%d_%d_x%d_y%d.jpg", i, framecount, multi_jpeg.frame[i].wXPixels, multi_jpeg.frame[i].wYPixels);
			printf("%d : %s : Write JPEG size %#x offset: %#x\n",framecount, jpeg_file, multi_jpeg.frame[i].dwSizeInBytes, multi_jpeg.frame[i].dwOffsetInBytes);
			printf("width: %d : height: %d  \n", multi_jpeg.frame[i].wWidthPixels, multi_jpeg.frame[i].wHeightPixels);

			fpjpg=fopen(jpeg_file,"wb");

			if(i == 0 ) {
				fwrite((unsigned char *)pdwlocalStreamBuffer, multi_jpeg.frame[i].dwSizeInBytes, 1, fpjpg);
			}
			else
				fwrite((unsigned char *)pdwlocalStreamBuffer+multi_jpeg.frame[i-1].dwOffsetInBytes, multi_jpeg.frame[i].dwSizeInBytes, 1, fpjpg);

			fclose(fpjpg);
		}
	}// get data

	Free( mhStreamLB );
	return rs;
}



int testVideoJPEG( void ){
	int iResult = 0;
	u8 iC = 0;
	ResetEngineMode rem = ResetVeEngine;

	//Mode change - we need to reset
	ResetVideoEngine(rem);
	usleep(100);

	video_init();
	get_video_engine_config();

	while (iC < COMPRESS_ITERATIONS) {
		printf("Compression Iter: %d \n", iC);
		if( multi_jpeg_compression(iC) == CaptureTimedOut) {
			ResetVideoEngine(rem);
			usleep(100);
		}
		else
			iC++;
	}//while

	return iResult;
}
#endif
