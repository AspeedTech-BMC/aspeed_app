/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#ifndef __MEM_COMMON_H
#define __MEM_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h> 
#include <sys/types.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <unistd.h>

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

#define SPI_BASE	0x1e620000

/* SPI DEF */
#define SPIM_CMD_WHA     0x01
#define SPIM_CMD_RD      0x0B
#define SPIM_CMD_DRD     0xBB
#define SPIM_CMD_WR      0x02
#define SPIM_CMD_DWR     0xD2
#define SPIM_CMD_STA     0x05
#define SPIM_CMD_ENBYTE  0x06
#define SPIM_CMD_DISBYTE 0x04
/* SPI END */

extern int cmd_get_data_size(char *, int);
extern unsigned long simple_strtoul(const char *, char **, unsigned int);
extern long simple_strtol(const char *, char **, unsigned int);

#endif	/* __MEM_COMMON_H */

