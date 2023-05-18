/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Keep all the ugly #ifdef for system stuff here
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#ifdef __LP64__
#define MEM_SUPPORT_64BIT_DATA	1
#else
#define MEM_SUPPORT_64BIT_DATA	0
#endif

#endif
