/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __UTILS_H__
#define __UTILS_H__

/* number of bits in a long int. */
#define BITS_PER_LONG  (__CHAR_BIT__ * __SIZEOF_LONG__)

/* contiguous bitmask starting at bit 'h' and ending at bit 'l' */
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* prepare bit mask  */
#define BIT(n)  (1 << (n))

/* calculate number of array elements */
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* avoid unused variable warning */
#define UNUSED(x) ((void)(x))

#endif
