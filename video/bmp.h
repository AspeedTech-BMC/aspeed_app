/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BMP_H_INCLUDED
#define BMP_H_INCLUDED

int loadBMP(const char *filename, unsigned char **pixels, int *width, int *height);
int writeBMP(const char *filename, unsigned char *data, int width, int height);

#endif /* BMP_H_INCLUDED */
