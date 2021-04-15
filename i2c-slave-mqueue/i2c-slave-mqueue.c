/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Aspeed Technology Inc.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int i, r;
    struct pollfd pfd;
    struct timespec ts;
    unsigned char data[256];
    
    pfd.fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    if (pfd.fd < 0)
        return -1;
    
    pfd.events = POLLPRI;
    
    while (1) {
        r = poll(&pfd, 1, 5000);
    
        if (r < 0)
            break;
    
        if (r == 0 || !(pfd.revents & POLLPRI))
            continue;
    
        lseek(pfd.fd, 0, SEEK_SET);
        r = read(pfd.fd, data, sizeof(data));
        if (r <= 0)
            continue;
    
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("[%ld.%.9ld] :", ts.tv_sec, ts.tv_nsec);
        for (i = 0; i < r; i++)
            printf(" %02x", data[i]);
        printf("\n");
    }
    
    close(pfd.fd);
    
    return 0;
}

