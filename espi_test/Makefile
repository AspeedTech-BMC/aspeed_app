#
# Copyright 2020 Aspeed Technology Inc.
#
ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS += -Wall -lpthread
CC      = $(CROSS_COMPILE)gcc

all: oob-pch-test

oob-pch-test: oob-pch-test.o
	$(CC) $(CFLAGS) oob-pch-test.o -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f oob-pch-test *.o

install:
	cp oob-pch-test $(INSTALL_DIR)

