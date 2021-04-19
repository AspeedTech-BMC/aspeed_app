
# Entry points

#
# Copyright (c) 2019-2032 ASPEED Technolnogy. All rights reserved. ASPEED CONFIDENTIAL. Unpublished
# work. Copying, access, use or distribution requires an applicable license approved by ASPEED.
#

ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CC=$(CROSS_COMPILE)gcc
RVAS_DRIVER_DIR=$(AST_SDK_TOP)/kernel/linux/drivers/soc/aspeed/rvas/

VTEST_OBJS := vtest.o
RVAS_TEST_OBJS := rvas_test.o

VTEST_DEPS=$(VTEST_OBJS:.o=.d)
RVAS_TEST_DEPS=$(RVAS_TEST_OBJS:.o=.d)

VTEST_NAME=vtest
RVAS_TEST_NAME=rvas_test
RM=rm
SED=sed
LIB_RVAS=./rvas_lib/librvas.a
APP_MAKEFILE=Makefile

LD_FLAGS=
#CFLAGS+=-c -g -DDEBUG -Wall -Wstrict-prototypes -I./rvas_lib/ -I./include/
CFLAGS+=-c -g -Wall -Wstrict-prototypes -I./rvas_lib/ -I$(RVAS_DRIVER_DIR)
RM_FLAGS=-f
DEP_FLAGS=-MM
LDFLAGS=
LIBS=-lrt -lpthread $(LIB_RVAS)

all: ${VTEST_NAME} ${RVAS_TEST_NAME}

%.o: %.c
	$(CC) $(CFLAGS) $*.c -o $*.o
	@set -e; $(RM) $(RM_FLAGS) $*.d; \
	$(CC) $(DEP_FLAGS) $(CFLAGS) $< > $*.d.tmp; \
	$(SED) 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $*.d.tmp > $*.d; \
	$(RM) $(RM_FLAGS) $*.d.tmp

-include $(VTEST_DEPS)
-include $(RVAS_TEST_DEPS)

 $(LIB_RVAS):
	$(MAKE) -C ./rvas_lib

${VTEST_NAME}: $(VTEST_OBJS) $(LIB_RVAS)
	$(CC) $(LD_FLAGS) $^ $(LIBS) -o $@

${RVAS_TEST_NAME}: $(RVAS_TEST_OBJS) $(LIB_RVAS)
	$(CC) $(LD_FLAGS) $^ $(LIBS) -o $@

.PHONY: clean
clean:
	$(RM) $(RM_FLAGS) ${VTEST_NAME} $(VTEST_OBJS) $(VTEST_DEPS) ${RVAS_TEST_NAME} $(RVAS_TEST_OBJS) $(RVAS_TEST_DEPS)
	$(MAKE) -C ./rvas_lib clean

.PHONY: rebuild
rebuild: clean all

.PHONY: install
install: all
	cp $(VTEST_NAME) $(INSTALL_DIR)
	cp $(RVAS_TEST_NAME) $(INSTALL_DIR)
