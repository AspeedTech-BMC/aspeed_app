CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

CFLAGS += -I$(AST_SDK_TOP)/kernel/linux/drivers/soc/aspeed/rvas/

#
# Copyright (c) 2019-2021 ASPEED Technology. All rights reserved. ASPEED CONFIDENTIAL. Unpublished
# work. Copying, access, use or distribution requires an applicable license approved by ASPEED.
#

LIB_NAME=librvas.a
LIB_OBJS=rvas.o
LIB_DEPS=$(LIB_OBJS:.o=.d)
LIB_MAKEFILE=Makefile

RM=rm
SED=sed

#CFLAGS+=-c -g -DDEBUG -Wall -Wstrict-prototypes
#CFLAGS+=-c -g -Wall -Wstrict-prototypes
CFLAGS+=-c -O3 -Wall -Wstrict-prototypes
AR_FLAGS=-rcs
RM_FLAGS=-f
DEP_FLAGS=-MM

all: $(LIB_NAME)

%.o: %.c
	$(CC) $(CFLAGS) $*.c -o $*.o
	@set -e; $(RM) $(RM_FLAGS) $*.d; \
	$(CC) $(DEP_FLAGS) $(CFLAGS) $< > $*.d.tmp; \
	$(SED) 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $*.d.tmp > $*.d; \
	$(RM) $(RM_FLAGS) $*.d.tmp

-include $(LIB_DEPS)

$(LIB_NAME): $(LIB_OBJS)
	$(AR) $(AR_FLAGS) $@ $^

.PHONY: clean
clean:
	-$(RM) $(RM_FLAGS) $(LIB_NAME) $(LIB_OBJS) $(LIB_DEPS)

.PHONY: rebuild
rebuild: clean all
