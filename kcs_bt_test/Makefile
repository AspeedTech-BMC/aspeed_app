#
# Copyright 2020 Aspeed Technology Inc.
#
ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CC		= $(CROSS_COMPILE)gcc
INCLUDE		= .
OBJS		= 
LDLIBS		= 
EXTRA_FLAGS	= 
EXEC_NAME	= kcs_bt_test

all:		$(EXEC_NAME)

$(EXEC_NAME):	$(EXEC_NAME).o
	$(CC) $(MYLDFLAGS) $(OBJS) $(EXEC_NAME).o -o $@ $(LDLIBS) $(EXTRA_FLAGS)

$(EXEC_NAME).o:	$(OBJS) $(EXEC_NAME).c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c $(EXEC_NAME).c

clean:
	rm -f $(EXEC_NAME).elf $(EXEC_NAME).gdb $(EXEC_NAME).o $(EXEC_NAME)

install:
	cp $(EXEC_NAME) $(INSTALL_DIR)
