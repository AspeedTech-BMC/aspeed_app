ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS += -Wall
OBJS	= hid_gadget_test.o
EXE	= hid_gadget_app

CC      = $(CROSS_COMPILE)gcc

.c.o:
	$(CC) $(CFLAGS) -c $<

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm -f $(EXE) $(OBJS)

install:
	cp $(EXE) $(INSTALL_DIR)

