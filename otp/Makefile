ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS += -Wall -Werror -lcrypto
ifeq ($(ARCH),arm)
	OBJS = otp_ast2600.o
endif
ifeq ($(ARCH),arm64)
	OBJS = otp_ast2700.o
endif

EXE	= otp_app
CC      = $(CROSS_COMPILE)gcc

.c.o:
	$(CC) $(CFLAGS) -c $<

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm -f $(EXE) $(OBJS)

install:
	cp $(EXE) $(INSTALL_DIR)

