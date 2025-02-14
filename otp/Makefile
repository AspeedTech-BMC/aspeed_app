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
	OBJS = otp_ast2700.o lib_otp_ast2700.o
	SHARED_LIB = lib_otp.so
endif

EXE	= otp_app
CC      = $(CROSS_COMPILE)gcc

.c.o:
	$(CC) $(CFLAGS) -c $<

$(EXE): $(OBJS) $(SHARED_LIB)
	$(CC) $(CFLAGS) $(OBJS) -o $@

ifeq ($(ARCH),arm64)
$(SHARED_LIB): lib_otp_ast2700.c otp_prov.c
	$(CC) -shared -fPIC $^ -o $@ -lcrypto -lssl
endif

clean:
	rm -f $(EXE) $(OBJS) $(SHARED_LIB)

install:
	cp $(EXE) $(INSTALL_DIR)

