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
	OBJS      = otp_ast2700.o lib_otp_ast2700.o
	OBJS_2705 = otp_ast2705.o
	SHARED_LIB = lib_otp.so
endif

EXE      = otp_app
EXE_2705 = otp-ast2705
CC       = $(CROSS_COMPILE)gcc

ifeq ($(ARCH),arm64)
all: $(EXE) $(EXE_2705)
else
all: $(EXE)
endif

.c.o:
	$(CC) $(CFLAGS) -c $<

$(EXE): $(OBJS) $(SHARED_LIB)
	$(CC) $(OBJS) -o $@ $(CFLAGS)

ifeq ($(ARCH),arm64)
$(SHARED_LIB): lib_otp_ast2700.c otp_prov.c
	$(CC) -shared -fPIC $^ -o $@ -lcrypto -lssl

$(EXE_2705): $(OBJS_2705)
	$(CC) $(OBJS_2705) -o $@ $(CFLAGS)
endif

clean:
	rm -f $(EXE) $(EXE_2705) $(OBJS) $(OBJS_2705) $(SHARED_LIB)

install:
	cp $(EXE) $(INSTALL_DIR)
ifeq ($(ARCH),arm64)
	cp $(EXE_2705) $(INSTALL_DIR)
endif

