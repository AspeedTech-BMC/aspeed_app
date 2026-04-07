ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS	+= -Wall -O3
CXXFLAGS+= -Wall -O3
OBJS	= aspeed_cptra.o
EXE	= aspeed-cptra

CC      = $(CROSS_COMPILE)g++
CXX     = $(CROSS_COMPILE)g++

MBEDTLS_DIR = ../lib/mbedtls
MBEDTLS_INC = $(MBEDTLS_DIR)/include
MBEDTLS_LIB_DIR = $(MBEDTLS_DIR)/library
MBEDTLS_LIBS = $(MBEDTLS_LIB_DIR)/libmbedx509.a $(MBEDTLS_LIB_DIR)/libmbedtls.a $(MBEDTLS_LIB_DIR)/libmbedcrypto.a

CFLAGS += -I$(MBEDTLS_INC)
CXXFLAGS += -I$(MBEDTLS_INC)

.c.o:
	$(CC) $(CFLAGS) -c $<

ifeq ($(ARCH),arm64)

all: $(EXE)

MBEDTLS_USER_CFG = $(abspath mbedtls_user_config.h)

$(MBEDTLS_LIBS):
	$(MAKE) -C $(MBEDTLS_DIR) lib CC="$(CROSS_COMPILE)gcc" AR="$(CROSS_COMPILE)ar" CFLAGS='-DMBEDTLS_USER_CONFIG_FILE=\"$(MBEDTLS_USER_CFG)\"'

$(EXE): $(OBJS) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(OBJS) $(MBEDTLS_LIBS) -o $@

install:
	cp $(EXE) $(INSTALL_DIR)
	cp video.inf $(INSTALL_DIR)

else

all:
	@echo "Skip building cptra for non-arm64 architecture"

install:
	@echo "Skip install cptra for non-arm64 architecture"

endif

clean:
	rm -f $(EXE) $(OBJS)
	$(MAKE) -C $(MBEDTLS_DIR) clean
