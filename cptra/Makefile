ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS	+= -Wall -O3
CXXFLAGS+= -Wall -O3
OBJS	= aspeed_cptra.o
MCI_OBJS = aspeed_cptra_mci.o

# Both platforms build to this same output name -- exactly one of them gets
# compiled in, so there's never a naming collision.
EXE	= aspeed_cptra

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

# PLATFORM selects which source gets built into $(EXE); the two are never
# built together. Defaults to ast2700 if not set on the command line:
#   make PLATFORM=ast2700   -> aspeed_cptra.c (legacy BootMCU-based test)
#   make PLATFORM=ast2705   -> aspeed_cptra_mci.c (Caliptra-SS MCI mailbox test)
# Either way the output is always named "aspeed_cptra".
PLATFORM ?= ast2700

ifeq ($(PLATFORM),ast2700)

all: $(EXE)

MBEDTLS_USER_CFG = $(abspath mbedtls_user_config.h)

$(MBEDTLS_LIBS):
	$(MAKE) -C $(MBEDTLS_DIR) lib CC="$(CROSS_COMPILE)gcc" AR="$(CROSS_COMPILE)ar" CFLAGS='-DMBEDTLS_USER_CONFIG_FILE=\"$(MBEDTLS_USER_CFG)\"'

$(EXE): $(OBJS) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(OBJS) $(MBEDTLS_LIBS) -o $@

install:
	cp $(EXE) $(INSTALL_DIR)
	cp video.inf $(INSTALL_DIR)

else ifeq ($(PLATFORM),ast2705)

all: $(EXE)

$(EXE): $(MCI_OBJS)
	$(CC) $(CFLAGS) $(MCI_OBJS) -o $@

install:
	cp $(EXE) $(INSTALL_DIR)

else

all:
	$(error PLATFORM must be set to "ast2700" or "ast2705", e.g. "make PLATFORM=ast2700")

install:
	$(error PLATFORM must be set to "ast2700" or "ast2705", e.g. "make PLATFORM=ast2700")

endif

else

all:
	@echo "Skip building cptra for non-arm64 architecture"

install:
	@echo "Skip install cptra for non-arm64 architecture"

endif

clean:
	rm -f $(EXE) $(OBJS) $(MCI_OBJS)
	$(MAKE) -C $(MBEDTLS_DIR) clean
