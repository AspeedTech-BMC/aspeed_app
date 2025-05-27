ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS	+= -Wall -O3
CXXFLAGS+= -Wall -O3
OBJS	= aspeed_mbox.o
EXE	= aspeed-mbox

CC      = $(CROSS_COMPILE)g++
CXX     = $(CROSS_COMPILE)g++

.c.o:
	$(CC) $(CFLAGS) -c $<

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

clean:
	rm -f $(EXE) $(OBJS)

install:
	cp $(EXE) $(INSTALL_DIR)
	cp video.inf $(INSTALL_DIR)
