ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS	+= -Wall -O3
OBJS	= main.o main1.o main2.o video.o ikvm_video.o
EXE	= ast-video

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
