ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CFLAGS += -Wall -O2 
LIBS 	= -ldl -lpthread
OBJS	=  libmctp.o mctp.o
EXE	= mctp
CC      = $(CROSS_COMPILE)gcc

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXE) $(OBJS)

install:
	cp $(EXE) $(INSTALL_DIR)

