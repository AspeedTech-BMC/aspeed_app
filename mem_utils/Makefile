ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CC      	= $(CROSS_COMPILE)gcc
MYCFLAGS	= -Wall -ansi
INCLUDE		= .
OBJS		= mem_common.h
LDLIBS		= -lc -lrt -lgcc
EXTRA_FLAGS     = -lpthread

EXEC_MW		= mw
OBJS_MW		= mw.o mem_common.o

EXEC_MD		= md
OBJS_MD		= md.o mem_common.o

all:		$(EXEC_MW) $(EXEC_MD)

mw:		$(OBJS_MW)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_MW) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

md:		$(OBJS_MD)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_MD) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

mw.o:		$(OBJS) mw.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c mw.c

md.o:		$(OBJS) md.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c md.c

mem_common.o:	$(OBJS) mem_common.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c mem_common.c

clean:
	-rm -f *.elf *.gdb *.o $(EXEC_MW) $(EXEC_MD)

install:
	cp $(EXEC_MW) $(EXEC_MD) $(INSTALL_DIR)
