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

EXEC_SPW	= spw
OBJS_SPW	= spw.o mem_common.o

EXEC_SPD	= spd
OBJS_SPD	= spd.o mem_common.o

all:		$(EXEC_MW) $(EXEC_MD) $(EXEC_SPW) $(EXEC_SPD)

mw:		$(OBJS_MW)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_MW) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

md:		$(OBJS_MD)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_MD) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

spw:	$(OBJS_SPW)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_SPW) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

spd:	$(OBJS_SPD)
	$(CC) $(MYLDFLAGS) $(OBJS) $(OBJS_SPD) -o $@ $(LDLIBS) $(EXTRA_FLAGS)
	chmod 744 $@

mw.o:		$(OBJS) mw.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c mw.c

md.o:		$(OBJS) md.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c md.c

spw.o:	$(OBJS) spw.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c spw.c

spd.o:	$(OBJS) spd.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c spd.c

mem_common.o:	$(OBJS) mem_common.c
	$(CC) $(MYCFLAGS) -l$(INCLUDE) -c mem_common.c

clean:
	-rm -f *.elf *.gdb *.o $(EXEC_MW) $(EXEC_MD) $(EXEC_SPW) $(EXEC_SPD)

install:
	cp $(EXEC_MW) $(EXEC_MD) $(EXEC_SPW) $(EXEC_SPD) $(INSTALL_DIR)
