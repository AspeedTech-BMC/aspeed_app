ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

CC          = $(CROSS_COMPILE)gcc
INCLUDE     = .
OBJS        = 
LDLIBS      = -lc -lrt -lgcc 
EXTRA_FLAGS = -lpthread
CFLAGS     += -Wall -O2
EXEC_NAME   = i2c-slave-mqueue

all: $(EXEC_NAME)

$(EXEC_NAME): $(EXEC_NAME).o
	$(CC) $(CFLAGS) $(OBJS) $(EXEC_NAME).o -o $@ $(LDLIBS) $(EXTRA_FLAGS)

$(EXEC_NAME).o: $(OBJS) $(EXEC_NAME).c
	$(CC) $(CFLAGS) -l$(INCLUDE) -c $(EXEC_NAME).c

clean:
	rm -f $(EXEC_NAME).elf $(EXEC_NAME).gdb $(EXEC_NAME).o $(EXEC_NAME)

install:
	cp $(EXEC_NAME) $(INSTALL_DIR)
