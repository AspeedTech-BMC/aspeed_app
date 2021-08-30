ifdef INST
ifeq ("$(origin INST)", "command line")
INSTALL_DIR := $(INST)
endif
endif

OBJ = main.o ikvm_video.o
ELF = ast-video2

CXX = $(CROSS_COMPILE)g++
CXXFLAGS = -Wall -O3 -I$(PREFIX_DIR)/include

LDFLAGS = -L$(PREFIX_DIR)/lib -lpthread

.cc : .o
	$(CXX) $(CXXFLAGS) -c $<

$(ELF) : $(OBJ)
	$(CXX) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(ELF) $(OBJ)

install:
	cp $(ELF) $(INSTALL_DIR)
