.PHONY: test
CC = g++
SHARED_FLAGS = -std=c++17 -Wall -o test

ifeq ($(shell $(CC) --version | grep -c "Apple clang"), 1)
  ifeq ($(shell test -d /opt/homebrew/include/boost && echo 1 || echo 0), 1)
    SHARED_FLAGS += -I/opt/homebrew/include
  endif
endif


test:
	g++ $(SHARED_FLAGS) -O3 src/RSA/*.cpp src/OAEP/*.cpp src/CJacob314-Hash/*.cpp test.cpp

debug:
	g++ $(SHARED_FLAGS) -g -DDEBUG_TESTING -O0 src/RSA/*.cpp src/OAEP/*.cpp src/CJacob314-Hash/*.cpp test.cpp