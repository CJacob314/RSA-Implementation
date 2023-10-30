.PHONY: test
.DEFAULT_GOAL := test
CC = g++
EXEC = test

SHARED_FLAGS = -std=c++17 -Wall -Wpedantic -Wextra

OPTLEVEL ?= -O3
# Call make with make NOOPT to disable most optimizations
ifdef NOOPT
OPTLEVEL := -O0
endif

ifeq ($(shell $(CC) --version | grep -c "Apple clang"), 1)
	ifeq ($(shell test -d /opt/homebrew/include/boost && echo 1 || echo 0), 1)
	SHARED_FLAGS += -I/opt/homebrew/include
	endif
endif


test: RSA-constructors.o RSA-methods.o RSA-operators.o oaep.o hash.o
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) -o $(EXEC) oaep.o RSA-constructors.o RSA-methods.o RSA-operators.o hash.o test.cpp -pthread

debug:
	$(CC) $(SHARED_FLAGS) -g -o $(EXEC) -DDEBUG_TESTING -O0 src/RSA/*.cpp src/OAEP/*.cpp src/CJacob314-Hash/*.cpp test.cpp -pthread

oaep.o:
	$(CC) $(SHARED_FLAGS) src/OAEP/*.cpp -c -o oaep.o

RSA-%.o: src/RSA/RSA-%.cpp
	$(CC) $(SHARED_FLAGS) -c $< -o $@

hash.o:
	$(CC) $(SHARED_FLAGS) src/CJacob314-Hash/*.cpp -c -o hash.o

clean:
	rm -f *.o $(EXEC)