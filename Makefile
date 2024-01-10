.PHONY: test
.DEFAULT_GOAL := test
CC = g++
EXEC = test
DEPS = -pthread -lboost_random -lboost_system
SHARED_FLAGS = -std=c++17 -Wall -Wpedantic -Wextra

OPTLEVEL ?= -O3 -flto=auto
# Call make with make NOOPT to disable most optimizations
ifdef NOOPT
OPTLEVEL := -O0
endif

ifeq ($(shell $(CC) --version | grep -c "Apple clang"), 1)
  ifeq ($(shell test -d /opt/homebrew/include/boost && echo 1 || echo 0), 1)
  SHARED_FLAGS += -I/opt/homebrew/include
  endif
endif

test: RSA-constructors.o RSA-methods.o RSA-operators.o oaep.o hash.o stringasm.o test.cpp
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) -o $(EXEC) $^ $(DEPS)

debug:
	$(CC) $(SHARED_FLAGS) -g -o $(EXEC) -DDEBUG_TESTING -O0 src/RSA/*.cpp src/OAEP/*.cpp src/CJacob314-Hash/*.cpp test.cpp $(DEPS)

oaep.o:
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) src/OAEP/*.cpp -c -o oaep.o

RSA-%.o: src/RSA/RSA-%.cpp
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) -c $< -o $@ $(DEPS)

stringasm.o: src/StringAssembler/StringAssembler.cpp
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) $< -c -o $@ $(DEPS)

hash.o: src/CJacob314-Hash/Hashing.cpp
	$(CC) $(SHARED_FLAGS) $(OPTLEVEL) $< -c -o $@ $(DEPS)

clean:
	rm -f *.o $(EXEC)
