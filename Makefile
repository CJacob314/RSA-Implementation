.PHONY: test

test:
	g++ -std=c++17 -o test -Wall -O3 src/RSA/*.cpp test.cpp

debug:
	g++ -g -std=c++17 -o test -Wall -O0 src/RSA/*.cpp test.cpp