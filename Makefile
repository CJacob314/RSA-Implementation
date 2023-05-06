.PHONY: test

test:
	g++ -std=c++17 -o test -Wall -O3 src/RSA/*.cpp test.cpp