.PHONY: embuild

embuild:
	em++ -O3 -sEXCEPTION_CATCHING_ALLOWED=[runtime_error] -std=c++2a -lembind -o ../rsa.js src/RSA/*.cpp src/OAEP/OAEP-methods.cpp src/CJacob314-Hash/Hashing.cpp -s USE_BOOST_HEADERS=1 -pthread -sPTHREAD_POOL_SIZE=navigator.hardwareConcurrency
