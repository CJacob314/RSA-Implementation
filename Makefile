.PHONY: embuild

embuild:
	em++ -std=c++2a -lembind -o ../rsa.js src/RSA/*.cpp src/OAEP/OAEP-methods.cpp src/CJacob314-Hash/Hashing.cpp -s USE_BOOST_HEADERS=1