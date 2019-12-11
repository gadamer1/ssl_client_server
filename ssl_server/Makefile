all: ssl_server
			

ssl_server: ssl_server.cpp
	g++ -o ssl_server ssl_server.cpp -lpthread -lssl -lcrypto

clean:
	rm ssl_server