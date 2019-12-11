all: ssl_client
			

ssl_client: ssl_client.cpp
	g++ -o ssl_client ssl_client.cpp -lssl -lcrypto

clean:
	rm ssl_client