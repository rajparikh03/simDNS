server: 
	gcc simDNSServer.c -o simDNSServer
	sudo ./simDNSServer FF:FF:FF:FF:FF:FF 127.0.0.1

client: 	
	gcc simDNSClient.c -o simDNSClient
	sudo ./simDNSClient FF:FF:FF:FF:FF:FF FF:FF:FF:FF:FF:FF 127.0.0.1 127.0.0.1

clean:
	rm simDNSServer simDNSClient