Assignment 6 - Raj Parikh (21CS30039) and Soukhin Nayek (21CS10062)

For Client:
1. To run the client, specify the following as arguments in makefile
<source_mac_address> <destination_mac_address> <source_ip> <destination_ip>
2. Also change the interface name in line 101 as required.
3. We have included stdin in fdset for the select call, so you can enter the queries whenever you want.
4. The timeout over the select call can be changed in line 205 and 242. We have set it to 10 seconds.

For Server:
1. To run the server, specify the following as arguments in makefile
<source_mac_address> <source_ip>
2. Also change the interface name in line 56 as required.
3. The probability of drop message can be changed in line 36. We have set it to 0.5.

Notes: 
1. Interface name should be set the same for both the client and the server. For loopback/local we have used 'lo'.
2. We have used Loopback address as the IP.