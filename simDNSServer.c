#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/select.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#define P 0.5
#define SIM_DNS_PROTOCOL 254
#define MAX_QUERY_COUNT 8
#define MAX_DOMAIN_LEN 31
#define MAX_BUFFER_SIZE 1024

struct simDNSHeader
{
    uint16_t id;
    char messageType;
    uint8_t count : 3;
};

int dropmessage(float prob)
{
    srand(time(NULL));
    float random = (float)rand() / RAND_MAX;
    return random < prob;
}

char *interface_name = "lo";
char src_mac_str[18];
char src_ip_str[16];
uint32_t src_ip;

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <source_mac_address> <source_ip>\n", argv[0]);
        return 1;
    }

    strcpy(src_mac_str, argv[1]);
    strcpy(src_ip_str, argv[2]);

    // create a socket and capture all packets till ethernet
    int sockfd;
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    unsigned char src_mac[ETH_ALEN];
    sscanf(src_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);

    src_ip = inet_addr(src_ip_str);

    struct sockaddr_ll server_addr;
    struct sockaddr client_addr;
    int cli_addrlen = sizeof(client_addr);

    memset(&server_addr, 0, sizeof(struct sockaddr_ll));
    server_addr.sll_family = AF_PACKET;
    server_addr.sll_protocol = htons(ETH_P_ALL);
    server_addr.sll_ifindex = if_nametoindex(interface_name);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server is running...Capturing all packets till ethernet.\n");

    while (1)
    {
        char buffer[MAX_BUFFER_SIZE];
        int recvlen = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, &client_addr, (socklen_t *)&cli_addrlen);
        if (recvlen < 0)
        {
            perror("recvfrom");
            continue;
        }

        struct ethhdr *eth_header = (struct ethhdr *)(buffer);
        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        struct simDNSHeader *query_header = (struct simDNSHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (ip_header->protocol == SIM_DNS_PROTOCOL && query_header->messageType == '0' && ip_header->daddr == src_ip)
        {
            printf("\n----------------\\\\\\-------------------\n");

            char *queries = (char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct simDNSHeader));

            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = ip_header->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = ip_header->daddr;
            struct ethhdr *eth = (struct ethhdr *)(buffer);

            if (!dropmessage(P))
            {
                printf("Received packet\n");
                printf("-IP Protocol : %d\n", (unsigned int)ip_header->protocol);
                printf("-ID : %d \n", query_header->id);
                printf("-NumQueries : %d\n", query_header->count);
                printf("-MessageType : %c\n\n", query_header->messageType);

                char response[MAX_BUFFER_SIZE];
                struct ether_header *response_eth_header = (struct ether_header *)response;
                struct iphdr *response_ip_header = (struct iphdr *)(response + sizeof(struct ether_header));
                struct simDNSHeader *response_header = (struct simDNSHeader *)(response + sizeof(struct ether_header) + sizeof(struct iphdr));
                char *response_data = (char *)(response + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct simDNSHeader));

                char *val = queries;
                for (int i = 0; i < query_header->count; i++)
                {
                    printf("--Query: ");
                    uint32_t *size = (uint32_t *)val;
                    val += sizeof(uint32_t);
                    char *query = val;
                    char domain[MAX_DOMAIN_LEN + 1];
                    for (int j = 0; j < size[0]; j++)
                    {
                        printf("%c", query[j]);
                        domain[j] = query[j];
                    }
                    domain[size[0]] = '\0';

                    val += size[0];

                    printf("   Response: ");
                    struct hostent *host = gethostbyname(domain);

                    if (host && host->h_addr_list[0])
                    {
                        struct in_addr addr;
                        memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
                        printf("%s\n", inet_ntoa(addr));
                        *response_data = 1;
                        response_data++;
                        memcpy(response_data, host->h_addr_list[0], sizeof(u_int32_t));
                    }
                    else
                    {
                        printf("0.0.0.0\n");
                        *response_data = 0; // Invalid response
                        response_data++;
                        memset(response_data, 0, sizeof(uint32_t));
                    }
                    response_data += sizeof(uint32_t);
                }

                memcpy(response_eth_header->ether_shost, eth_header->h_dest, ETH_ALEN);
                memcpy(response_eth_header->ether_dhost, eth_header->h_source, ETH_ALEN);
                response_eth_header->ether_type = htons(ETH_P_IP);

                response_ip_header->ihl = 5;
                response_ip_header->version = 4;
                response_ip_header->tos = 0;
                response_ip_header->tot_len = htons(response_data - response - sizeof(struct ether_header)); // total length (Data + IP header)
                response_ip_header->id = htons(54321);
                response_ip_header->frag_off = 0;
                response_ip_header->ttl = 64;
                response_ip_header->protocol = 0xFE; // set the protocol to 254
                response_ip_header->saddr = ip_header->daddr;
                response_ip_header->daddr = ip_header->saddr;

                response_header->id = query_header->id;
                response_header->messageType = '1';
                response_header->count = query_header->count;

                // Send the simDNS response to the client
                struct sockaddr_ll client_addrll;
                memset(&client_addrll, 0, sizeof(struct sockaddr_ll));
                client_addrll.sll_ifindex = if_nametoindex(interface_name);

                server_addr.sll_family = AF_PACKET;
                server_addr.sll_protocol = htons(ETH_P_IP);
                server_addr.sll_halen = ETH_ALEN;
                memcpy(client_addrll.sll_addr, eth_header->h_source, ETH_ALEN);

                int bytes_sent = sendto(sockfd, response, response_data - response, 0, (struct sockaddr *)&client_addrll, sizeof(client_addrll));
                if (bytes_sent < 0)
                {
                    perror("sendto");
                    exit(1);
                }
                else
                    printf("\nResponse Packet for ID: %d sent successfully\n", response_header->id);
            }
            else
            {
                printf("\t\tMessage dropped\n");
            }
        }
    }

    close(sockfd);
    return 0;
}
