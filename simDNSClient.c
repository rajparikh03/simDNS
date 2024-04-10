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
#include <net/if.h>

#define SIM_DNS_PROTOCOL 254
#define MAX_QUERY_COUNT 8
#define MAX_DOMAIN_LENGTH 31
#define MAX_RETRIES 3
#define MAX_PENDING_QUERIES 1000
#define MAX_BUFFER_SIZE 1024

struct simDNSHeader
{
    uint16_t id;
    char messageType;
    uint8_t count : 3;
};

struct pendingQuery
{
    int id;
    int retries;
    int num;
    char *queries[MAX_QUERY_COUNT];
};

int isValidDomain(char *domain)
{
    int len = strlen(domain);

    // Check length
    if (len < 3)
    {
        printf("\nInvalid query format. %s domain name has length less than 3\n", domain);
        return 0;
    }

    if (len > MAX_DOMAIN_LENGTH)
    {
        printf("\nInvalid query format. %s domain name has length greater than 31\n\n", domain);
        return 0;
    }

    // Check for alphanumeric characters and hyphens
    for (int i = 0; i < len; i++)
    {
        if (!(isalnum(domain[i])) && domain[i] != '-' && domain[i] != '.')
        {
            printf("\nInvalid query format. %s contains alphanumeric character(s) other than (.) and (-).\n\n", domain);
            return 0;
        }

        if (i == 0 && domain[i] == '-')
        {
            printf("\nInvalid query format. %s contains hypen at the beginning.\n\n", domain);
            return 0;
        }

        if (i == len - 1 && domain[i] == '-')
        {
            printf("\nInvalid query format. %s contains hypen at the end.\n\n", domain);
            return 0;
        }

        if (i < len - 1 && domain[i] == '-' && domain[i + 1] == '-')
        {
            printf("\nInvalid query format. %s contains consecutive hypens.\n\n", domain);
            return 0;
        }
    }

    return 1;
}

char *interface_name = "lo";
char src_mac_str[18], dst_mac_str[18];
char src_ip_str[16], dst_ip_str[16];
uint32_t src_ip, dst_ip;

void send_query(int sockfd, char *domains[], int numDomains, int unique_id, int flag)
{
    char datagram[MAX_BUFFER_SIZE];

    unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];

    sscanf(src_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);

    sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]);

    src_ip = inet_addr(src_ip_str);

    dst_ip = inet_addr(dst_ip_str);

    struct sockaddr_ll server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_ll));
    server_addr.sll_family = AF_PACKET;
    server_addr.sll_protocol = htons(ETH_P_IP);
    server_addr.sll_ifindex = if_nametoindex(interface_name);
    server_addr.sll_halen = ETH_ALEN;
    memcpy(server_addr.sll_addr, dst_mac, ETH_ALEN);

    struct ether_header *eth_header = (struct ether_header *)datagram;
    struct iphdr *ip_header = (struct iphdr *)(datagram + sizeof(struct ether_header));
    struct simDNSHeader *query_header = (struct simDNSHeader *)(datagram + sizeof(struct ether_header) + sizeof(struct iphdr));
    char *query_data = (char *)(datagram + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct simDNSHeader));

    for (int i = 0; i < numDomains; i++)
    {
        uint32_t domain_len = strlen(domains[i]);
        memcpy(query_data, &domain_len, sizeof(uint32_t));
        query_data += sizeof(uint32_t);
        memcpy(query_data, domains[i], domain_len);
        query_data += domain_len;
    }

    memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
    memcpy(eth_header->ether_dhost, dst_mac, ETH_ALEN);
    eth_header->ether_type = htons(ETH_P_IP);

    query_header->id = unique_id;
    query_header->messageType = '0';
    query_header->count = numDomains;

    ip_header->ihl = 5;
    ip_header->version = 4; // IPv4
    ip_header->tos = 0;
    ip_header->tot_len = htons(query_data - datagram - sizeof(struct ether_header)); // Total length (IP header + Data)
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = 0xFE; // Set the protocol field to 254
    ip_header->saddr = src_ip;
    ip_header->daddr = dst_ip;

    if (sendto(sockfd, datagram, query_data - datagram, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("sendto");
    }
    if (flag == 0)
    {
        printf("Query Packet ID: %d Sent Successfully\n", unique_id);
    }
    else
    {
        printf("Query Packet ID: %d Retransmitted Successfully\n", unique_id);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        printf("Usage: %s <source_mac_address> <destination_mac_address> <source_ip> <destination_ip>\n", argv[0]);
        return 1;
    }

    strcpy(src_mac_str, argv[1]);
    strcpy(dst_mac_str, argv[2]);
    strcpy(src_ip_str, argv[3]);
    strcpy(dst_ip_str, argv[4]);

    struct pendingQuery pending_queries[MAX_PENDING_QUERIES];

    for (int i = 0; i < MAX_PENDING_QUERIES; i++)
    {
        pending_queries[i].id = -1;
        pending_queries[i].retries = 0;
        pending_queries[i].num = 0;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 10; // 10 second timeout
    timeout.tv_usec = 0;
    while (1)
    {
        char buffer[MAX_BUFFER_SIZE];
        fd_set read_fds;
        FD_ZERO(&read_fds);
        int maxfd = -1;
        FD_SET(STDIN_FILENO, &read_fds); // include stdin in the fdset
        maxfd = STDIN_FILENO;
        FD_SET(sockfd, &read_fds); // include sockfd in the fdset
        if (maxfd < sockfd)
            maxfd = sockfd;

        int select_result = select(maxfd + 1, &read_fds, NULL, NULL, &timeout);
        if (select_result < 0)
        {
            perror("select");
            continue;
        }

        if (select_result == 0)
        {
            // Timeout, retransmit pending queries
            for (int i = 0; i < MAX_PENDING_QUERIES; i++)
            {
                if (pending_queries[i].id != -1 && pending_queries[i].retries < MAX_RETRIES)
                {
                    send_query(sockfd, pending_queries[i].queries, pending_queries[i].num, pending_queries[i].id, 1);
                    pending_queries[i].retries++;
                }
                else if (pending_queries[i].id != -1 && pending_queries[i].retries >= MAX_RETRIES)
                {
                    printf("Query ID: %d - No response received after %d retries\n", pending_queries[i].id, MAX_RETRIES);
                    pending_queries[i].id = -1;
                }
            }
            timeout.tv_sec = 10; // 10 second timeout
            timeout.tv_usec = 0;
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            // Any activity in stdin
            char query[MAX_BUFFER_SIZE];
            char *domains[MAX_QUERY_COUNT];
            int numDomains = 0;

            fgets(query, sizeof(query), stdin);

            // Remove trailing newline
            query[strcspn(query, "\n")] = '\0';

            // Parse the query string
            char *token = strtok(query, " ");
            if (token == NULL)
            {
                printf("\nInvalid query format. Empty String.\n\n");
                continue;
            }
            if (strcmp(token, "EXIT") == 0)
            {
                break;
            }
            if (strcmp(token, "getIP") != 0)
            {
                printf("\nInvalid query format. Begin with getIP.\n\n");
                continue;
            }

            token = strtok(NULL, " ");
            if (token == NULL || !isdigit(*token))
            {
                printf("\nInvalid query format. Please specify the number of domains.\n\n");
                continue;
            }

            numDomains = atoi(token);
            if (numDomains <= 0 || numDomains > MAX_QUERY_COUNT)
            {
                printf("\nInvalid query format. Number of domains should be between 1 and %d\n\n", MAX_QUERY_COUNT);
                continue;
            }

            int validQuery = 1;
            int cnt = 0;
            while (token = strtok(NULL, " "))
            {
                if (!isValidDomain(token))
                {
                    validQuery = 0;
                    break;
                }
                domains[cnt] = strdup(token);
                cnt++;
            }
            if (validQuery == 0)
            {
                continue;
            }

            if (cnt != numDomains)
            {
                printf("\nInvalid query format. Number of domains MISMATCHED.\n\n");
                continue;
            }

            printf("\nQuery is valid. Processing...\n\n");

            int found = 0;
            int idx = -1;
            for (int i = 0; i < MAX_PENDING_QUERIES; i++)
            {
                if (pending_queries[i].id == -1)
                {
                    found = 1;
                    pending_queries[i].id = i;
                    pending_queries[i].retries = 0;
                    pending_queries[i].num = numDomains;
                    idx = i;
                    for (int j = 0; j < numDomains; j++)
                    {
                        pending_queries[i].queries[j] = strdup(domains[j]);
                    }
                    break;
                }
            }
            if (!found)
            {
                printf("Too many pending queries\n\n");
                continue;
            }
            send_query(sockfd, domains, numDomains, idx, 0);
        }

        if (FD_ISSET(sockfd, &read_fds))
        {
            // Any activity on sockfd
            struct sockaddr serv;
            int server_addrlen = sizeof(serv);
            ssize_t recv_len = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, &serv, (socklen_t *)&server_addrlen);
            if (recv_len < 0)
            {
                perror("recvfrom");
                continue;
            }

            struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            struct simDNSHeader *response_header = (struct simDNSHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

            if (ip_header->protocol == SIM_DNS_PROTOCOL && ip_header->daddr == src_ip && ip_header->saddr == dst_ip && response_header->messageType == '1')
            {
                struct simDNSHeader *response_header = (struct simDNSHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
                int found = 0;
                for (int i = 0; i < MAX_PENDING_QUERIES; i++)
                {
                    if (pending_queries[i].id == response_header->id)
                    {
                        found = 1;
                        printf("\nQuery ID: %d\nTotal query strings: %d\n", response_header->id, response_header->count);

                        char *responses = (char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct simDNSHeader));
                        for (int j = 0; j < response_header->count; j++)
                        {
                            char valid = *responses;
                            responses++;
                            uint32_t ip_addr = *(uint32_t *)responses;
                            responses += sizeof(uint32_t);

                            char ip_str[INET_ADDRSTRLEN];
                            printf("%-32s ", pending_queries[i].queries[j]);
                            if (valid)
                            {
                                inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
                                printf("%s\n", ip_str);
                            }
                            else
                            {
                                printf("NO IP ADDRESS FOUND\n");
                            }
                        }
                        printf("\n");
                        pending_queries[i].id = -1;
                        break;
                    }
                }
            }
        }
    }
    close(sockfd);
    return 0;
}