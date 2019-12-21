#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef size_t (*data_handler_t)(const void *, size_t, size_t, FILE *);

bool is_ipv4(const struct ether_header *eth_header);
bool is_tcp(const struct iphdr *ip_header);
char *end_of_ip(const struct iphdr *ip_header);
char *tcp_payload(const struct tcphdr *tcp_header);
int packet_handler(FILE *fd, const struct pcap_pkthdr *pcap_header, const u_char *data, data_handler_t data_handler);
