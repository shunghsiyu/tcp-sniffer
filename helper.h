#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


bool is_ip(const struct ether_header *eth_header);
bool is_tcp(const struct iphdr *ip_header);
char *end_of_ip(const struct iphdr *ip_header);
char *tcp_payload(const struct tcphdr *tcp_header);
