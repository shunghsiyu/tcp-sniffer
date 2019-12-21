#include "helper.h"
#include <stdio.h>


bool is_ip(const struct ether_header *eth_header) {
	return ntohs(eth_header->ether_type) == ETHERTYPE_IP;
}

bool is_tcp(const struct iphdr *ip_header) {
	return ip_header->protocol == IPPROTO_TCP;
}

char *end_of_ip(const struct iphdr *ip_header) {
	return (char *) ip_header + ntohs(ip_header->tot_len);
}

char *tcp_payload(const struct tcphdr *tcp_header) {
	return (char *) tcp_header + (tcp_header->doff * 4);
}
