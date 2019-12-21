#include "helper.h"
#include <stdio.h>

inline bool is_ip(struct ether_header *eth_header) {
	return ntohs(eth_header->ether_type) == ETHERTYPE_IP;
}

bool is_tcp(struct iphdr *ip_header) {
	return ip_header->protocol == IPPROTO_TCP;
}

