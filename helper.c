#include "helper.h"


bool is_ipv4(const struct ether_header *eth_header) {
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

int packet_handler(FILE *fd, const struct pcap_pkthdr *pcap_header, const u_char *data, data_handler_t data_handler) {
	struct ether_header *eth_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	char *payload, *end;

	if (pcap_header->caplen < sizeof(struct ether_header))
		return 0;

	/* For better performance we could use pcap_compile to filter
	 * packet in kernel-space. */
	eth_header = (struct ether_header *) data;
	/* TODO: Work with IPv6 */
	if (!is_ipv4(eth_header))
		return 0;

	ip_header = (struct iphdr *) (data + sizeof(struct ether_header));
	if (!is_tcp(ip_header))
		return 0;

	tcp_header = (struct tcphdr *) ((char *)ip_header + ip_header->ihl * 4);
	payload = tcp_payload(tcp_header);
	end = end_of_ip(ip_header);
	if (payload >= end)
		return 0; /* No payload */
	if (end > (char *) data + pcap_header->caplen)
		return 0; /* XXX: Skip cases where we did not capture the whole packet */

	data_handler(payload, sizeof(char), end - payload, fd);
	return 1;
}
