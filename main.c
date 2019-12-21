#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "helper.h"

const int PCAP_BUFFER_SIZE = 65536;


void sniff(pcap_t *handle) {
	int retval;
	struct pcap_pkthdr *pcap_header;
	const u_char *data;
	struct ether_header *eth_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	char *payload, *end;

	printf("Start sniffing!\n");
	for (int count = 10; count > 0;) {
		retval = pcap_next_ex(handle, &pcap_header, &data);
		if (retval != 1) {
			fprintf(stderr, "Failed to capture packet, error code: %d\n", retval);
			return;
		}

		if (pcap_header->caplen < sizeof(struct ether_header))
			continue;

		eth_header = (struct ether_header *) data;
		if (!is_ip(eth_header))
			continue;

		ip_header = (struct iphdr *) (data + sizeof(struct ether_header));
		if (!is_tcp(ip_header))
			continue;

		tcp_header = (struct tcphdr *) ((char *)ip_header + ip_header->ihl * 4);
		payload = tcp_payload(tcp_header);
		end = end_of_ip(ip_header);
		if (payload >= end)
			continue; /* No payload */

		printf("Payload size: %d\n", (int) (end - payload));
		for (char *ptr = payload; ptr < end; ptr++) {
			printf("%02X", *ptr);
		}
		printf("\n");

		count--;
	}
	printf("Stopped sniffing!\n");
}

int main(int argc, char *argv[]) {
	char *dev;
	bpf_u_int32 ip, mask;
	int retval;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int linktype;

	if (argc < 2) {
		fprintf(stderr, "Please supply device name!\n");
		exit(1);
	}

	dev = argv[1];
	printf("Device: %s\n", dev);

	retval = pcap_lookupnet(dev, &ip, &mask, errbuf);
	if (retval == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	printf("IP: 0x%X, Mask: 0x%X\n", ntohl(ip), ntohl(mask));

	handle = pcap_open_live(dev, PCAP_BUFFER_SIZE, 0, 100, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	linktype = pcap_datalink(handle);
	if (linktype != 1) {
		fprintf(stderr, "Unsupported link-type %d", linktype);
		exit(1);
	}

	sniff(handle);
	pcap_close(handle);

	exit(0);
}
