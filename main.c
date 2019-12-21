#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

const int PCAP_BUFFER_SIZE = 1024;

void sniff(pcap_t *handle, const int data_offset) {
	int retval;
	struct pcap_pkthdr *pcap_header;
	const u_char *data;
	struct ether_header *eth_header;
	struct iphdr *ip_header;

	printf("Start sniffing!\n");
	for (int count = 10; count > 0; count--) {
		retval = pcap_next_ex(handle, &pcap_header, &data);
		if (retval != 1) {
			fprintf(stderr, "Failed to capture packet, error code: %d\n", retval);
			return;
		}

		printf("Length of packet: %d\n", pcap_header->len);
		if ((int) pcap_header->caplen < data_offset)
			return;
		eth_header = (struct ether_header *) data;
		printf("Source MAC address: ");
		for (int i = 0; i < ETHER_ADDR_LEN; i++) {
			printf("%02X", eth_header->ether_dhost[i]);
		}
		printf("\n");
		printf("Destination MAC address: ");
		for (int i = 0; i < ETHER_ADDR_LEN; i++) {
			printf("%02X", eth_header->ether_shost[i]);
		}
		printf("\n");

		retval = ntohs(eth_header->ether_type);
		printf("Ethernet packet type: 0x%X\n", retval);
		if (retval != ETHERTYPE_IP) {
			fprintf(stderr, "Unsupported ethernet packet type %d", retval);
		}

		ip_header = (struct iphdr *) (data + data_offset);
		printf("Source IP: %X\n", ntohl(ip_header->saddr));
		printf("Destination IP: %X\n", ntohl(ip_header->daddr));
		printf("Protocol: 0x%X\n", (unsigned int) ip_header->protocol);
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

	sniff(handle, 14);
	pcap_close(handle);

	exit(0);
}
