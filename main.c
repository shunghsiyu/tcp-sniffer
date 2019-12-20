#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

int main(int argc, char *argv[]) {
	char *dev;
	bpf_u_int32 ip, mask;
	int retval;
	char errbuf[PCAP_ERRBUF_SIZE];

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

	exit(0);
}
