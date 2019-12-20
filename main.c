#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

const int PCAP_BUFFER_SIZE = 1024;

void sniff(const pcap_t *handle) {
	printf("Start sniffing!\n");
	printf("Stopped sniffing!\n");
}

int main(int argc, char *argv[]) {
	char *dev;
	bpf_u_int32 ip, mask;
	int retval;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

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

	handle = pcap_open_live(dev, PCAP_BUFFER_SIZE, 0, -1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	sniff(handle);
	pcap_close(handle);

	exit(0);
}
