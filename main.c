#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "helper.h"

const int PCAP_BUFFER_SIZE = 65536;

static volatile sig_atomic_t capturing = 1;


void signal_handler(__attribute__((unused)) int sig) {
	capturing = 0;
}

void sniff(pcap_t *handle, FILE *fd) {
	int retval;
	struct pcap_pkthdr *pcap_header;
	const u_char *data;

	printf("Start sniffing!\n");
	while (capturing) {
		/* We could also use pcap_dispatch() or pcap_loop() */
		retval = pcap_next_ex(handle, &pcap_header, &data);
		if (retval != 1) {
			fprintf(stderr, "Failed to retrieve packet, error code: %d\n", retval);
			return;
		}
		packet_handler(fd, pcap_header, data, fwrite);
	}
	printf("\nStopped sniffing!\n");
}

void install_signal_handler(void) {
	struct sigaction signal_action = {
		.sa_handler = signal_handler,
	};
	sigaction(SIGINT, &signal_action, NULL);
}

int main(int argc, char *argv[]) {
	char *dev;
	bpf_u_int32 ip, mask;
	int retval;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int linktype;
	FILE *fd;

	if (argc < 2) {
		fprintf(stderr, "Please supply device name and output file!\n");
		exit(1);
	} else if (argc < 3) {
		fprintf(stderr, "Please supply output file!\n");
		exit(1);
	}

	dev = argv[1];
	fprintf(stderr, "Device: %s\n", dev);

	retval = pcap_lookupnet(dev, &ip, &mask, errbuf);
	if (retval == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	fprintf(stderr, "IP: 0x%X, Mask: 0x%X\n", ntohl(ip), ntohl(mask));

	handle = pcap_open_live(dev, PCAP_BUFFER_SIZE, 0, 100, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	linktype = pcap_datalink(handle);
	if (linktype != 1) {
		fprintf(stderr, "Unsupported link-type %d", linktype);
		pcap_close(handle);
		exit(1);
	}

	fd = fopen(argv[2], "wb");
	install_signal_handler();
	sniff(handle, fd);
	fclose(fd);
	pcap_close(handle);

	exit(0);
}
