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
static pcap_t *handle;


void signal_handler(__attribute__((unused)) int sig) {
	capturing = 0;
	pcap_breakloop(handle);
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
	int linktype;
	FILE *fd;
	int count, max_packet_count;
	struct dispatch_param param;

	if (argc < 2) {
		fprintf(stderr, "Please supply device name and output file!\n");
		exit(1);
	} else if (argc < 3) {
		fprintf(stderr, "Please supply output file!\n");
		exit(1);
	} else if (argc < 4) {
		max_packet_count = -1;
	} else {
		/* TODO: handle overflow and other errors */
		max_packet_count = (int) strtol(argv[3], NULL, 10);
	}

	dev = argv[1];
	fprintf(stderr, "Device: %s\n", dev);

	retval = pcap_lookupnet(dev, &ip, &mask, errbuf);
	if (retval == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	fprintf(stderr, "IP: 0x%X, Mask: 0x%X\n", ntohl(ip), ntohl(mask));

	handle = pcap_open_live(dev, PCAP_BUFFER_SIZE, 0, 500, errbuf);
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

	param.fd = fd;
	param.data_handler = fwrite;
	fprintf(stderr, "Start sniffing!\n");
	count = pcap_dispatch(handle, max_packet_count, packet_handler, (void *) &param);
	if (count == -2) {
		fprintf(stderr, "\nCapture interrupted\n");
	} else if (count < 0) {
		fprintf(stderr, "Failed to retrieve packet, error code: %d\n", retval);
		exit(1);
	}
	fprintf(stderr, "Stopped sniffing! Got %d packets\n", count);
	fclose(fd);
	pcap_close(handle);

	exit(0);
}
