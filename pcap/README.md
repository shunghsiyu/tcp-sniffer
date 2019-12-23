# Pcap-based TCP Packet Capturing

## Requirements

Runtime Libraries:
* Pcap

Unit Testing Libraries:
* Check

End-to-end Testing Tools:
* ip
* netcat


## Makefile

### Build

`make default`

### Unit Testing

`make test`

### End-to-end Testing

`make e2e`

## Capture Packet

`main.out DEVICE OUTPUT_FILE [PACKET_COUNT]`

* `DEVICE` is the name of the network interface, e.g. `eth0`.
* `OUTPUT_FILE` is the location where packet payload will be written.
* `PACKET_COUNT` is optional. Specifiying it makes the program exit after a certain number of packet is captured. If not specified then the program keep capturing packets until it is idle (for 500ms).
