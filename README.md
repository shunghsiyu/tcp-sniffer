# TCP Packet Sniffer

## Ideas

To implement a TCP packet sniffer in C/C++, a few ideas comes to mind:
* Look at how `tcpdump` works, and mimick what it does
* Try to see if a script of the same function exists in [BCC](https://github.com/iovisor/bcc) and work on from there (or look at similar tools like [SystemTap](https://sourceware.org/systemtap/) or [DTrace](http://dtrace.org/blogs/about/))
* Write a kernel module with access to all the kernel-space memory and functions to retrieve TCP packages 

Some considerations for each of the above ideas:
* Kernel hacking (i.e. writing a kernel module) will probably be the most fun, the least portable and the most dangerous way to achieve our goal. It will be hard to imagine a production system acutally use a kernel module to capture TCP packets.
* Using [BCC](https://github.com/iovisor/bcc) should be almost as fun as writing a kernel module, but will be much more restrictive in terms of what we can do in the kernel-space (so less chance of shooting ourself in the foot :D). Transporting data out of the eBPF program will probably take some research.
* Mimicking `tcpdump` will probably be the easiest way to go, there should be more resources on how to capture TCP packets the `tcpdump` way; it will, however, probably be the least efficient of them of them all (and that may be fine)


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

## Reference

* [Socket Programming in C/C++](https://www.geeksforgeeks.org/socket-programming-cc/)
* [The Sniffer's Guide to Raw Traffic](http://yuba.stanford.edu/~casado/pcap/section1.html)
* [Stripping layer 2 in pcap](https://idea.popcount.org/2013-01-29-stripping-layer-2-in-pcap/)
* [fffaraz/lsniffer.c](https://gist.github.com/fffaraz/7f9971463558e9ea9545)
* [CS5600: Introduction to Unit Testing C code with Check](http://www.ccs.neu.edu/home/skotthe/classes/cs5600/fall/2015/labs/intro-check.html)
