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

