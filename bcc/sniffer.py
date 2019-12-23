#!/usr/bin/env python3
#
# tcpv4tracer   Trace TCP connections.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS]
#
# You should generally try to avoid writing long scripts that measure multiple
# functions and walk multiple kernel structures, as they will be a burden to
# maintain as the kernel changes.
# The following code should be replaced, and simplified, when static TCP probes
# exist.
#
# Copyright 2017 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License")
from bcc import BPF

import argparse as ap
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

bpf_text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <linux/skbuff.h>
#pragma clang diagnostic pop
#include <net/ip.h>
#include <net/tcp.h>
#include <bcc/proto.h>

#ifndef tcp_doff
#define tcp_doff(th) (((u_int8_t *)th)[12] >> 4)
#endif

struct data_t {
    u8 offset;
};
BPF_PERF_OUTPUT(tcp_payload);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

int tcp_sniff(struct pt_regs *ctx, struct sk_buff *skb) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    struct data_t data = {};
    if (bpf_probe_read(&data.offset, 1, ((u_int8_t *)tcp) + 12) != 0)
        return 0;
    data.offset = data.offset >> 4;
    tcp_payload.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
"""


def print_tcp_payload(cpu, data, size):
    event = b["tcp_payload"].event(data)
    print(event.offset)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_rcv", fn_name="tcp_sniff")

print("Tracing TCP payload. Ctrl-C to end.")

b["tcp_payload"].open_perf_buffer(print_tcp_payload)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
