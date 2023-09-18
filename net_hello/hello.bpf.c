#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// This is an example of an eBPF program that attaches to the XDP hook point on a net‐
// work interface.
// This counter will get incremented every time the program runs.

int counter = 0;

// The macro SEC() defines a section called xdp that you’ll be able to see in the
// compiled object file.
SEC("xdp")
// It uses a helper function,
// bpf_printk, to write a string of text,
//  increments the global variable counter, and then returns the
//  value XDP_PASS.This is the verdict indicating to the kernel
//   that it should process this network packet as normal.

int hello(struct xdp_md *ctx)
{
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}

// defines a license string, and this is a
// crucial requirement for eBPF programs. Some of the BPF helper functions in the
// kernel are defined as “GPL only.” If you want to use any of these functions, your
// BPF code has to be declared as having a GPL-compatible license

char LICENSE[] SEC("license") = "Dual BSD/GPL";