// BCC provides a BPF_PROG_ARRAY macro for easily defining maps of type
// BPF_MAP_TYPE_PROG_ARRAY.I have called the map syscall and allowed for 300
// entries, 9
// which is going to be sufficient for this example.
#include <uapi/linux/bpf.h>
BPF_PROG_ARRAY(syscall, 300);

// In the user space code that you’ll see shortly, I’m going to attach this eBPF pro‐
// gram to the sys_enter raw tracepoint, which gets hit whenever any syscall is
// made.The context passed to an eBPF program attached to a raw tracepoint takes
// the form of this bpf_raw_tracepoint_args structure.
int hello(struct bpf_raw_tracepoint_args *ctx)
{
    // In the case of sys_enter, the raw tracepoint arguments include the opcode iden‐
    // tifying which syscall is being made.
    int opcode = ctx->args[1];
    // Here we make a tail call to the entry in the program array whose key matches the
    // opcode.This line of code will be rewritten by BCC to a call to the
    // bpf_tail_call() helper function before it passes the source code to the
    // compiler.
    syscall.call(ctx, opcode);
    // If the tail call succeeds, this line tracing out the opcode value will never be hit.
    // I’ve used this to provide a default line of trace for opcodes for which there isn’t a
    // program entry in the map
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

// hello_exec() is a program that will be loaded into the syscall program array
// map, to be executed as a tail call when the opcode indicates it’s an execve()
// syscall.It’s just going to generate a line of trace to tell the user a new program is
// being executed.
int hello_exec(void *ctx)
{
    bpf_trace_printk("Executing a program");
    return 0;
}

// hello_timer() is another program that will be loaded into the syscall program
// array.In this case it’s going to be referred to by more than one entry in the pro‐
// gram array.
int hello_timer(struct bpf_raw_tracepoint_args *ctx)
{
    int opcode = ctx->args[1];
    switch (opcode)
    {
    case 222:
        bpf_trace_printk("Creating a timer");
        break;
    case 226:
        bpf_trace_printk("Deleting a timer");
        break;
    default:
        bpf_trace_printk("Some other timer operation");
        break;
    }
    return 0;
}
// ignore_opcode() is a tail call program that does nothing.I’ll use this for syscalls
// where I don’t want any trace to be generated at all.
int ignore_opcode(void *ctx)
{
    return 0;
}