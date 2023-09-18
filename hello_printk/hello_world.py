#!/usr/bin/python

# hello() is the ebpf program that runs in the kernel
# hello.py is the user space program


from bcc import BPF

program = r"""
    int hello(void *ctx){
    # helper function to write a message 
    bpf_trace_printk("Hello, World!\\n");
    return 0;
      }

"""
# creating a bpf object by passing the program
b = BPF(text=program)
# ebpf program is attached to the event execve system call
# whenever execve system call is executed ebpf program whill be triggered
syscall = b.get_syscall_fnname("execve")
# attach syscall kernel function using kbprobe
b.attach_kprobe(event=syscall,fn_name="hello")
# read tracing output from the kernel
b.trace_print()