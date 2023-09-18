"""
    bpf for performing a command on an extended BPF
map or program.

int bpf(int cmd, union bpf_attr *attr, unsigned int size);
 cmd --> specifies which command to perform

 attr argument to the bpf() syscall holds whatever data is needed to specify the
parameters for the command, and size indicates how many bytes of data there are in
attr.

program sends a message to the perf buffer whenever it runs, conveying information
from the kernel to user space about execve() syscall events. What’s new in this ver‐
sion is that it allows for different messages to be configured for each user ID.

"""

#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct


b = BPF(src_file="bpf_config.c") 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(501)] = ct.create_string_buffer(b"Hi user 501!")
 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
b["output"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()