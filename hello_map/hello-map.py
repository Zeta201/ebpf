#!/usr/bin/python3  
from bcc import BPF
from time import sleep
"""
    A map is a data structure that can be accessed from an eBPF program and from user
space.
    Usecases
    1. User space writing configuration information to be retrieved by an eBPF
program
    2. An eBPF program storing state, for later retrieval by another eBPF program (or a
    future run of the same program)
    3. An eBPF program writing results or metrics into a map, for retrieval by the user
    space app that will present results

    Types of maps
    1. Array maps
    2. Maps optimized for FIFO LIFO 
    3. sockmaps and devmaps hold information about sockets and network
    devices used by eBPF programs
    4. Hash maps
    5. Perf and ring buffers

"""
"""
 Hash Table Map Demo
 Key Value pairs where key is the user id and value is the number of times
 execve is called by a process under that user id
"""
"""
The program is compiled, loaded into the kernel,
 and attached to the execve kprobe.
"""
b = BPF(src_file="hello-map.c")

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# This part of the code loops indefinitely, looking for output to display every two
# seconds
while True:
    sleep(2)
    s = ""
    # BCC automatically creates a Python object to represent the hash table. This code
    # loops through any values and prints them to the screen.
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)