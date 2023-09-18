#!/usr/bin/python3  

"""
   Let you write data in a
   structure of your choosing into a perf ring buffer map.

   A ring buffer as a piece of memory
logically organized in a ring, with separate “write” and “read” pointers

   If the read pointer catches up with the write pointer, it simply means there’s no data to
read. If a write operation would make the write pointer overtake the read pointer, the
data doesn’t get written and a drop counter gets incremented. Read operations include
the drop counter to indicate whether data has been lost since the last successful read.
"""








from bcc import BPF

b = BPF(src_file="ring.c") 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
#print_event is a callback function that will output a line of data to the screen.
# BCC does some heavy lifting so that I can refer to the map simply as b["out
# put"] and grab data from it using b["output"].event().  

def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
 #b["output"].open_perf_buffer() opens the perf ring buffer. The function
# takes print_event as an argument to define that this is the callback function to
# be used whenever there is data to read from the buffer.
b["output"].open_perf_buffer(print_event) 

# The program will now loop indefinitely,7
#  polling the perf ring buffer. If there is
# any data available, print_event will get called

while True:   
   b.perf_buffer_poll()