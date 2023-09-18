#!/usr/bin/python3 
"""
    Tail calls can call and execute another eBPF program and
replace the execution context.
    prog_array_map is an eBPF map of type BPF_MAP_TYPE_PROG_ARRAY, which holds
a set of file descriptors that identify eBPF programs.
"""


from bcc import BPF
import ctypes as ct


# Instead of attaching to a kprobe, as you saw earlier, this time the user space code
# attaches the main eBPF program to the sys_enter tracepoint.
b = BPF(src_file="hello_trail.c")
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# These calls to b.load_func() return a file descriptor for each tail call program.
# Notice that tail calls need to have the same program type as their parent—
# BPF.RAW_TRACEPOINT in this case. Also, it bears pointing out that each tail call
# program is an eBPF program in its own right.

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# The user space code creates entries in the syscall map. The map doesn’t have to
# be fully populated for every possible opcode; if there is no entry for a particular
# opcode, it simply means no tail call will be executed. Also, it’s perfectly fine to
# have multiple entries that point to the same eBPF program. In this case, I want
# the hello_timer() tail call to be executed for any of a set of timer-related
# syscalls.


prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# Some syscalls get run so frequently by the system that a line of trace for each of
# them clutters up the trace output to the point of unreadability. I’ve used the
# ignore_opcode() tail call for several syscalls.
# Ignore some syscalls that come up a lot
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(29)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(56)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(57)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(63)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(64)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(66)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(72)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(73)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(79)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(98)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(101)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(115)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(131)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(134)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(135)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(139)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(172)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(280)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(291)] = ct.c_int(ignore_fn.fd)

# Print the trace output to the screen, until the user terminates the program
b.trace_print()