#include <uapi/linux/bpf.h>

// BCC defines the macro BPF_PERF_OUTPUT for creating a map that will be used to
// pass messages from the kernel to user space.I’ve called this map output.
BPF_PERF_OUTPUT(output);

// Every time hello() is run, the code will write a structure’s worth of data. This is
// the definition of that structure, which has fields for the process ID, the name of
// the currently running command, and a text message.
struct data_t
{
   int pid;
   int uid;
   char command[16];
   char message[12];
};

int hello(void *ctx)
{
   // data is a local variable that holds the data structure to be submitted, and message
   // holds the "Hello World" string.
   struct data_t data = {};
   char message[12] = "Hello World";

   // bpf_get_current_pid_tgid() is a helper function that gets the ID of the process
   // that triggered this eBPF program to run.It returns a 64 - bit value with the process
   // ID in the top 32 bits.
   data.pid = bpf_get_current_pid_tgid() >> 32;
   // bpf_get_current_uid_gid() is the helper function you saw in the previous
   // example for obtaining the user ID.
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   // Similarly, bpf_get_current_comm() is a helper function for getting the name of
   // the executable(or “command”) that’s running in the process that made the exe
   //  cve syscall.
   bpf_get_current_comm(&data.command, sizeof(data.command));
   // bpf_probe_read_kernel() copies it into the right place in the data structure.
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
   // At this point the data structure is populated with the process ID, command
   // name, and message.This call to output.perf_submit() puts that data into the
   //   map.
   output.perf_submit(ctx, &data, sizeof(data));

   return 0;
}