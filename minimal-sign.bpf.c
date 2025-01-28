#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sys_execve")
int minimal_prog(struct pt_regs *ctx)
{
    bpf_printk("Hello from minimal eBPF program!\n");
    return 0;
}
