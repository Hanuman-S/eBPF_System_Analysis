from bcc import BPF
from time import sleep
import os
program = """
#include <uapi/linux/ptrace.h>
struct counts {
    u64 fork_count;
    u64 exec_count;
    u64 fork_ema;
    u64 exec_ema;
    u64 fork_last;
    u64 exec_last;

    u64 malloc_calls;
    u64 free_calls;
    u64 malloc_bytes;
    u64 free_bytes;

    u64 mmap_calls;
    u64 munmap_calls;
    u64 mmap_bytes;
    u64 munmap_bytes;
};

BPF_HASH(fork_exec_info, u32, struct counts);
int kprobe__sys_clone(void *ctx){
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct counts zero = {};
    	struct counts *val;
    	val = fork_exec_info.lookup_or_try_init(&pid, &zero);
    	if(val){
        	val->fork_count++;
			if(val->fork_last != 0){
				u64 cts = bpf_ktime_get_ns();
        		u64 delay = cts - val->fork_last;

                if(val->fork_ema != 0){
					val->fork_ema = val->fork_ema - (val->fork_ema >> 3) + delay;
                } else {
					val->fork_ema = delay;
                }
			}
			val->fork_last = bpf_ktime_get_ns();
    	}
	
    	return 0;
}

int kprobe__sys_execve(void *ctx){
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct counts zero = {};
    	struct counts *val;
    	val = fork_exec_info.lookup_or_try_init(&pid, &zero);
    	if(val){
        	val->exec_count++;
			if(val->exec_last != 0){
                u64 cts = bpf_ktime_get_ns();
                u64 delay = cts - val->exec_last;
                if(val->exec_ema != 0){
					val->exec_ema = val->exec_ema - (val->exec_ema >> 3) + (delay >> 3);
                } else {
					val->exec_ema = delay;
                }
            }
			val->exec_last = bpf_ktime_get_ns();
    	}
	
    	return 0;
}

BPF_HASH(ptr_size_map, u64, u64);

int probe_malloc(struct pt_regs *ctx) {
    u64 size = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 tid = bpf_get_current_pid_tgid();
    ptr_size_map.update(&tid, &size);
    return 0;
}

int probe_malloc_ret(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *sizep = ptr_size_map.lookup(&tid);
    if (!sizep) return 0;

    u64 ptr = PT_REGS_RC(ctx);
    u64 size = *sizep;

    ptr_size_map.delete(&tid);

    struct counts zero = {};
    u32 pid = tid >> 32;
    struct counts *val = fork_exec_info.lookup_or_try_init(&pid, &zero);

    if (val) {
        val->malloc_calls++;
        val->malloc_bytes += size;

        ptr_size_map.update(&ptr, &size);
    }
    return 0;
}

int probe_free(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *sizep = ptr_size_map.lookup(&ptr);

    struct counts zero = {};
    struct counts *val = fork_exec_info.lookup_or_try_init(&pid, &zero);

    if (val) {
        val->free_calls++;

        if (sizep) {
            val->free_bytes += *sizep;
            ptr_size_map.delete(&ptr);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u64 len = args->len;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (len < (1 << 20)) return 0;  // filter <1MB

    struct counts zero = {};
    struct counts *val = fork_exec_info.lookup_or_try_init(&pid, &zero);

    if (val) {
        val->mmap_calls++;
        val->mmap_bytes += len;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_munmap) {
    u64 len = args->len;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct counts zero = {};
    struct counts *val = fork_exec_info.lookup_or_try_init(&pid, &zero);

    if (val) {
        val->munmap_calls++;
        val->munmap_bytes += len;
    }
    return 0;
}
"""

b = BPF(text=program)
libc_path = BPF.find_library("c")
print("Using libc at:", libc_path)
b.attach_uprobe(name=libc_path, sym="malloc", fn_name="probe_malloc")
b.attach_uretprobe(name=libc_path, sym="malloc", fn_name="probe_malloc_ret")
b.attach_uprobe(name=libc_path, sym="free", fn_name="probe_free")

print("Tracing fork() and exec()... Press Ctrl+C to stop.")
while True:
    try:
        sleep(1)
        os.system("clear")
        print(f"{'PID':<6} {'MALLOC':<8} {'FREE':<8} "
        f"{'MALLOC_B':<12} {'FREE_B':<12} "
        f"{'MMAP':<8} {'MUNMAP':<8}")

        table = b["fork_exec_info"]
        for k, v in table.items():
            print(f"{k.value:<6} "
            f"{v.malloc_calls:<8} {v.free_calls:<8} "
            f"{v.malloc_bytes:<12} {v.free_bytes:<12} "
            f"{v.mmap_calls:<8} {v.munmap_calls:<8}")
    except KeyboardInterrupt:
        print("\nStopping...")
        break
