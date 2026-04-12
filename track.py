from bcc import BPF
from time import sleep
import os

program = """
struct cpu_metrics_t {
    u64 fork_count;
    u64 exec_count;
    u64 fork_ema;
    u64 exec_ema;
    u64 fork_last;
    u64 exec_last;
    u64 cpu_time_ns;
    u64 ctx_switches;
    u64 invol_switches;
    u64 last_sched_in_ts;
};

BPF_HASH(cpu_metrics, u32, struct cpu_metrics_t);

int kprobe__sys_clone(void *ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct cpu_metrics_t zero = {};
    struct cpu_metrics_t *val = cpu_metrics.lookup_or_try_init(&pid, &zero);
    if(val){
        val->fork_count++;
        u64 cts = bpf_ktime_get_ns();
        if(val->fork_last != 0){
            u64 delay = cts - val->fork_last;
            if(val->fork_ema != 0)
                val->fork_ema = val->fork_ema - (val->fork_ema >> 3) + (delay >> 3);
            else
                val->fork_ema = delay;
        }
        val->fork_last = cts;
    }
    return 0;
}

int kprobe__sys_execve(void *ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct cpu_metrics_t zero = {};
    struct cpu_metrics_t *val = cpu_metrics.lookup_or_try_init(&pid, &zero);
    if(val){
        val->exec_count++;
        u64 cts = bpf_ktime_get_ns();
        if(val->exec_last != 0){
            u64 delay = cts - val->exec_last;
            if(val->exec_ema != 0)
                val->exec_ema = val->exec_ema - (val->exec_ema >> 3) + (delay >> 3);
            else
                val->exec_ema = delay;
        }
        val->exec_last = cts;
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch){
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    struct cpu_metrics_t zero = {};
    u64 ts = bpf_ktime_get_ns();
    if(prev_pid){
        struct cpu_metrics_t *prev = cpu_metrics.lookup_or_try_init(&prev_pid, &zero);
        if(prev){
            if(prev->last_sched_in_ts)
                prev->cpu_time_ns += ts - prev->last_sched_in_ts;
            prev->ctx_switches++;
            if(args->prev_state == 0)
                prev->invol_switches++;
        }
    }
    if(next_pid){
        struct cpu_metrics_t *next = cpu_metrics.lookup(&next_pid);
        if(next)
            next->last_sched_in_ts = ts;
    }
    return 0;
}
"""

def get_proc_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except:
        return "?"

b = BPF(text=program)
print("Tracing... Press Ctrl+C to stop.")

while True:
    try:
        sleep(1)
        os.system("clear")
        print(f"{'PID':<8}{'NAME':<16}{'FORK':<8}{'EXEC':<8}"
              f"{'FORK_EMA(us)':<16}{'EXEC_EMA(us)':<16}"
              f"{'CPU(ms)':<12}{'CTX_SW':<10}{'INVOL':<8}")
        print("-" * 102)

        table = b["cpu_metrics"]
        for k, v in sorted(table.items(), key=lambda x: x[1].cpu_time_ns, reverse=True):
            pid = k.value
            print(f"{pid:<8}"
                  f"{get_proc_name(pid):<16}"
                  f"{v.fork_count:<8}"
                  f"{v.exec_count:<8}"
                  f"{v.fork_ema/1000:<16.2f}"
                  f"{v.exec_ema/1000:<16.2f}"
                  f"{v.cpu_time_ns/1_000_000:<12.1f}"
                  f"{v.ctx_switches:<10}"
                  f"{v.invol_switches:<8}")

    except KeyboardInterrupt:
        print("\nStopping...")
        break