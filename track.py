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

struct fs_metrics_t {
    u64 open_count;
    u64 read_bytes;
    u64 write_bytes;
    u64 unlink_count;
    u8 sensitive_access;
};

BPF_HASH(cpu_metrics, u32, struct cpu_metrics_t);

BPF_HASH(fs_metrics, u32, struct fs_metrics_t);

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

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 count = args->count;

    if(count < 512){
        return 0;
    }

    struct fs_metrics_t zero = {};
    struct fs_metrics_t *val = fs_metrics.lookup_or_try_init(&pid, &zero);

    if(val){
        val->read_bytes += count;
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 count = args->count;

    if(count < 512){
        return 0;
    }

    struct fs_metrics_t zero = {};
    struct fs_metrics_t *val = fs_metrics.lookup_or_try_init(&pid, &zero);

    if(val){
        val->write_bytes += count;
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fs_metrics_t zero = {};
    struct fs_metrics_t *val = fs_metrics.lookup_or_try_init(&pid, &zero);

    if(val){
        val->unlink_count++;
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fs_metrics_t zero = {};
    struct fs_metrics_t *val = fs_metrics.lookup_or_try_init(&pid, &zero);

    if(val) {
        val->open_count++;

        char fname[32];
        bpf_probe_read_user_str(fname, sizeof(fname), args->filename);

        if (fname[0]=='/' && fname[1]=='e' && fname[2]=='t' && fname[3]=='c' && fname[4]=='/') {
            if (fname[5]=='s' || fname[5]=='p')
                val->sensitive_access = 1;
        } else if (fname[0]=='/' && fname[1]=='r' && fname[2]=='o' && fname[3]=='o' && fname[4]=='t') {
            val->sensitive_access = 1;
        }
    }

    return 0;
}
"""

prev_cpu = {}
prev_fs  = {}

def get_proc_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except:
        return "?"

def print_cpu(b):
    table = b["cpu_metrics"]
    if not table:
        return

    print(f"\n{'PID':<8}{'NAME':<16}{'FORK':<8}{'EXEC':<8}"
          f"{'FORK_EMA(us)':<16}{'EXEC_EMA(us)':<16}"
          f"{'CPU(ms)':<12}{'CTX_SW':<10}{'INVOL':<8}")
    print("-" * 102)

    for k, v in sorted(table.items(), key=lambda x: x[1].cpu_time_ns, reverse=True):
        pid = k.value
        prev = prev_cpu.get(pid)

        if prev:
            delta_cpu  = v.cpu_time_ns   - prev['cpu_time_ns']
            delta_ctx  = v.ctx_switches  - prev['ctx_switches']
            delta_inv  = v.invol_switches - prev['invol_switches']
            if any(x < 0 for x in [delta_cpu, delta_ctx, delta_inv]):
                prev_cpu[pid] = {'cpu_time_ns': v.cpu_time_ns,
                                 'ctx_switches': v.ctx_switches,
                                 'invol_switches': v.invol_switches}
                continue
        else:
            delta_cpu = delta_ctx = delta_inv = 0

        prev_cpu[pid] = {'cpu_time_ns':    v.cpu_time_ns,
                         'ctx_switches':   v.ctx_switches,
                         'invol_switches': v.invol_switches}

        print(f"{pid:<8}"
              f"{get_proc_name(pid):<16}"
              f"{v.fork_count:<8}"
              f"{v.exec_count:<8}"
              f"{v.fork_ema/1000:<16.2f}"
              f"{v.exec_ema/1000:<16.2f}"
              f"{v.cpu_time_ns/1_000_000:<12.1f}"
              f"{v.ctx_switches:<10}"
              f"{v.invol_switches:<8}")

def print_fs(b):
    table = b["fs_metrics"]
    if not table:
        return

    print(f"\n{'PID':<8}{'NAME':<16}{'OPENS':<10}{'READS(KB)':<14}"
          f"{'WRITES(KB)':<14}{'UNLINKS':<10}{'SENSITIVE':<10}")
    print("-" * 82)

    for k, v in sorted(table.items(), key=lambda x: x[1].open_count, reverse=True):
        pid  = k.value
        prev = prev_fs.get(pid)

        if prev:
            delta_opens   = v.open_count   - prev['open_count']
            delta_reads   = v.read_bytes   - prev['read_bytes']
            delta_writes  = v.write_bytes  - prev['write_bytes']
            delta_unlinks = v.unlink_count - prev['unlink_count']
            if any(x < 0 for x in [delta_opens, delta_reads, delta_writes, delta_unlinks]):
                prev_fs[pid] = {'open_count':  v.open_count,
                                'read_bytes':  v.read_bytes,
                                'write_bytes': v.write_bytes,
                                'unlink_count': v.unlink_count}
                continue
        else:
            delta_opens = delta_reads = delta_writes = delta_unlinks = 0

        prev_fs[pid] = {'open_count':   v.open_count,
                        'read_bytes':   v.read_bytes,
                        'write_bytes':  v.write_bytes,
                        'unlink_count': v.unlink_count}

        sensitive = v.sensitive_access
        if sensitive:
            v.sensitive_access = 0
            table[k] = v

        print(f"{pid:<8}"
              f"{get_proc_name(pid):<16}"
              f"{delta_opens:<10}"
              f"{delta_reads/1024:<14.1f}"
              f"{delta_writes/1024:<14.1f}"
              f"{delta_unlinks:<10}"
              f"{'YES!!!!' if sensitive else 'no':<10}")


b = BPF(text=program)
print("Tracing... Press Ctrl+C to stop.")

while True:
    try:
        sleep(1)
        os.system("clear")
        print("=" * 102)
        print(f"  SNAPSHOT  {__import__('time').strftime('%H:%M:%S')}")
        print("=" * 102)
        print_cpu(b)
        print_fs(b)
    except KeyboardInterrupt:
        print("\nStopping...")
        break