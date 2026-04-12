from bcc import BPF
from time import sleep
import os
import time
from detector import Detector

program = """
#include <uapi/linux/ptrace.h>
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

struct mem_metrics_t {
    u64 malloc_calls;
    u64 free_calls;
    u64 malloc_bytes;
    u64 free_bytes;
    u64 mmap_calls;
    u64 munmap_calls;
    u64 mmap_bytes;
    u64 munmap_bytes;
};

BPF_HASH(mem_metrics, u32, struct mem_metrics_t);

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

BPF_HASH(tmp_alloc, u64, u64);
BPF_HASH(active_alloc, u64, u64);

int probe_malloc(struct pt_regs *ctx){
    u64 size = PT_REGS_PARM1(ctx);
    u64 tid = bpf_get_current_pid_tgid();
    tmp_alloc.update(&tid, &size);
    return 0;
}

int probe_malloc_ret(struct pt_regs *ctx){
    u64 tid = bpf_get_current_pid_tgid();
    u64 *sizep = tmp_alloc.lookup(&tid);
    if(!sizep) return 0;

    u64 ptr = PT_REGS_RC(ctx);
    u64 size = *sizep;
    tmp_alloc.delete(&tid);

    u32 pid = tid >> 32;
    struct mem_metrics_t zero = {};
    struct mem_metrics_t *v = mem_metrics.lookup_or_try_init(&pid, &zero);

    if(v){
        v->malloc_calls++;
        v->malloc_bytes += size;
        active_alloc.update(&ptr, &size);
    }
    return 0;
}

int probe_free(struct pt_regs *ctx){
    u64 ptr = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *sizep = active_alloc.lookup(&ptr);

    struct mem_metrics_t zero = {};
    struct mem_metrics_t *v = mem_metrics.lookup_or_try_init(&pid, &zero);

    if(v){
        v->free_calls++;
        if(sizep){
            v->free_bytes += *sizep;
            active_alloc.delete(&ptr);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap){
    if(args->len < (1<<20)) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct mem_metrics_t zero = {};
    struct mem_metrics_t *v = mem_metrics.lookup_or_try_init(&pid, &zero);

    if(v){
        v->mmap_calls++;
        v->mmap_bytes += args->len;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_munmap){
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct mem_metrics_t zero = {};
    struct mem_metrics_t *v = mem_metrics.lookup_or_try_init(&pid, &zero);

    if(v){
        v->munmap_calls++;
        v->munmap_bytes += args->len;
    }
    return 0;
}
"""

# ── state ─────────────────────────────────────────────────────────────────────

prev_cpu = {}   # pid -> last cpu snapshot
prev_fs  = {}   # pid -> last fs snapshot
prev_mem = {}
detector = Detector()

# ── helpers ───────────────────────────────────────────────────────────────────

def get_proc_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except:
        return "?"

def get_rss(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except:
        return 0
    return 0

# ── display + detection ───────────────────────────────────────────────────────

def process_cpu(b):
    table = b["cpu_metrics"]
    if not table:
        return

    print(f"\n{'PID':<8}{'NAME':<16}{'FORK':<8}{'EXEC':<8}"
          f"{'FORK_EMA(us)':<16}{'EXEC_EMA(us)':<16}"
          f"{'CPU(ms)':<12}{'CTX_SW':<10}{'INVOL':<8}")
    print("-" * 102)

    for k, v in sorted(table.items(), key=lambda x: x[1].cpu_time_ns, reverse=True):
        pid  = k.value
        name = get_proc_name(pid)
        prev = prev_cpu.get(pid)

        if prev:
            fork_delta  = v.fork_count    - prev['fork_count']
            exec_delta  = v.exec_count    - prev['exec_count']
            cpu_delta   = v.cpu_time_ns   - prev['cpu_time_ns']
            ctx_delta   = v.ctx_switches  - prev['ctx_switches']
            inv_delta   = v.invol_switches - prev['invol_switches']

            # guard against pid reuse
            if any(x < 0 for x in [fork_delta, exec_delta, cpu_delta, ctx_delta, inv_delta]):
                prev_cpu[pid] = {
                    'fork_count':    v.fork_count,
                    'exec_count':    v.exec_count,
                    'cpu_time_ns':   v.cpu_time_ns,
                    'ctx_switches':  v.ctx_switches,
                    'invol_switches': v.invol_switches,
                }
                continue

            detector.update_cpu(pid, name, {
                "fork_delta":           fork_delta,
                "exec_delta":           exec_delta,
                "cpu_time_delta":       cpu_delta,
                "ctx_switches_delta":   ctx_delta,
                "invol_switches_delta": inv_delta,
            })
        else:
            fork_delta = exec_delta = cpu_delta = ctx_delta = inv_delta = 0

        prev_cpu[pid] = {
            'fork_count':    v.fork_count,
            'exec_count':    v.exec_count,
            'cpu_time_ns':   v.cpu_time_ns,
            'ctx_switches':  v.ctx_switches,
            'invol_switches': v.invol_switches,
        }

        print(f"{pid:<8}"
              f"{name:<16}"
              f"{v.fork_count:<8}"
              f"{v.exec_count:<8}"
              f"{v.fork_ema/1000:<16.2f}"
              f"{v.exec_ema/1000:<16.2f}"
              f"{v.cpu_time_ns/1_000_000:<12.1f}"
              f"{v.ctx_switches:<10}"
              f"{v.invol_switches:<8}")


def process_fs(b):
    table = b["fs_metrics"]
    if not table:
        return

    print(f"\n{'PID':<8}{'NAME':<16}{'OPENS':<10}{'READS(KB)':<14}"
          f"{'WRITES(KB)':<14}{'UNLINKS':<10}{'SENSITIVE':<10}")
    print("-" * 82)

    for k, v in sorted(table.items(), key=lambda x: x[1].open_count, reverse=True):
        pid  = k.value
        name = get_proc_name(pid)
        prev = prev_fs.get(pid)

        if prev:
            open_delta   = v.open_count   - prev['open_count']
            read_delta   = v.read_bytes   - prev['read_bytes']
            write_delta  = v.write_bytes  - prev['write_bytes']
            unlink_delta = v.unlink_count - prev['unlink_count']

            if any(x < 0 for x in [open_delta, read_delta, write_delta, unlink_delta]):
                prev_fs[pid] = {
                    'open_count':   v.open_count,
                    'read_bytes':   v.read_bytes,
                    'write_bytes':  v.write_bytes,
                    'unlink_count': v.unlink_count,
                }
                continue

            sensitive = bool(v.sensitive_access)

            detector.update_fs(pid, name, {
                "open_delta":   open_delta,
                "read_delta":   read_delta,
                "write_delta":  write_delta,
                "unlink_delta": unlink_delta,
            }, sensitive=sensitive)
        else:
            open_delta = read_delta = write_delta = unlink_delta = 0
            sensitive  = False

        prev_fs[pid] = {
            'open_count':   v.open_count,
            'read_bytes':   v.read_bytes,
            'write_bytes':  v.write_bytes,
            'unlink_count': v.unlink_count,
        }

        # reset sticky flag after reading
        if v.sensitive_access:
            v.sensitive_access = 0
            table[k] = v

        print(f"{pid:<8}"
              f"{name:<16}"
              f"{open_delta:<10}"
              f"{read_delta/1024:<14.1f}"
              f"{write_delta/1024:<14.1f}"
              f"{unlink_delta:<10}"
              f"{'YES ⚠' if sensitive else 'no':<10}")

def process_mem(b):
    table = b["mem_metrics"]
    if not table:
        return

    print(f"\n{'PID':<8}{'NAME':<16}"
          f"{'MALLOC':<10}{'FREE':<10}"
          f"{'HEAP':<12}{'MMAP':<12}{'RSS(KB)':<12}")
    print("-" * 90)

    for k, v in sorted(table.items(), key=lambda x: x[1].malloc_bytes, reverse=True):
        pid  = k.value
        name = get_proc_name(pid)
        prev = prev_mem.get(pid)

        rss = get_rss(pid)

        if prev:
            malloc_delta = v.malloc_calls - prev['malloc_calls']
            free_delta   = v.free_calls   - prev['free_calls']

            heap_now  = v.malloc_bytes - v.free_bytes
            heap_prev = prev['heap']
            heap_delta = heap_now - heap_prev

            mmap_now  = v.mmap_bytes - v.munmap_bytes
            mmap_prev = prev['mmap']
            mmap_delta = mmap_now - mmap_prev

            rss_delta = rss - prev['rss']

            if any(x < 0 for x in [malloc_delta, free_delta, heap_delta, mmap_delta, rss_delta]):
                prev_mem[pid] = {
                    'malloc_calls': v.malloc_calls,
                    'free_calls': v.free_calls,
                    'heap': heap_now,
                    'mmap': mmap_now,
                    'rss': rss
                }
                continue

            detector.update_mem(pid, name, {
                "malloc_delta": malloc_delta,
                "free_delta": free_delta,
                "heap_growth": heap_delta,
                "mmap_delta": mmap_delta,
                "rss_delta": rss_delta
            })

        else:
            malloc_delta = free_delta = heap_delta = mmap_delta = rss_delta = 0

        prev_mem[pid] = {
            'malloc_calls': v.malloc_calls,
            'free_calls': v.free_calls,
            'heap': v.malloc_bytes - v.free_bytes,
            'mmap': v.mmap_bytes - v.munmap_bytes,
            'rss': rss
        }

        print(f"{pid:<8}"
              f"{name:<16}"
              f"{malloc_delta:<10}"
              f"{free_delta:<10}"
              f"{heap_delta:<12}"
              f"{mmap_delta:<12}"
              f"{rss_delta:<12}")


# ── entry point ───────────────────────────────────────────────────────────────

b = BPF(text=program)
libc_path = BPF.find_library("c")
print("Using libc at:", libc_path)
b.attach_uprobe(name=libc_path, sym="malloc", fn_name="probe_malloc")
b.attach_uretprobe(name=libc_path, sym="malloc", fn_name="probe_malloc_ret")
b.attach_uprobe(name=libc_path, sym="free", fn_name="probe_free")
print("Tracing... Press Ctrl+C to stop.")

while True:
    try:
        sleep(5)
        os.system("clear")
        print("=" * 102)
        print(f"  SNAPSHOT  {time.strftime('%H:%M:%S')}")
        print("=" * 102)
        process_cpu(b)
        process_fs(b)
        process_mem(b)      
    except KeyboardInterrupt:
        print("\nStopping...")
        break