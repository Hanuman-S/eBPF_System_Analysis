from bcc import BPF
from time import sleep
import os
program = """
struct counts {
    u64 fork_count;
    u64 exec_count;
    u64 fork_ema;
    u64 exec_ema;
    u64 fork_last;
    u64 exec_last;
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
"""

b = BPF(text=program)
print("Tracing fork() and exec()... Press Ctrl+C to stop.")
while True:
    try:
        sleep(1)
        os.system("clear")
        print(f"{'PID':<8}{'FORK_CNT':<12}{'EXEC_CNT':<12}"
              f"{'FORK_EMA(us)':<18}{'EXEC_EMA(us)':<18}")

        table = b["fork_exec_info"]
        for k, v in table.items():
            print(f"{k.value:<8}"
                  f"{v.fork_count:<12}"
                  f"{v.exec_count:<12}"
                  f"{v.fork_ema/1000:<18.2f}"
                  f"{v.exec_ema/1000:<18.2f}")
    except KeyboardInterrupt:
        print("\nStopping...")
        break
