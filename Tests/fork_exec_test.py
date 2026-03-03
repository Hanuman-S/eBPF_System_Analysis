
import os
import time
import sys

NUM_FORKS = 10       
FORK_INTERVAL = 0.2  
EXEC_DELAY = 0.1     

def main():
    print(f"Parent PID: {os.getpid()}")
    
    for i in range(NUM_FORKS):
        pid = os.fork()
        if pid == 0:
            time.sleep(EXEC_DELAY)  
            print(f"Child PID {os.getpid()} calling exec()")
            os.execv("/bin/ls", ["ls"])
            sys.exit(1)
        else:
            time.sleep(FORK_INTERVAL)

    for _ in range(NUM_FORKS):
        os.wait()

    print("All children finished")

if __name__ == "__main__":
    main()
