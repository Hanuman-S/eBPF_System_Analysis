# detector.py
import math
import logging
from datetime import datetime

logging.basicConfig(
    filename="anomalies.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

LEARNING_WINDOWS   = 6
Z_SCORE_THRESHOLD  = 2.5
GRACE_WINDOWS      = 5
UNLINK_HARD_LIMIT  = 20


class MetricTracker:
    def __init__(self, alpha=0.125):
        self.alpha          = alpha
        self.ema            = None
        self.variance       = 0.0
        self.window_count   = 0
        self.consec_flags   = 0
        self.prev_value     = None

    def update(self, value) -> dict:
        self.window_count += 1

        if self.ema is None:
            self.ema        = float(value)
            self.prev_value = float(value)
            return {"learning": True}

        if self.window_count <= LEARNING_WINDOWS:
            diff            = float(value) - self.ema
            self.variance   = self.alpha * diff ** 2 + (1 - self.alpha) * self.variance
            self.ema        = self.alpha * float(value) + (1 - self.alpha) * self.ema
            self.prev_value = float(value)
            return {"learning": True}

        stddev  = math.sqrt(self.variance) if self.variance > 0 else 0
        diff    = float(value) - self.ema
        z_score = diff / stddev if stddev > 0 else 0

        flagged  = abs(z_score) > Z_SCORE_THRESHOLD
        roc_flag = (self.prev_value > 0 and value > 2 * self.prev_value)

        if flagged or roc_flag:
            self.consec_flags += 1
            if self.consec_flags >= GRACE_WINDOWS:
                self.ema          = float(value)
                self.variance     = 0.0
                self.consec_flags = 0
                self.prev_value   = float(value)
                return {"rebased": True, "value": value}
        else:
            self.consec_flags = 0
            diff              = float(value) - self.ema
            self.variance     = self.alpha * diff ** 2 + (1 - self.alpha) * self.variance
            self.ema          = self.alpha * float(value) + (1 - self.alpha) * self.ema

        self.prev_value = float(value)

        return {
            "learning":  False,
            "flagged":   flagged,
            "roc_flag":  roc_flag,
            "z_score":   round(z_score, 2),
            "ema":       round(self.ema, 2),
            "stddev":    round(stddev, 2),
            "value":     value,
        }


class ProcessDetector:

    CPU_METRICS = [
        "fork_delta", "exec_delta", "cpu_time_delta",
        "ctx_switches_delta", "invol_switches_delta"
    ]

    FS_METRICS = [
        "open_delta", "read_delta", "write_delta", "unlink_delta"
    ]

    MEM_METRICS = [
        "malloc_delta",
        "free_delta",
        "heap_growth",
        "mmap_delta",
        "rss_delta"
    ]

    def __init__(self, pid, name):
        self.pid     = pid
        self.name    = name
        self.metrics = {
            m: MetricTracker()
            for m in self.CPU_METRICS + self.FS_METRICS + self.MEM_METRICS
        }

    def _alert(self, metric, result):
        msg = (f"[ALERT] PID={self.pid} ({self.name}) "
               f"metric={metric} "
               f"value={result.get('value')} "
               f"z={result.get('z_score')} "
               f"ema={result.get('ema')} "
               f"stddev={result.get('stddev')}")
        print(f"\033[91m{msg}\033[0m")
        logging.info(msg)

    def _hard_alert(self, metric, value, reason):
        msg = (f"[HARD ALERT] PID={self.pid} ({self.name}) "
               f"metric={metric} value={value} reason={reason}")
        print(f"\033[91m{msg}\033[0m")
        logging.info(msg)

    # ───────────────── CPU ─────────────────

    def update_cpu(self, deltas: dict):
        for metric, value in deltas.items():
            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                self._alert(metric, result)

    # ───────────────── FS ─────────────────

    def update_fs(self, deltas: dict, sensitive: bool):

        if sensitive:
            self._hard_alert("sensitive_access", 1, "/etc or /root path opened")

        for metric, value in deltas.items():
            if metric == "unlink_delta" and value > UNLINK_HARD_LIMIT:
                self._hard_alert(metric, value,
                                 f">{UNLINK_HARD_LIMIT} deletions in one window")

            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                self._alert(metric, result)

    # ───────────────── MEMORY ─────────────────

    def update_mem(self, deltas: dict):
        """
        deltas = {
            malloc_delta,
            free_delta,
            heap_growth,
            mmap_delta,
            rss_delta
        }
        """

        # Heap leak: malloc increasing but no frees
        if deltas["heap_growth"] > 0 and deltas["free_delta"] == 0:
            self._hard_alert(
                "heap_leak_suspected",
                deltas["heap_growth"],
                "malloc increasing without frees"
            )

        # mmap leak: mmap growing without munmap
        if deltas["mmap_delta"] > 0:
            self._hard_alert(
                "mmap_leak_suspected",
                deltas["mmap_delta"],
                "mmap increasing without munmap"
            )

        # RSS anomaly: memory growing without allocation activity
        if deltas["rss_delta"] > 0 and deltas["malloc_delta"] == 0:
            self._hard_alert(
                "rss_growth_no_alloc",
                deltas["rss_delta"],
                "RSS growing without malloc"
            )

        # Statistical detection (EMA + Z-score)
        for metric, value in deltas.items():
            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                self._alert(metric, result)


class Detector:

    def __init__(self):
        self.processes = {}

    def _get(self, pid, name) -> ProcessDetector:
        if pid not in self.processes:
            self.processes[pid] = ProcessDetector(pid, name)
        return self.processes[pid]

    def remove(self, pid):
        self.processes.pop(pid, None)

    def update_cpu(self, pid, name, deltas: dict):
        self._get(pid, name).update_cpu(deltas)

    def update_fs(self, pid, name, deltas: dict, sensitive: bool):
        self._get(pid, name).update_fs(deltas, sensitive)

    def update_mem(self, pid, name, deltas: dict):
        self._get(pid, name).update_mem(deltas)