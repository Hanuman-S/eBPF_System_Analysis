# detector.py
import math
import logging
import numpy as np
from sklearn.ensemble import IsolationForest    

logging.basicConfig(
    filename="anomalies.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

LEARNING_WINDOWS   = 6
Z_SCORE_THRESHOLD  = 2.5
GRACE_WINDOWS      = 5
UNLINK_HARD_LIMIT  = 20

FEATURE_KEYS = [
    "fork_delta", "exec_delta", "cpu_time_delta",
    "ctx_switches_delta", "invol_switches_delta",
    "open_delta", "read_delta", "write_delta", "unlink_delta",
    "malloc_delta", "free_delta", "heap_growth", "mmap_delta", "rss_delta"
]

# ── MetricTracker (unchanged) ─────────────────────────────────────────────────

class MetricTracker:
    def __init__(self, alpha=0.125):
        self.alpha        = alpha
        self.ema          = None
        self.variance     = 0.0
        self.window_count = 0
        self.consec_flags = 0
        self.prev_value   = None

    def update(self, value) -> dict:
        self.window_count += 1

        if self.ema is None:
            self.ema        = float(value)
            self.prev_value = float(value)
            return {"learning": True}

        if self.window_count <= LEARNING_WINDOWS:
            diff          = float(value) - self.ema
            self.variance = self.alpha * diff ** 2 + (1 - self.alpha) * self.variance
            self.ema      = self.alpha * float(value) + (1 - self.alpha) * self.ema
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
            diff          = float(value) - self.ema
            self.variance = self.alpha * diff ** 2 + (1 - self.alpha) * self.variance
            self.ema      = self.alpha * float(value) + (1 - self.alpha) * self.ema

        self.prev_value = float(value)
        return {
            "learning": False,
            "flagged":  flagged,
            "roc_flag": roc_flag,
            "z_score":  round(z_score, 2),
            "ema":      round(self.ema, 2),
            "stddev":   round(stddev, 2),
            "value":    value,
        }


# ── MLConfirmation: one Isolation Forest per flagged PID ─────────────────────

class MLConfirmation:
    """
    Activated only when EMA flags a PID.
    Collects feature vectors from all windows (including normal ones
    seen before flagging) to train on, then scores each new window.
    """

    MIN_TRAIN_SAMPLES = 10      # need at least this many windows before fitting
    CONTAMINATION     = 0.1     # expected fraction of anomalies in training data
    ANOMALY_SCORE_THRESHOLD = -0.1  # isolation forest scores: <0 = more anomalous

    def __init__(self, pid, name):
        self.pid         = pid
        self.name        = name
        self.history     = []       # all feature vectors seen so far
        self.model       = None
        self.fitted      = False

    def _fit(self):
        if len(self.history) >= self.MIN_TRAIN_SAMPLES:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.CONTAMINATION,
                random_state=42
            )
            self.model.fit(np.array(self.history))
            self.fitted = True

    def update(self, feature_vector: list) -> dict:
        """
        Feed a new window's feature vector.
        Returns confirmation result if model is fitted, else accumulating.
        """
        self.history.append(feature_vector)

        # try fitting if not yet fitted
        if not self.fitted:
            self._fit()
            return {"status": "accumulating", "samples": len(self.history)}

        vec    = np.array([feature_vector])
        score  = self.model.score_samples(vec)[0]   # more negative = more anomalous
        pred   = self.model.predict(vec)[0]          # -1 = anomaly, 1 = normal

        # refit periodically to adapt to new data (every 20 windows)
        if len(self.history) % 20 == 0:
            self._fit()

        return {
            "status":    "confirmed" if pred == -1 else "cleared",
            "score":     round(float(score), 4),
            "anomalous": pred == -1,
        }


# ── ProcessDetector ───────────────────────────────────────────────────────────

class ProcessDetector:

    CPU_METRICS = [
        "fork_delta", "exec_delta", "cpu_time_delta",
        "ctx_switches_delta", "invol_switches_delta"
    ]
    FS_METRICS = [
        "open_delta", "read_delta", "write_delta", "unlink_delta"
    ]
    MEM_METRICS = [
        "malloc_delta", "free_delta", "heap_growth", "mmap_delta", "rss_delta"
    ]

    def __init__(self, pid, name):
        self.pid     = pid
        self.name    = name
        self.metrics = {
            m: MetricTracker()
            for m in self.CPU_METRICS + self.FS_METRICS + self.MEM_METRICS
        }
        self.ml          = None          # created only when first EMA flag fires
        self.all_deltas  = {}            # accumulates current window's full vector

    def _alert(self, metric, result, ml_result=None):
        ml_str = ""
        if ml_result:
            if ml_result["status"] == "confirmed":
                ml_str = f" | ML=CONFIRMED (score={ml_result['score']})"
            elif ml_result["status"] == "cleared":
                ml_str = f" | ML=cleared (score={ml_result['score']})"
            else:
                ml_str = f" | ML=accumulating ({ml_result['samples']} samples)"

        msg = (f"[ALERT] PID={self.pid} ({self.name}) "
               f"metric={metric} "
               f"value={result.get('value')} "
               f"z={result.get('z_score')} "
               f"ema={result.get('ema')} "
               f"stddev={result.get('stddev')}"
               f"{ml_str}")
        print(f"\033[91m{msg}\033[0m")
        logging.info(msg)

    def _hard_alert(self, metric, value, reason, ml_result=None):
        ml_str = ""
        if ml_result:
            if ml_result["status"] == "confirmed":
                ml_str = f" | ML=CONFIRMED (score={ml_result['score']})"
            elif ml_result["status"] == "cleared":
                ml_str = f" | ML=cleared (score={ml_result['score']})"

        msg = (f"[HARD ALERT] PID={self.pid} ({self.name}) "
               f"metric={metric} value={value} reason={reason}"
               f"{ml_str}")
        print(f"\033[91m{msg}\033[0m")
        logging.info(msg)

    def _run_ml(self) -> dict | None:
        """
        Build feature vector from current window and run ML if active.
        Returns ml_result or None if ML not yet activated.
        """
        if self.ml is None:
            return None

        # build vector in fixed order matching FEATURE_KEYS
        vec = [float(self.all_deltas.get(k, 0)) for k in FEATURE_KEYS]
        return self.ml.update(vec)

    def _activate_ml(self):
        """Activate ML layer on first EMA flag for this PID."""
        if self.ml is None:
            self.ml = MLConfirmation(self.pid, self.name)
            msg = f"[ML ACTIVATED] PID={self.pid} ({self.name}) — EMA flagged, ML layer now tracking"
            print(f"\033[93m{msg}\033[0m")   # yellow
            logging.info(msg)

    def _commit_window(self, deltas: dict):
        """Merge this subsystem's deltas into the full window vector."""
        self.all_deltas.update(deltas)

    def _finish_window(self):
        """Call after all subsystems have been updated for this window."""
        self.all_deltas = {}

    # ── CPU ──────────────────────────────────────────────────────────────────

    def update_cpu(self, deltas: dict):
        self._commit_window(deltas)
        ema_flagged = False

        for metric, value in deltas.items():
            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                ema_flagged = True
                self._activate_ml()
                ml_result = self._run_ml()
                self._alert(metric, result, ml_result)

    # ── FS ───────────────────────────────────────────────────────────────────

    def update_fs(self, deltas: dict, sensitive: bool):
        self._commit_window(deltas)

        if sensitive:
            self._activate_ml()
            ml_result = self._run_ml()
            self._hard_alert("sensitive_access", 1,
                             "/etc or /root path opened", ml_result)

        for metric, value in deltas.items():
            if metric == "unlink_delta" and value > UNLINK_HARD_LIMIT:
                self._activate_ml()
                ml_result = self._run_ml()
                self._hard_alert(metric, value,
                                 f">{UNLINK_HARD_LIMIT} deletions in one window",
                                 ml_result)

            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                self._activate_ml()
                ml_result = self._run_ml()
                self._alert(metric, result, ml_result)

    # ── MEM ──────────────────────────────────────────────────────────────────

    def update_mem(self, deltas: dict):
        self._commit_window(deltas)

        if deltas.get("heap_growth", 0) > 0 and deltas.get("free_delta", 0) == 0:
            self._activate_ml()
            ml_result = self._run_ml()
            self._hard_alert("heap_leak_suspected", deltas["heap_growth"],
                             "malloc increasing without frees", ml_result)

        if deltas.get("mmap_delta", 0) > 0:
            self._activate_ml()
            ml_result = self._run_ml()
            self._hard_alert("mmap_leak_suspected", deltas["mmap_delta"],
                             "mmap increasing without munmap", ml_result)

        if deltas.get("rss_delta", 0) > 0 and deltas.get("malloc_delta", 0) == 0:
            self._activate_ml()
            ml_result = self._run_ml()
            self._hard_alert("rss_growth_no_alloc", deltas["rss_delta"],
                             "RSS growing without malloc", ml_result)

        for metric, value in deltas.items():
            result = self.metrics[metric].update(value)
            if result.get("learning") or result.get("rebased"):
                continue
            if result.get("flagged") or result.get("roc_flag"):
                self._activate_ml()
                ml_result = self._run_ml()
                self._alert(metric, result, ml_result)

    def finish_window(self):
        """Call once per window after all three subsystems are updated."""
        self._finish_window()


# ── Detector ──────────────────────────────────────────────────────────────────

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

    def finish_window(self, pid, name):
        """Call after all subsystems updated for a PID to reset window state."""
        self._get(pid, name).finish_window()