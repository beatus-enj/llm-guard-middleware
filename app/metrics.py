"""
metrics.py — 无外部依赖的 Prometheus 指标收集器

纯 stdlib 实现，线程安全，支持：
  - Counter / Histogram / Gauge
  - 1min/5min 滑动窗口速率
  - Prometheus text exposition format 0.0.4
"""

import time
import threading
from collections import deque
from typing import Dict, List, Tuple


class SlidingWindowCounter:
    """固定时间窗口内事件计数，用于实时速率计算"""
    def __init__(self, max_window_sec: int = 3600):
        self._lock = threading.Lock()
        self._events: deque = deque()
        self._max_window = max_window_sec

    def record(self, value: float = 1.0):
        now = time.time()
        with self._lock:
            self._events.append((now, value))
            cutoff = now - self._max_window
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()

    def rate(self, window_sec: int) -> float:
        now = time.time()
        cutoff = now - window_sec
        with self._lock:
            return sum(v for ts, v in self._events if ts >= cutoff)

    def rate_per_sec(self, window_sec: int) -> float:
        return self.rate(window_sec) / window_sec


class Histogram:
    BUCKETS = (1, 5, 10, 20, 30, 50, 75, 100, 150, 200, 500, 1000, float("inf"))

    def __init__(self):
        self._lock = threading.Lock()
        self._counts = [0] * len(self.BUCKETS)
        self._sum = 0.0
        self._total = 0

    def observe(self, value_ms: float):
        with self._lock:
            self._sum += value_ms
            self._total += 1
            for i, b in enumerate(self.BUCKETS):
                if value_ms <= b:
                    self._counts[i] += 1

    def snapshot(self):
        with self._lock:
            return list(self._counts), self._sum, self._total


class GuardMetrics:
    """LLM Guard 全部指标注册表"""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {
            "requests_total": 0,
            "blocked_total": 0,
            "passed_total": 0,
            "stream_chunks_total": 0,
            "stream_blocked_total": 0,
            "rule_hits_total": 0,
            "ml_hits_total": 0,
            "alert_sent_total": 0,
            "rule_reloads_total": 0,
            "errors_total": 0,
        }
        self._blocked_by_type: Dict[str, int] = {}
        self._blocked_by_source: Dict[str, int] = {}
        self._alerts_by_channel: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {
            "rule_count": 0, "ml_model_loaded": 0, "last_reload_ts": 0,
        }
        self.detect_latency = Histogram()
        self.request_latency = Histogram()
        self.req_window = SlidingWindowCounter()
        self.blocked_window = SlidingWindowCounter()
        self.latency_window = SlidingWindowCounter()
        self._start_time = time.time()

    def record_request(self, blocked: bool, latency_ms: float,
                       threat_type: str = None, source: str = None):
        self.req_window.record()
        self.request_latency.observe(latency_ms)
        with self._lock:
            self._counters["requests_total"] += 1
            if blocked:
                self._counters["blocked_total"] += 1
                self.blocked_window.record()
                if threat_type:
                    self._blocked_by_type[threat_type] = self._blocked_by_type.get(threat_type, 0) + 1
                if source:
                    self._blocked_by_source[source] = self._blocked_by_source.get(source, 0) + 1
                if source == "rule_engine":
                    self._counters["rule_hits_total"] += 1
                elif source == "ml_model":
                    self._counters["ml_hits_total"] += 1
            else:
                self._counters["passed_total"] += 1

    def record_detect_latency(self, latency_ms: float):
        self.detect_latency.observe(latency_ms)
        self.latency_window.record(latency_ms)

    def record_stream_chunk(self, blocked: bool = False):
        with self._lock:
            self._counters["stream_chunks_total"] += 1
            if blocked:
                self._counters["stream_blocked_total"] += 1

    def record_alert(self, channel: str):
        with self._lock:
            self._counters["alert_sent_total"] += 1
            self._alerts_by_channel[channel] = self._alerts_by_channel.get(channel, 0) + 1

    def record_rule_reload(self, rule_count: int):
        with self._lock:
            self._counters["rule_reloads_total"] += 1
            self._gauges["rule_count"] = rule_count
            self._gauges["last_reload_ts"] = time.time()

    def record_error(self):
        with self._lock:
            self._counters["errors_total"] += 1

    def set_gauge(self, name: str, value: float):
        with self._lock:
            self._gauges[name] = value

    def _fmt_histogram(self, name: str, hist: Histogram, help_text: str) -> str:
        counts, s, total = hist.snapshot()
        lines = [f"# HELP {name} {help_text}", f"# TYPE {name} histogram"]
        cumulative = 0
        for bucket, count in zip(hist.BUCKETS, counts):
            cumulative += count
            le = "+Inf" if bucket == float("inf") else (str(int(bucket)) if bucket == int(bucket) else str(bucket))
            lines.append(f'{name}_bucket{{le="{le}"}} {cumulative}')
        lines += [f"{name}_sum {s:.3f}", f"{name}_count {total}"]
        return "\n".join(lines)

    def exposition(self) -> str:
        """Prometheus text format 0.0.4"""
        now = time.time()
        with self._lock:
            c = dict(self._counters)
            bbt = dict(self._blocked_by_type)
            bbs = dict(self._blocked_by_source)
            abc = dict(self._alerts_by_channel)
            g = dict(self._gauges)

        L = []
        def counter(name, val, help_text):
            L.extend([f"# HELP {name} {help_text}", f"# TYPE {name} counter", f"{name} {val}"])
        def gauge(name, val, help_text):
            L.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {val}"])

        counter("llmguard_requests_total",       c["requests_total"],       "Total requests received")
        counter("llmguard_blocked_total",         c["blocked_total"],         "Total requests blocked")
        counter("llmguard_passed_total",          c["passed_total"],          "Requests passed to upstream")
        counter("llmguard_stream_chunks_total",   c["stream_chunks_total"],   "SSE chunks inspected")
        counter("llmguard_stream_blocked_total",  c["stream_blocked_total"],  "SSE chunks blocked")
        counter("llmguard_rule_hits_total",       c["rule_hits_total"],       "Blocks by rule engine")
        counter("llmguard_ml_hits_total",         c["ml_hits_total"],         "Blocks by ML model")
        counter("llmguard_alerts_total",          c["alert_sent_total"],      "Alerts sent")
        counter("llmguard_rule_reloads_total",    c["rule_reloads_total"],    "Hot-reload count")
        counter("llmguard_errors_total",          c["errors_total"],          "Internal errors")

        # 分组 counter
        L += ["# HELP llmguard_blocked_by_type_total Blocks by threat type",
               "# TYPE llmguard_blocked_by_type_total counter"]
        for t, n in bbt.items():
            L.append(f'llmguard_blocked_by_type_total{{threat_type="{t}"}} {n}')

        L += ["# HELP llmguard_blocked_by_source_total Blocks by source",
               "# TYPE llmguard_blocked_by_source_total counter"]
        for s, n in bbs.items():
            L.append(f'llmguard_blocked_by_source_total{{source="{s}"}} {n}')

        L += ["# HELP llmguard_alerts_by_channel_total Alerts by channel",
               "# TYPE llmguard_alerts_by_channel_total counter"]
        for ch, n in abc.items():
            L.append(f'llmguard_alerts_by_channel_total{{channel="{ch}"}} {n}')

        # 滑动窗口速率
        req1m  = self.req_window.rate(60);     blk1m  = self.blocked_window.rate(60)
        req5m  = self.req_window.rate(300);    blk5m  = self.blocked_window.rate(300)
        gauge("llmguard_requests_rate1m",  self.req_window.rate_per_sec(60),      "Req/s (1min window)")
        gauge("llmguard_blocked_rate1m",   self.blocked_window.rate_per_sec(60),  "Blocked/s (1min window)")
        gauge("llmguard_requests_rate5m",  self.req_window.rate_per_sec(300),     "Req/s (5min window)")
        gauge("llmguard_blocked_rate5m",   self.blocked_window.rate_per_sec(300), "Blocked/s (5min window)")
        gauge("llmguard_block_ratio_1m",   blk1m / req1m if req1m > 0 else 0,    "Block ratio 1min")
        gauge("llmguard_block_ratio_5m",   blk5m / req5m if req5m > 0 else 0,    "Block ratio 5min")

        lat_sum = self.latency_window.rate(60)
        avg_lat = lat_sum / req1m if req1m > 0 else 0.0
        gauge("llmguard_detect_latency_avg_ms", avg_lat,                 "Avg detect latency ms (1min)")
        gauge("llmguard_rule_count",            g.get("rule_count", 0),  "Active rules")
        gauge("llmguard_ml_model_loaded",       g.get("ml_model_loaded", 0), "ML model loaded 0/1")
        gauge("llmguard_uptime_seconds",        now - self._start_time,  "Process uptime seconds")
        gauge("llmguard_last_reload_timestamp", g.get("last_reload_ts", 0), "Unix ts of last reload")

        L.append(self._fmt_histogram("llmguard_detect_latency_ms",  self.detect_latency,  "Detection latency ms"))
        L.append(self._fmt_histogram("llmguard_request_latency_ms", self.request_latency, "Full request latency ms"))

        return "\n".join(L) + "\n"


_inst: GuardMetrics = None
_inst_lock = threading.Lock()

def get_metrics() -> GuardMetrics:
    global _inst
    if _inst is None:
        with _inst_lock:
            if _inst is None:
                _inst = GuardMetrics()
    return _inst
