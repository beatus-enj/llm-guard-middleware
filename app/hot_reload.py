"""
hot_reload.py — 规则文件热更新监控

使用 watchdog 监听 rules.yaml 文件变化，
变化后原子性地重建规则引擎，并触发告警通知。
"""

import logging
import threading
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger("llm-guard.hot_reload")


class RuleFileWatcher:
    """
    监控规则文件修改时间，变化时回调 on_reload(new_rule_count)。
    使用轮询而非 inotify，避免 watchdog 依赖问题，兼容所有 OS。
    """

    def __init__(self, rules_path: str, on_reload: Callable[[int, bool, str], None],
                 poll_interval: float = 2.0):
        self.rules_path = Path(rules_path)
        self.on_reload = on_reload
        self.poll_interval = poll_interval
        self._last_mtime: float = self._get_mtime()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="rule-watcher")

    def start(self):
        self._thread.start()
        logger.info(f"⏱  规则热更新监控启动: {self.rules_path} (轮询间隔 {self.poll_interval}s)")

    def stop(self):
        self._stop_event.set()

    def _get_mtime(self) -> float:
        try:
            return self.rules_path.stat().st_mtime
        except FileNotFoundError:
            return 0.0

    def _poll_loop(self):
        while not self._stop_event.is_set():
            time.sleep(self.poll_interval)
            try:
                mtime = self._get_mtime()
                if mtime != self._last_mtime and mtime > 0:
                    self._last_mtime = mtime
                    logger.info(f"🔄 检测到规则文件变化: {self.rules_path}")
                    # 延迟 200ms 等待文件写入完成
                    time.sleep(0.2)
                    self.on_reload()
            except Exception as e:
                logger.error(f"热更新监控异常: {e}")


# 也支持 watchdog（如果可用，使用事件驱动替代轮询）
def try_watchdog_watcher(rules_path: str, on_reload: Callable,
                         poll_interval: float = 2.0) -> RuleFileWatcher:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class _Handler(FileSystemEventHandler):
            def __init__(self, path, callback):
                self._path = str(Path(path).resolve())
                self._callback = callback
                self._debounce_timer = None
                self._lock = threading.Lock()

            def on_modified(self, event):
                if not event.is_directory and str(Path(event.src_path).resolve()) == self._path:
                    with self._lock:
                        if self._debounce_timer:
                            self._debounce_timer.cancel()
                        self._debounce_timer = threading.Timer(0.3, self._callback)
                        self._debounce_timer.daemon = True
                        self._debounce_timer.start()

        class _WatchdogWatcher:
            def __init__(self):
                self._obs = Observer()
                handler = _Handler(rules_path, on_reload)
                watch_dir = str(Path(rules_path).parent.resolve())
                self._obs.schedule(handler, watch_dir, recursive=False)

            def start(self):
                self._obs.start()
                logger.info(f"⚡ 使用 watchdog inotify 监控: {rules_path}")

            def stop(self):
                self._obs.stop()

        return _WatchdogWatcher()

    except ImportError:
        logger.info("watchdog 不可用，降级为轮询模式")
        return RuleFileWatcher(rules_path, on_reload, poll_interval)
