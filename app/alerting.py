"""
alerting.py — 多维告警引擎

支持渠道：
  - Webhook（企业微信 / 飞书 / 钉钉 / 自定义）
  - SMTP 邮件
  - 日志文件（始终开启，作为兜底）

告警策略：
  - 拦截率超阈值（1min 窗口）
  - 单 IP 高频攻击
  - 新型威胁类型首次出现
  - 规则热更新成功/失败

防抖：每个 alert_key 冷却时间内只发一次

alerting.py v3 — 保留原有 AlertManager 和 AlertCooldown，
新增 AsyncAlertManager（Step 4：daemon 线程 → asyncio.Task）
迁移对比：  
queue.Queue      →  asyncio.Queue  
threading.Thread →  asyncio.Task（由 lifespan 管理）  
urllib.request   →  httpx.AsyncClient（异步，不阻塞事件循环）  
smtplib          →  loop.run_in_executor 包装（无原生 async 支持）
"""

import json
import logging
import smtplib
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from app.config import Settings

logger = logging.getLogger("llm-guard.alerting")
import asyncio


class AlertCooldown:
    """防抖 - 同一告警 key 在冷却期内只触发一次"""
    def __init__(self, cooldown_sec: int = 300):
        self._lock = threading.Lock()
        self._last: dict = {}
        self.cooldown = cooldown_sec

    def should_alert(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._last.get(key, 0)
            if now - last >= self.cooldown:
                self._last[key] = now
                return True
            return False


class AlertManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.cooldown = AlertCooldown(settings.ALERT_COOLDOWN_SEC)
        self._lock = threading.Lock()
        self._seen_threat_types: set = set()
        # 异步发送队列，避免阻塞检测主路径
        self._queue: list = []
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()
        logger.info(f"告警引擎启动 | webhook={'✅' if settings.ALERT_WEBHOOK_URL else '❌'} "
                    f"smtp={'✅' if settings.ALERT_SMTP_HOST else '❌'}")

    # ── 公开接口 ──────────────────────────────────────────────────────────────

    def check_block_rate(self, block_ratio: float, req_count: int):
        """拦截率告警"""
        threshold = self.settings.ALERT_BLOCK_RATIO_THRESHOLD
        if block_ratio >= threshold and req_count >= 5:
            key = "high_block_ratio"
            if self.cooldown.should_alert(key):
                self._enqueue("🚨 高拦截率告警", (
                    f"过去1分钟拦截率: **{block_ratio:.1%}**\n"
                    f"请求总量: {req_count}\n"
                    f"阈值: {threshold:.0%}"
                ), level="critical", key=key)

    def check_new_threat_type(self, threat_type: str):
        """新威胁类型首次出现"""
        with self._lock:
            if threat_type not in self._seen_threat_types:
                self._seen_threat_types.add(threat_type)
                key = f"new_threat_{threat_type}"
                if self.cooldown.should_alert(key):
                    self._enqueue("🆕 新型威胁类型", (
                        f"首次检测到威胁类型: `{threat_type}`\n"
                        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    ), level="warning", key=key)

    def notify_rule_reload(self, success: bool, rule_count: int, error: str = ""):
        """规则热更新通知"""
        if success:
            key = f"rule_reload_ok_{int(time.time() // 60)}"
            if self.cooldown.should_alert(key):
                self._enqueue("🔄 规则热更新成功", (
                    f"新规则总数: {rule_count}\n"
                    f"更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                ), level="info", key=key)
        else:
            self._enqueue("❌ 规则热更新失败", (
                f"错误信息: {error}\n"
                f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            ), level="critical", key=f"rule_reload_fail_{time.time()}")

    def notify_block(self, threat_type: str, reason: str, text_snippet: str):
        """高危拦截实时通知（只通知严重类型）"""
        critical_types = {"harmful_content", "weapon", "malware"}
        if threat_type not in critical_types:
            return
        key = f"block_{threat_type}"
        if self.cooldown.should_alert(key):
            self._enqueue("🚫 高危内容拦截", (
                f"威胁类型: `{threat_type}`\n"
                f"原因: {reason}\n"
                f"内容片段: `{text_snippet[:100]}`"
            ), level="warning", key=key)

    # ── 内部发送队列 ──────────────────────────────────────────────────────────

    def _enqueue(self, title: str, body: str, level: str = "warning", key: str = ""):
        with self._lock:
            self._queue.append((title, body, level, key, time.time()))

    def _worker_loop(self):
        while True:
            time.sleep(0.5)
            with self._lock:
                items = list(self._queue)
                self._queue.clear()
            for title, body, level, key, ts in items:
                self._dispatch(title, body, level)

    def _dispatch(self, title: str, body: str, level: str):
        # 1. 始终写日志
        log_fn = logger.critical if level == "critical" else (
            logger.warning if level == "warning" else logger.info)
        log_fn(f"[ALERT] {title} | {body.replace(chr(10), ' | ')}")

        from app.metrics import get_metrics  # 避免循环导入

        # 2. Webhook
        if self.settings.ALERT_WEBHOOK_URL:
            try:
                self._send_webhook(title, body, level)
                get_metrics().record_alert("webhook")
            except Exception as e:
                logger.error(f"Webhook 发送失败: {e}")

        # 3. SMTP
        if self.settings.ALERT_SMTP_HOST and self.settings.ALERT_SMTP_TO:
            try:
                self._send_email(title, body, level)
                get_metrics().record_alert("email")
            except Exception as e:
                logger.error(f"邮件发送失败: {e}")

        get_metrics().record_alert("log")

    def _send_webhook(self, title: str, body: str, level: str):
        """发送到企业微信/飞书/钉钉/自定义 Webhook"""
        url = self.settings.ALERT_WEBHOOK_URL
        wtype = self.settings.ALERT_WEBHOOK_TYPE.lower()
        color_map = {"critical": "#FF0000", "warning": "#FF8C00", "info": "#36A64F"}
        color = color_map.get(level, "#808080")

        if wtype == "wecom":
            # 企业微信 Markdown
            payload = {"msgtype": "markdown", "markdown": {
                "content": f"## {title}\n{body}\n> 来自 LLM Guard Middleware"
            }}
        elif wtype == "feishu":
            # 飞书卡片
            payload = {"msg_type": "interactive", "card": {
                "header": {"title": {"content": title, "tag": "plain_text"},
                           "template": "red" if level == "critical" else "orange"},
                "elements": [{"tag": "div", "text": {"content": body, "tag": "lark_md"}}]
            }}
        elif wtype == "dingtalk":
            # 钉钉 Markdown
            payload = {"msgtype": "markdown", "markdown": {
                "title": title,
                "text": f"## {title}\n{body}"
            }}
        else:
            # 通用 JSON
            payload = {"title": title, "body": body, "level": level,
                       "source": "llm-guard", "timestamp": int(time.time())}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()

    def _send_email(self, title: str, body: str, level: str):
        s = self.settings
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[LLM Guard][{level.upper()}] {title}"
        msg["From"] = s.ALERT_SMTP_FROM
        msg["To"] = s.ALERT_SMTP_TO
        html = f"""<html><body>
<h2 style="color:{'red' if level=='critical' else 'orange'}">{title}</h2>
<pre style="background:#f4f4f4;padding:12px">{body}</pre>
<hr/><small>LLM Guard Middleware — {time.strftime('%Y-%m-%d %H:%M:%S')}</small>
</body></html>"""
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(s.ALERT_SMTP_HOST, s.ALERT_SMTP_PORT, timeout=10) as smtp:
            if s.ALERT_SMTP_TLS:
                smtp.starttls()
            if s.ALERT_SMTP_USER:
                smtp.login(s.ALERT_SMTP_USER, s.ALERT_SMTP_PASSWORD)
            smtp.sendmail(s.ALERT_SMTP_FROM, s.ALERT_SMTP_TO.split(","), msg.as_string())
# ════════════════════════════════════════════════════════════════════════════
#  AsyncAlertManager — Step 4 新增（FastAPI v3 使用）
# ════════════════════════════════════════════════════════════════════════════

class AsyncAlertManager:
    """
    Step 4 迁移：daemon 线程 → asyncio.Task

    改动点：
      queue.Queue       →  asyncio.Queue（与事件循环天然集成）
      threading.Thread  →  asyncio.Task（由 lifespan 管理，cancel 优雅退出）
      urllib.request    →  httpx.AsyncClient（异步，不阻塞事件循环）
      smtplib           →  loop.run_in_executor（线程池包装同步库）

    调用方式变化：
      旧: alerter.check_and_alert(result, ratio)         # 同步
      新: asyncio.create_task(alerter.check_and_alert(...))  # fire-and-forget
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.cooldown = AlertCooldown(settings.ALERT_COOLDOWN_SEC)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._seen_threat_types: set = set()
        self._seen_lock = asyncio.Lock()
        logger.info(f"异步告警引擎初始化 | "
                    f"webhook={'✅' if settings.ALERT_WEBHOOK_URL else '❌'} "
                    f"smtp={'✅' if settings.ALERT_SMTP_HOST else '❌'}")

    # ── Step 4: worker 是协程，由 lifespan 作为 Task 启动 ──────────────────

    async def worker_loop(self):
        """
        后台协程，消费告警队列。
        对比旧版 _worker_loop（daemon 线程 + time.sleep(0.5)）：
          - 不占用线程，协程轻量
          - asyncio.wait_for 超时继续，不是 sleep 轮询
          - CancelledError 信号优雅退出，资源确保释放
        """
        logger.info("异步告警 worker 启动")
        while True:
            try:
                title, body, level = await asyncio.wait_for(
                    self._queue.get(), timeout=5.0
                )
                await self._dispatch(title, body, level)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("告警 worker 退出")
                break
            except Exception as e:
                logger.error(f"告警 worker 异常: {e}")

    # ── 公开接口（均为协程）────────────────────────────────────────────────

    async def check_and_alert(self, result: dict, block_ratio: float):
        """检测完成后调用。调用方: asyncio.create_task(alerter.check_and_alert(...))"""
        await self.check_new_threat_type(result.get("threat_type", "unknown"))
        await self.check_block_rate(block_ratio)

    async def check_new_threat_type(self, threat_type: str):
        async with self._seen_lock:
            if threat_type in self._seen_threat_types:
                return
            self._seen_threat_types.add(threat_type)
        if self.cooldown.should_alert(f"new_threat_{threat_type}"):
            await self._enqueue(
                f"🆕 新型威胁: {threat_type}",
                f"首次检测到 [{threat_type}]\n时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            )

    async def check_block_rate(self, ratio: float):
        threshold = self.settings.ALERT_BLOCK_RATIO_THRESHOLD
        if ratio >= threshold and self.cooldown.should_alert("high_block_ratio"):
            await self._enqueue(
                f"🚨 高拦截率: {ratio:.0%}",
                f"1分钟拦截率 {ratio:.1%} 超过阈值 {threshold:.0%}",
                level="critical",
            )

    async def notify_rule_reload(self, success: bool, rule_count: int, error: str = ""):
        if success:
            key = f"reload_ok_{int(time.time() // 60)}"
            if self.cooldown.should_alert(key):
                await self._enqueue("🔄 规则热更新成功", f"规则数: {rule_count} 条")
        else:
            # 失败告警不受冷却限制
            await self._enqueue("❌ 规则热更新失败", f"错误: {error}", level="critical")

    # ── 内部：入队 & 分发 ──────────────────────────────────────────────────

    async def _enqueue(self, title: str, body: str, level: str = "warning"):
        """
        非阻塞入队。
        旧: self._queue.append(...)  # list，有锁
        新: self._queue.put_nowait(...)  # asyncio.Queue，QueueFull 时丢弃
        """
        try:
            self._queue.put_nowait((title, body, level))
        except asyncio.QueueFull:
            logger.warning(f"告警队列满，丢弃: {title[:40]}")

    async def _dispatch(self, title: str, body: str, level: str):
        """实际发送，所有 I/O 均异步"""
        log_fn = logger.critical if level == "critical" else (
            logger.warning if level == "warning" else logger.info)
        log_fn(f"[ALERT/{level.upper()}] {title}")

        from app.metrics import get_metrics
        m = get_metrics()

        tasks = []
        if self.settings.ALERT_WEBHOOK_URL:
            tasks.append(self._send_webhook(title, body, level))
        if getattr(self.settings, "ALERT_SMTP_HOST", ""):
            loop = asyncio.get_event_loop()
            tasks.append(
                loop.run_in_executor(None, self._send_email_sync, title, body, level)
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"告警发送失败: {r}")

        m.record_alert("log")

    async def _send_webhook(self, title: str, body: str, level: str):
        """
        Step 4 改动：urllib.request → httpx.AsyncClient
        旧: urllib.request.urlopen(req, timeout=5)   # 同步阻塞
        新: await client.post(url, json=payload)     # 异步，不阻塞事件循环
        """
        try:
            import httpx as _httpx
            url = self.settings.ALERT_WEBHOOK_URL
            wtype = getattr(self.settings, "ALERT_WEBHOOK_TYPE", "generic").lower()
            payloads = {
                "wecom":    {"msgtype": "markdown",
                             "markdown": {"content": f"## {title}\n{body}\n> 来自 LLM Guard"}},
                "feishu":   {"msg_type": "text",
                             "content": {"text": f"{title}\n{body}"}},
                "dingtalk": {"msgtype": "markdown",
                             "markdown": {"title": title, "text": f"## {title}\n{body}"}},
                "generic":  {"title": title, "body": body, "level": level,
                             "source": "llm-guard", "timestamp": int(time.time())},
            }
            payload = payloads.get(wtype, payloads["generic"])
            async with _httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}")
            from app.metrics import get_metrics
            get_metrics().record_alert("webhook")
        except Exception as e:
            raise RuntimeError(f"Webhook 失败: {e}") from e

    def _send_email_sync(self, title: str, body: str, level: str):
        """
        Step 4 改动：smtplib 无原生 async，用 run_in_executor 在线程池运行。
        函数本身仍是同步的，由 asyncio 负责调度到线程池。
        """
        s = self.settings
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[LLM Guard][{level.upper()}] {title}"
            msg["From"] = getattr(s, "ALERT_SMTP_FROM", "llm-guard@example.com")
            msg["To"] = getattr(s, "ALERT_SMTP_TO", "")
            color = {"critical": "red", "warning": "orange"}.get(level, "green")
            html = (f"<html><body><h2 style='color:{color}'>{title}</h2>"
                    f"<pre style='background:#f4f4f4;padding:12px'>{body}</pre>"
                    f"<hr/><small>LLM Guard — {time.strftime('%Y-%m-%d %H:%M:%S')}</small>"
                    f"</body></html>")
            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(html, "html"))
            port = getattr(s, "ALERT_SMTP_PORT", 587)
            with smtplib.SMTP(s.ALERT_SMTP_HOST, port, timeout=10) as smtp:
                if getattr(s, "ALERT_SMTP_TLS", True):
                    smtp.starttls()
                if getattr(s, "ALERT_SMTP_USER", ""):
                    smtp.login(s.ALERT_SMTP_USER, s.ALERT_SMTP_PASSWORD)
                smtp.sendmail(msg["From"], msg["To"].split(","), msg.as_string())
            from app.metrics import get_metrics
            get_metrics().record_alert("email")
        except Exception as e:
            raise RuntimeError(f"SMTP 失败: {e}") from e