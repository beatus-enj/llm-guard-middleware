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
