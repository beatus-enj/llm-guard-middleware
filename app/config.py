"""配置管理 v2 — 新增告警、热更新、流式审核相关配置"""

import os
from dotenv import load_dotenv

load_dotenv(override=False)

def _bool(key, default="false"):
    return os.getenv(key, default).lower() == "true"

def _int(key, default):
    return int(os.getenv(key, str(default)))

def _float(key, default):
    return float(os.getenv(key, str(default)))


class Settings:
    def __init__(self):
        # 上游
        self.UPSTREAM_URL: str     = os.getenv("UPSTREAM_URL", "http://localhost:8080")
        self.UPSTREAM_TIMEOUT: float = _float("UPSTREAM_TIMEOUT", 120.0)

        # 监听
        self.HOST: str  = os.getenv("HOST", "0.0.0.0")
        self.PORT: int  = _int("PORT", 8000)

        # 功能开关
        self.ENABLE_RULE_ENGINE: bool = _bool("ENABLE_RULE_ENGINE", "true")
        self.ENABLE_ML_MODEL: bool    = _bool("ENABLE_ML_MODEL", "false")
        self.ENABLE_STREAM_GUARD: bool = _bool("ENABLE_STREAM_GUARD", "true")

        # ML
        self.ML_MODEL_NAME: str     = os.getenv("ML_MODEL_NAME", "unitary/toxic-bert")
        self.ML_MODEL_CACHE_DIR: str = os.getenv("ML_MODEL_CACHE_DIR", "./model_cache")
        self.ML_THRESHOLD: float    = _float("ML_THRESHOLD", 0.7)
        self.ML_INJECTION_THRESHOLD: float = _float("ML_INJECTION_THRESHOLD", 0.65)

        # 安全回复
        self.SAFE_REPLY_MESSAGE: str = os.getenv(
            "SAFE_REPLY_MESSAGE",
            "很抱歉，您的请求包含不当内容，无法处理。如有疑问请联系管理员。"
        )

        # 规则文件
        self.RULES_CONFIG: str = os.getenv("RULES_CONFIG", "./config/rules.yaml")

        # 热更新
        self.ENABLE_HOT_RELOAD: bool   = _bool("ENABLE_HOT_RELOAD", "true")
        self.HOT_RELOAD_POLL_SEC: float = _float("HOT_RELOAD_POLL_SEC", 2.0)

        # ── 告警配置 ──────────────────────────────────────────────────────
        self.ALERT_BLOCK_RATIO_THRESHOLD: float = _float("ALERT_BLOCK_RATIO_THRESHOLD", 0.5)
        self.ALERT_COOLDOWN_SEC: int   = _int("ALERT_COOLDOWN_SEC", 300)

        # Webhook（企业微信/飞书/钉钉/自定义）
        self.ALERT_WEBHOOK_URL: str    = os.getenv("ALERT_WEBHOOK_URL", "")
        self.ALERT_WEBHOOK_TYPE: str   = os.getenv("ALERT_WEBHOOK_TYPE", "generic")  # wecom|feishu|dingtalk|generic

        # SMTP
        self.ALERT_SMTP_HOST: str      = os.getenv("ALERT_SMTP_HOST", "")
        self.ALERT_SMTP_PORT: int      = _int("ALERT_SMTP_PORT", 587)
        self.ALERT_SMTP_TLS: bool      = _bool("ALERT_SMTP_TLS", "true")
        self.ALERT_SMTP_USER: str      = os.getenv("ALERT_SMTP_USER", "")
        self.ALERT_SMTP_PASSWORD: str  = os.getenv("ALERT_SMTP_PASSWORD", "")
        self.ALERT_SMTP_FROM: str      = os.getenv("ALERT_SMTP_FROM", "llm-guard@example.com")
        self.ALERT_SMTP_TO: str        = os.getenv("ALERT_SMTP_TO", "")
