"""配置管理 - 支持环境变量和 .env 文件覆盖"""

import os
from dotenv import load_dotenv

load_dotenv(override=False)


class Settings:
    def __init__(self):
        self.UPSTREAM_URL: str = os.getenv("UPSTREAM_URL", "http://localhost:8080")
        self.UPSTREAM_TIMEOUT: float = float(os.getenv("UPSTREAM_TIMEOUT", "120.0"))
        self.HOST: str = os.getenv("HOST", "0.0.0.0")
        self.PORT: int = int(os.getenv("PORT", "8000"))
        self.ENABLE_RULE_ENGINE: bool = os.getenv("ENABLE_RULE_ENGINE", "true").lower() == "true"
        self.ENABLE_ML_MODEL: bool = os.getenv("ENABLE_ML_MODEL", "false").lower() == "true"
        self.ML_MODEL_NAME: str = os.getenv("ML_MODEL_NAME", "unitary/toxic-bert")
        self.ML_MODEL_CACHE_DIR: str = os.getenv("ML_MODEL_CACHE_DIR", "./model_cache")
        self.ML_THRESHOLD: float = float(os.getenv("ML_THRESHOLD", "0.7"))
        self.ML_INJECTION_THRESHOLD: float = float(os.getenv("ML_INJECTION_THRESHOLD", "0.65"))
        self.SAFE_REPLY_MESSAGE: str = os.getenv(
            "SAFE_REPLY_MESSAGE",
            "很抱歉，您的请求包含不当内容，无法处理。如有疑问请联系管理员。"
        )
        self.RULES_CONFIG: str = os.getenv("RULES_CONFIG", "./config/rules.yaml")
