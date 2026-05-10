#!/usr/bin/env python3
"""启动入口 - python run.py"""
from app.config import Settings
from app.main import app
import logging

if __name__ == "__main__":
    settings = Settings()
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    logger = logging.getLogger("llm-guard")
    logger.info(f"🛡️  LLM Guard Middleware 启动")
    logger.info(f"   上游地址: {settings.UPSTREAM_URL}")
    logger.info(f"   监听: http://{settings.HOST}:{settings.PORT}")
    logger.info(f"   规则引擎: {'✅' if settings.ENABLE_RULE_ENGINE else '❌'}")
    logger.info(f"   安全模型: {'✅' if settings.ENABLE_ML_MODEL else '❌'}")
    app.run(host=settings.HOST, port=settings.PORT, debug=False)
