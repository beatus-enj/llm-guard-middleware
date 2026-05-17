#!/usr/bin/env python3
"""启动入口 - python run.py"""
import logging
from app.config import Settings
from app.main import app, start_watcher, settings as app_settings

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    logger = logging.getLogger("llm-guard")
    logger.info("🛡️  LLM Guard Middleware v2 启动")
    logger.info(f"   上游: {app_settings.UPSTREAM_URL}")
    logger.info(f"   监听: http://{app_settings.HOST}:{app_settings.PORT}")
    logger.info(f"   规则引擎: {'✅' if app_settings.ENABLE_RULE_ENGINE else '❌'}")
    logger.info(f"   ML模型: {'✅' if app_settings.ENABLE_ML_MODEL else '❌'}")
    logger.info(f"   流式审核: {'✅' if app_settings.ENABLE_STREAM_GUARD else '❌'}")
    logger.info(f"   热更新: {'✅' if app_settings.ENABLE_HOT_RELOAD else '❌'}")
    logger.info(f"   Prometheus: http://{app_settings.HOST}:{app_settings.PORT}/metrics")
    logger.info(f"   Grafana:    http://localhost:3000  (docker-compose)")

    # 启动热更新监控（仅在真实运行时，不在测试时）
    start_watcher()

    app.run(host=app_settings.HOST, port=app_settings.PORT,
            debug=False, threaded=True)
