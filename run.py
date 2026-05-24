#!/usr/bin/env python3
"""启动入口 - python run.py"""
"""
run.py v3 — FastAPI + uvicorn 启动入口
Step 3 改动：  
新: from app.main import app      uvicorn.run(...)       # 生产级 ASGI 服务器      
# start_watcher 已移入 lifespan，自动触发
"""
import logging
import uvicorn
from app.main import app, settings

if __name__ == "__main__":    
    logging.basicConfig(        
        level=logging.INFO,        
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",    
    )    
    uvicorn.run(        
        "app.main:app",        
        host=settings.HOST,        
        port=settings.PORT,        
        workers=1,           # 多核生产环境: workers=4        
        reload=False,        # 开发时可改 True（与 lifespan 兼容性较差）        
        log_level="info",        
        access_log=False,    # 用中间件自己的日志    
    )