"""
main.py v3 — LLM Guard Middleware（FastAPI 迁移版）

从 Flask v2 迁移记录：
  Step 1  改路由    @app.route → @app.post/@app.get, def → async def
  Step 2  改代理    requests.request → httpx.AsyncClient, iter_content → aiter_bytes
  Step 3  改生命周期 start_watcher()/daemon线程 → @asynccontextmanager lifespan
  Step 4  改告警    AlertManager(线程) → AsyncAlertManager(asyncio.Task)
"""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from app.config import Settings
from app.detector import ContentDetector
from app.metrics import get_metrics
from app.alerting import AsyncAlertManager
from app.hot_reload import try_watchdog_watcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("llm-guard")

# ── 全局单例 ──────────────────────────────────────────────────────────────────
settings    = Settings()
detector    = ContentDetector(settings)
metrics     = get_metrics()
alerter     = AsyncAlertManager(settings)   # Step 4: 原 AlertManager(settings)
_watcher    = None
_start_time = time.time()


# ── Step 3: 热更新回调（watchdog线程 → asyncio事件循环桥接）─────────────────

def _on_rule_reload():
    """
    v3 alerter 是异步的，run_coroutine_threadsafe 桥接到主事件循环。
    """
    success, count, err = detector.hot_reload()
    metrics.record_rule_reload(count if success else 0)
    metrics.set_gauge("rule_count", float(count))
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                alerter.notify_rule_reload(success, count, err), loop
            )
    except RuntimeError:
        pass


# ── Step 3: lifespan（替代分散的 start_watcher() + daemon线程）──────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    v3 集中到 lifespan：
      - yield 前：启动告警 Task、文件监控
      - yield 后：cancel Task、stop watcher（资源确保释放）
    """
    global _watcher

    # 1. 告警后台协程（替代 daemon 线程）
    alert_task = asyncio.create_task(alerter.worker_loop(), name="alert-worker")

    # 2. 热更新文件监控
    if settings.ENABLE_HOT_RELOAD:
        _watcher = try_watchdog_watcher(
            settings.RULES_CONFIG, _on_rule_reload, settings.HOT_RELOAD_POLL_SEC
        )
        _watcher.start()

    # 3. 初始化指标
    metrics.set_gauge("rule_count", float(detector.rule_count))
    metrics.set_gauge("ml_model_loaded", 1.0 if detector.model_loaded else 0.0)

    logger.info("🛡️  LLM Guard Middleware v3 (FastAPI) 启动")
    logger.info(f"   上游:     {settings.UPSTREAM_URL}")
    logger.info(f"   规则数:   {detector.rule_count} 条")
    logger.info(f"   流式审核: {'✅' if settings.ENABLE_STREAM_GUARD else '❌'}")
    logger.info(f"   热更新:   {'✅' if settings.ENABLE_HOT_RELOAD else '❌'}")
    logger.info(f"   ML 模型:  {'✅' if detector.model_loaded else '❌'}")
    logger.info(f"   文档:     http://localhost:{settings.PORT}/docs")
    logger.info(f"   指标:     http://localhost:{settings.PORT}/metrics")

    yield  # ← 应用在此运行

    # 关闭清理
    alert_task.cancel()
    try:
        await alert_task
    except asyncio.CancelledError:
        pass
    if _watcher:
        _watcher.stop()
    logger.info("LLM Guard 已关闭")



app = FastAPI(
    title="LLM Guard Middleware",
    description="Prompt注入 & 有害内容安全代理 | 流式审核 | 规则热更新 | Prometheus指标",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ════════════════════════════════════════════════════════════════════════════
#  辅助函数（逻辑与 v2 完全相同）
# ════════════════════════════════════════════════════════════════════════════

def extract_text(body: dict) -> str:
    texts = []
    for msg in body.get("messages", []):
        c = msg.get("content", "")
        if isinstance(c, str):
            texts.append(c)
        elif isinstance(c, list):
            texts.extend(p["text"] for p in c if isinstance(p, dict) and p.get("type") == "text")
    if "prompt" in body:
        p = body["prompt"]
        texts.extend([p] if isinstance(p, str) else [str(x) for x in p])
    return "\n".join(texts)


def build_safe_response(body: dict, result: dict) -> dict:
    guard = {
        "blocked": True,
        "reason": result.get("reason", ""),
        "threat_type": result.get("threat_type", ""),
        "latency_ms": round(result.get("latency_ms", 0.0), 3),
    }
    if "messages" in body:
        return {
            "id": "chatcmpl-guard-blocked", "object": "chat.completion", "created": 0,
            "model": body.get("model", "guarded"),
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": settings.SAFE_REPLY_MESSAGE},
                         "finish_reason": "stop", "logprobs": None}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "_guard": guard,
        }
    return {
        "id": "cmpl-guard-blocked", "object": "text_completion", "created": 0,
        "model": body.get("model", "guarded"),
        "choices": [{"index": 0, "text": settings.SAFE_REPLY_MESSAGE,
                     "finish_reason": "stop", "logprobs": None}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "_guard": guard,
    }


def _block_ratio() -> float:
    req = metrics.req_window.rate(60)
    blk = metrics.blocked_window.rate(60)
    return blk / req if req > 0 else 0.0


# ════════════════════════════════════════════════════════════════════════════
#  Step 2: 改代理 — requests → httpx.AsyncClient
# ════════════════════════════════════════════════════════════════════════════

async def proxy_upstream(request: Request, path: str):
    """
    v3:  async def proxy_upstream(request, path):
             body = await request.body()              # 异步读请求体
             async with httpx.AsyncClient() as c:     # 等待时让出事件循环
                 resp = await c.request(...)
             StreamingResponse(resp.aiter_bytes())    # 异步迭代
    """
    upstream_url = f"{settings.UPSTREAM_URL}/{path.lstrip('/')}"
    excluded = {"host", "transfer-encoding", "connection", "keep-alive"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded}

    body = await request.body()   # Step 2: await

    try:
        async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT) as client:
            resp = await client.request(  # Step 2: await
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=body,             # Step 2
                params=dict(request.query_params),
            )
    except httpx.ConnectError:
        metrics.record_error()
        return JSONResponse({"error": f"无法连接上游: {settings.UPSTREAM_URL}"}, status_code=502)
    except httpx.TimeoutException:
        metrics.record_error()
        return JSONResponse({"error": "上游超时"}, status_code=504)

    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        return StreamingResponse(
            resp.aiter_bytes(),           # Step 2: aiter_bytes()
            status_code=resp.status_code,
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
        )

    try:
        return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception:
        return JSONResponse({"error": "上游响应非 JSON"}, status_code=502)


def _extract_sse_text(chunk_bytes: bytes) -> str:
    try:
        line = chunk_bytes.decode("utf-8", errors="ignore").strip()
        if line.startswith("data:") and "[DONE]" not in line:
            payload = json.loads(line[5:].strip())
            delta = payload.get("choices", [{}])[0].get("delta", {})
            return delta.get("content", "")
    except Exception:
        pass
    return ""


async def proxy_upstream_stream(request: Request, path: str, body: dict):
    """
    v3:  httpx client.stream() + async for chunk in resp.aiter_bytes()
    """
    upstream_url = f"{settings.UPSTREAM_URL}/{path.lstrip('/')}"
    excluded = {"host", "transfer-encoding", "connection", "keep-alive"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded}
    stream_guard = detector.new_stream_guard() if settings.ENABLE_STREAM_GUARD else None

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT) as client:
                async with client.stream("POST", upstream_url,
                                         json=body, headers=headers) as resp:
                    async for chunk in resp.aiter_bytes():  # Step 2: async for + aiter_bytes
                        if not chunk:
                            continue
                        if stream_guard:
                            text_piece = _extract_sse_text(chunk)
                            if text_piece:
                                blocked, result = stream_guard.feed(text_piece)
                                metrics.record_stream_chunk(blocked=blocked)
                                if blocked:
                                    block_event = json.dumps({
                                        "id": "chatcmpl-guard-stream-blocked",
                                        "object": "chat.completion.chunk",
                                        "choices": [{"index": 0,
                                                     "delta": {"content": settings.SAFE_REPLY_MESSAGE},
                                                     "finish_reason": "stop"}],
                                        "_guard": {"blocked": True,
                                                   "threat_type": result.get("threat_type"),
                                                   "reason": result.get("reason")}
                                    })
                                    yield f"data: {block_event}\n\ndata: [DONE]\n\n".encode()
                                    logger.warning(
                                        f"🚫 流式拦截 | {result.get('threat_type')} | "
                                        f"{result.get('reason','')[:60]}"
                                    )
                                    return
                            else:
                                metrics.record_stream_chunk(blocked=False)
                        yield chunk

            if stream_guard:
                blocked, result = stream_guard.flush()
                if blocked:
                    metrics.record_stream_chunk(blocked=True)

        except Exception as e:
            metrics.record_error()
            logger.error(f"流式代理异常: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n".encode()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


# ════════════════════════════════════════════════════════════════════════════
#  核心请求处理
# ════════════════════════════════════════════════════════════════════════════

async def handle_llm_request(request: Request, path: str):
    t_start = time.perf_counter()

    try:
        body = await request.json()    # Step 1: await
    except Exception:
        raise HTTPException(status_code=400, detail="无效的 JSON 请求体")

    text = extract_text(body)
    is_stream = body.get("stream", False)

    if text.strip():
        t_detect = time.perf_counter()
        result = detector.detect(text)   # 同步纯CPU，不需要 await
        latency_ms = (time.perf_counter() - t_detect) * 1000
        result["latency_ms"] = latency_ms
        metrics.record_detect_latency(latency_ms)

        if result["blocked"]:
            total_ms = (time.perf_counter() - t_start) * 1000
            result["latency_ms"] = total_ms
            metrics.record_request(blocked=True, latency_ms=total_ms,
                                   threat_type=result.get("threat_type"),
                                   source=result.get("source"))
            logger.warning(
                f"🚫 拦截 | {result['threat_type']} | "
                f"{result['reason'][:80]} | {text[:60]!r}"
            )
            # Step 4: create_task fire-and-forget
            asyncio.create_task(alerter.check_and_alert(result, _block_ratio()))
            return JSONResponse(build_safe_response(body, result))

    logger.info(f"✅ 通过检测 stream={is_stream}")

    if is_stream:
        total_ms = (time.perf_counter() - t_start) * 1000
        metrics.record_request(blocked=False, latency_ms=total_ms)
        return await proxy_upstream_stream(request, path, body)

    resp = await proxy_upstream(request, path)   # Step 2: await
    total_ms = (time.perf_counter() - t_start) * 1000
    metrics.record_request(blocked=False, latency_ms=total_ms)
    return resp


# ════════════════════════════════════════════════════════════════════════════
#  Step 1: 改路由
#  v3: @app.post("/path") + async def handler(request: Request):
# ════════════════════════════════════════════════════════════════════════════

@app.post("/v1/chat/completions", tags=["LLM Proxy"])
@app.post("/chat/completions",    tags=["LLM Proxy"])
async def chat_completions(request: Request):
    return await handle_llm_request(request, "/v1/chat/completions")


@app.post("/v1/completions", tags=["LLM Proxy"])
@app.post("/completions",    tags=["LLM Proxy"])
async def completions(request: Request):
    return await handle_llm_request(request, "/v1/completions")


@app.get("/metrics", response_class=PlainTextResponse, tags=["Observability"])
async def prometheus_metrics():
    # Step 1: PlainTextResponse
    return PlainTextResponse(
        content=metrics.exposition(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/guard/health", tags=["Guard"])
async def guard_health():
    # Step 1: return dict，FastAPI 自动序列化
    return {
        "status": "ok",
        "middleware": "llm-guard-fastapi",
        "version": "3.0.0",
        "upstream": settings.UPSTREAM_URL,
        "rule_engine": settings.ENABLE_RULE_ENGINE,
        "ml_model": settings.ENABLE_ML_MODEL,
        "stream_guard": settings.ENABLE_STREAM_GUARD,
        "hot_reload": settings.ENABLE_HOT_RELOAD,
        "model_loaded": detector.model_loaded,
        "rule_count": detector.rule_count,
        "uptime_sec": round(time.time() - _start_time, 1),
    }


@app.post("/guard/check", tags=["Guard"])
async def guard_check(request: Request):
    try:
        body = await request.json()   # Step 1: await
        text = body.get("text", "")
    except Exception:
        raise HTTPException(status_code=400, detail='需要 JSON: {"text": "..."}')
    t0 = time.perf_counter()
    result = detector.detect(text)
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return result                     # Step 1: 直接 return dict


@app.post("/guard/reload", tags=["Guard"])
async def guard_reload():
    success, count, err = detector.hot_reload()
    if success:
        metrics.record_rule_reload(count)
        metrics.set_gauge("rule_count", float(count))
        await alerter.notify_rule_reload(True, count)   # Step 4: await
        return {"success": True, "rule_count": count, "timestamp": int(time.time())}
    await alerter.notify_rule_reload(False, 0, err)     # Step 4: await
    raise HTTPException(status_code=500, detail=f"热更新失败: {err}")


@app.get("/guard/stats", tags=["Guard"])
async def guard_stats():
    req1m = metrics.req_window.rate(60)
    blk1m = metrics.blocked_window.rate(60)
    return {
        "uptime_sec": round(time.time() - _start_time),
        "requests_1m": int(req1m),
        "blocked_1m": int(blk1m),
        "block_ratio_1m": round(blk1m / req1m, 4) if req1m > 0 else 0,
        "rule_count": detector.rule_count,
        "detect_latency_avg_ms": round(m.latency_window.rate(60) / req1m, 2) if req1m > 0 else 0,
        "model_loaded": detector.model_loaded,
    }


# Step 1: catch_all
# v3: @app.api_route("/{path:path}") + async def catch_all(request, path)
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"],
    include_in_schema=False,
)
async def catch_all(request: Request, path: str):
    return await proxy_upstream(request, path)   # Step 2: await



if __name__ == "__main__":
    logger.info("🛡️  LLM Guard Middleware v3 启动")
    logger.info(f"   上游: {settings.UPSTREAM_URL}  监听: :{settings.PORT}")
    logger.info(f"   流式审核: {'✅' if settings.ENABLE_STREAM_GUARD else '❌'}")
    logger.info(f"   热更新: {'✅' if settings.ENABLE_HOT_RELOAD else '❌'}")
    logger.info(f"   Prometheus: http://{settings.HOST}:{settings.PORT}/metrics")
    uvicorn.run(app, host=settings.HOST, port=settings.PORT, log_config=None)
