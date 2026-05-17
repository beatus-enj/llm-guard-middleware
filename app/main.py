"""
main.py v2 — LLM Guard Middleware

新增：
  - 流式审核（SSE chunk 逐步检测）
  - Prometheus /metrics 端点
  - 规则热更新 + 告警联动
  - 全链路延迟埋点
"""

import json
import logging
import time
import threading
import requests
from flask import Flask, request, Response, jsonify

from app.config import Settings
from app.detector import ContentDetector
from app.metrics import get_metrics
from app.alerting import AlertManager
from app.hot_reload import try_watchdog_watcher

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger("llm-guard")

# ── 全局单例初始化 ────────────────────────────────────────────────────────────
settings = Settings()
detector = ContentDetector(settings)
metrics  = get_metrics()
alerter  = AlertManager(settings)

_watcher = None


def _on_rule_reload():
    """热更新回调：重载规则 → 更新指标 → 触发告警"""
    success, count, err = detector.hot_reload()
    metrics.record_rule_reload(count if success else 0)
    metrics.set_gauge("rule_count", count)
    alerter.notify_rule_reload(success, count, err)


def start_watcher():
    """在 run.py 中显式调用，测试时不调用"""
    global _watcher
    if settings.ENABLE_HOT_RELOAD and _watcher is None:
        _watcher = try_watchdog_watcher(settings.RULES_CONFIG, _on_rule_reload,
                                        settings.HOT_RELOAD_POLL_SEC)
        _watcher.start()


# 更新初始指标
metrics.set_gauge("rule_count", detector.rule_count)
metrics.set_gauge("ml_model_loaded", 1.0 if detector.model_loaded else 0.0)

app = Flask("llm-guard")


# ════════════════════════════════════════════════════════════════════════════
#  辅助函数
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


def safe_response(body: dict, result: dict) -> dict:
    is_chat = "messages" in body
    guard = {"blocked": True, "reason": result.get("reason",""), "threat_type": result.get("threat_type","")}
    if is_chat:
        return {"id": "chatcmpl-guard-blocked", "object": "chat.completion", "created": 0,
                "model": body.get("model","guarded"),
                "choices": [{"index":0,"message":{"role":"assistant","content":settings.SAFE_REPLY_MESSAGE},
                             "finish_reason":"stop","logprobs":None}],
                "usage": {"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}, "_guard": guard}
    return {"id": "cmpl-guard-blocked", "object": "text_completion", "created": 0,
            "model": body.get("model","guarded"),
            "choices": [{"index":0,"text":settings.SAFE_REPLY_MESSAGE,"finish_reason":"stop","logprobs":None}],
            "usage": {"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}, "_guard": guard}


def _record_block(result: dict, latency_ms: float, text: str):
    metrics.record_request(blocked=True, latency_ms=latency_ms,
                           threat_type=result.get("threat_type"),
                           source=result.get("source"))
    metrics.record_detect_latency(latency_ms)
    ttype = result.get("threat_type", "")
    alerter.check_new_threat_type(ttype)
    alerter.notify_block(ttype, result.get("reason",""), text[:120])
    # 检查拦截率
    req1m = metrics.req_window.rate(60)
    blk1m = metrics.blocked_window.rate(60)
    alerter.check_block_rate(blk1m / req1m if req1m > 0 else 0, int(req1m))
    logger.warning(f"🚫 拦截 | {result['threat_type']} | {result['reason'][:80]} | {text[:60]!r}")


# ════════════════════════════════════════════════════════════════════════════
#  非流式代理
# ════════════════════════════════════════════════════════════════════════════

def proxy_upstream(path: str):
    url = f"{settings.UPSTREAM_URL}/{path.lstrip('/')}"
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    try:
        resp = requests.request(request.method, url, headers=headers,
                                data=request.get_data(), params=request.args,
                                timeout=settings.UPSTREAM_TIMEOUT, stream=True)
        ct = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ct:
            return Response(resp.iter_content(1024), status=resp.status_code, content_type=ct)
        return Response(resp.content, status=resp.status_code, content_type=ct)
    except requests.ConnectionError:
        metrics.record_error()
        return jsonify({"error": f"无法连接上游: {settings.UPSTREAM_URL}"}), 502
    except requests.Timeout:
        metrics.record_error()
        return jsonify({"error": "上游超时"}), 504


# ════════════════════════════════════════════════════════════════════════════
#  流式代理（SSE 逐 chunk 审核）
# ════════════════════════════════════════════════════════════════════════════

def _extract_sse_text(chunk_bytes: bytes) -> str:
    """从 SSE data: {...} 行中提取 delta.content"""
    try:
        line = chunk_bytes.decode("utf-8", errors="ignore").strip()
        if line.startswith("data:") and "[DONE]" not in line:
            payload = json.loads(line[5:].strip())
            # Chat completions delta
            delta = payload.get("choices", [{}])[0].get("delta", {})
            return delta.get("content", "")
    except Exception:
        pass
    return ""


def proxy_upstream_stream(path: str, body: dict):
    """流式代理：对 SSE 逐 chunk 做内容审核"""
    url = f"{settings.UPSTREAM_URL}/{path.lstrip('/')}"
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    stream_guard = detector.new_stream_guard() if settings.ENABLE_STREAM_GUARD else None

    def generate():
        try:
            with requests.post(url, json=body, headers=headers,
                               timeout=settings.UPSTREAM_TIMEOUT, stream=True) as resp:
                for chunk in resp.iter_content(chunk_size=None):
                    if not chunk:
                        continue

                    if stream_guard:
                        text_piece = _extract_sse_text(chunk)
                        if text_piece:
                            blocked, result = stream_guard.feed(text_piece)
                            metrics.record_stream_chunk(blocked=blocked)
                            if blocked:
                                # 发送拦截 SSE 事件后终止流
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
                                logger.warning(f"🚫 流式拦截 | {result.get('threat_type')} | {result.get('reason','')[:60]}")
                                return
                        else:
                            metrics.record_stream_chunk(blocked=False)

                    yield chunk

                # 流结束，检测剩余缓冲
                if stream_guard:
                    blocked, result = stream_guard.flush()
                    if blocked:
                        metrics.record_stream_chunk(blocked=True)

        except Exception as e:
            metrics.record_error()
            logger.error(f"流式代理异常: {e}")
            err_event = json.dumps({"error": str(e)})
            yield f"data: {err_event}\n\n".encode()

    return Response(generate(), content_type="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


# ════════════════════════════════════════════════════════════════════════════
#  核心请求处理
# ════════════════════════════════════════════════════════════════════════════

def handle_llm_request(path: str):
    t_start = time.perf_counter()
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "无效 JSON"}), 400

    text = extract_text(body)
    is_stream = body.get("stream", False)

    if text.strip():
        t_detect = time.perf_counter()
        result = detector.detect(text)
        latency_ms = (time.perf_counter() - t_detect) * 1000
        metrics.record_detect_latency(latency_ms)

        if result["blocked"]:
            total_ms = (time.perf_counter() - t_start) * 1000
            _record_block(result, total_ms, text)
            return jsonify(safe_response(body, result)), 200

    logger.info(f"✅ 通过检测 stream={is_stream}")

    if is_stream:
        total_ms = (time.perf_counter() - t_start) * 1000
        metrics.record_request(blocked=False, latency_ms=total_ms)
        return proxy_upstream_stream(path, body)

    resp = proxy_upstream(path)
    total_ms = (time.perf_counter() - t_start) * 1000
    metrics.record_request(blocked=False, latency_ms=total_ms)
    return resp


# ════════════════════════════════════════════════════════════════════════════
#  路由
# ════════════════════════════════════════════════════════════════════════════

@app.route("/v1/chat/completions", methods=["POST"])
@app.route("/chat/completions", methods=["POST"])
def chat_completions():
    return handle_llm_request("/v1/chat/completions")

@app.route("/v1/completions", methods=["POST"])
@app.route("/completions", methods=["POST"])
def completions():
    return handle_llm_request("/v1/completions")

@app.route("/metrics")
def prometheus_metrics():
    """Prometheus /metrics 端点"""
    return Response(metrics.exposition(), content_type="text/plain; version=0.0.4; charset=utf-8")

@app.route("/guard/health")
def guard_health():
    return jsonify({
        "status": "ok", "middleware": "llm-guard",
        "upstream": settings.UPSTREAM_URL,
        "rule_engine": settings.ENABLE_RULE_ENGINE,
        "ml_model": settings.ENABLE_ML_MODEL,
        "stream_guard": settings.ENABLE_STREAM_GUARD,
        "hot_reload": settings.ENABLE_HOT_RELOAD,
        "model_loaded": detector.model_loaded,
        "rule_count": detector.rule_count,
    })

@app.route("/guard/check", methods=["POST"])
def guard_check():
    body = request.get_json(force=True, silent=True) or {}
    text = body.get("text", "")
    t0 = time.perf_counter()
    result = detector.detect(text)
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return jsonify(result)

@app.route("/guard/reload", methods=["POST"])
def guard_reload():
    """手动触发规则热更新"""
    success, count, err = detector.hot_reload()
    if success:
        metrics.record_rule_reload(count)
        metrics.set_gauge("rule_count", count)
        alerter.notify_rule_reload(True, count)
        return jsonify({"success": True, "rule_count": count})
    return jsonify({"success": False, "error": err}), 500

@app.route("/guard/stats")
def guard_stats():
    """简易统计摘要"""
    m = metrics
    req1m = m.req_window.rate(60)
    blk1m = m.blocked_window.rate(60)
    return jsonify({
        "uptime_sec": round(time.time() - m._start_time),
        "requests_1m": int(req1m),
        "blocked_1m": int(blk1m),
        "block_ratio_1m": round(blk1m / req1m, 4) if req1m > 0 else 0,
        "detect_latency_avg_ms": round(m.latency_window.rate(60) / req1m, 2) if req1m > 0 else 0,
        "rule_count": detector.rule_count,
    })

@app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","OPTIONS"])
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","OPTIONS"])
def catch_all(path):
    return proxy_upstream(path)


if __name__ == "__main__":
    logger.info("🛡️  LLM Guard Middleware v2 启动")
    logger.info(f"   上游: {settings.UPSTREAM_URL}  监听: :{settings.PORT}")
    logger.info(f"   流式审核: {'✅' if settings.ENABLE_STREAM_GUARD else '❌'}")
    logger.info(f"   热更新: {'✅' if settings.ENABLE_HOT_RELOAD else '❌'}")
    logger.info(f"   Prometheus: http://{settings.HOST}:{settings.PORT}/metrics")
    app.run(host=settings.HOST, port=settings.PORT, debug=False, threaded=True)
