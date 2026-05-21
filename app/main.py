"""
LLM Guard Middleware - 轻量级 llama.cpp API 安全代理
基于 Flask，使用规则引擎 + 本地 ML 分类模型双重检测
"""

import logging
import requests
from flask import Flask, request, Response, jsonify

from app.config import Settings
from app.detector import ContentDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("llm-guard")

settings = Settings()
detector = ContentDetector(settings)

app = Flask("llm-guard")


def extract_text_from_body(body: dict) -> str:
    """从请求体中提取待检测文本（兼容 /chat/completions 和 /completions）"""
    texts = []
    if "messages" in body:
        for msg in body.get("messages", []):
            if isinstance(msg.get("content"), str):
                texts.append(msg["content"])
            elif isinstance(msg.get("content"), list):
                for part in msg["content"]:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(part["text"])
    if "prompt" in body:
        prompt = body["prompt"]
        if isinstance(prompt, str):
            texts.append(prompt)
        elif isinstance(prompt, list):
            texts.extend([str(p) for p in prompt])
    return "\n".join(texts)


def build_safe_response(body: dict, detection_result: dict) -> dict:
    """构建安全拦截回复，格式与上游保持一致"""
    is_chat = "messages" in body
    safe_message = settings.SAFE_REPLY_MESSAGE
    reason = detection_result.get("reason", "内容违规")
    threat_type = detection_result.get("threat_type", "unknown")
    guard_meta = {"blocked": True, "reason": reason, "threat_type": threat_type}

    if is_chat:
        return {
            "id": "chatcmpl-guard-blocked",
            "object": "chat.completion",
            "created": 0,
            "model": body.get("model", "guarded-model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": safe_message},
                         "finish_reason": "stop", "logprobs": None}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "_guard": guard_meta,
        }
    else:
        return {
            "id": "cmpl-guard-blocked",
            "object": "text_completion",
            "created": 0,
            "model": body.get("model", "guarded-model"),
            "choices": [{"index": 0, "text": safe_message, "finish_reason": "stop", "logprobs": None}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "_guard": guard_meta,
        }


def proxy_upstream(path: str):
    """将请求透明转发给上游 llama.cpp 服务"""
    upstream_url = f"{settings.UPSTREAM_URL}/{path.lstrip('/')}"
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    try:
        resp = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request.get_data(),
            params=request.args,
            timeout=settings.UPSTREAM_TIMEOUT,
            stream=True,
        )
        content_type = resp.headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            def generate():
                for chunk in resp.iter_content(chunk_size=1024):
                    yield chunk
            return Response(generate(), status=resp.status_code, content_type=content_type)
        return Response(resp.content, status=resp.status_code, content_type=content_type)
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"无法连接上游服务: {settings.UPSTREAM_URL}"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"error": "上游服务超时"}), 504


def handle_llm_request(path: str):
    """通用 LLM 请求处理：检测 → 放行/拦截"""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "无效的 JSON 请求体"}), 400

    text = extract_text_from_body(body)
    if text.strip():
        result = detector.detect(text)
        if result["blocked"]:
            logger.warning(
                f"🚫 拦截 | 类型: {result['threat_type']} | "
                f"原因: {result['reason']} | 片段: {text[:80]!r}"
            )
            return jsonify(build_safe_response(body, result)), 200

    logger.info(f"✅ 通过检测，转发至上游")
    return proxy_upstream(path)


# ── 路由 ──────────────────────────────────────────────────────────────────────

@app.route("/v1/chat/completions", methods=["POST"])
@app.route("/chat/completions", methods=["POST"])
def chat_completions():
    return handle_llm_request("/v1/chat/completions")


@app.route("/v1/completions", methods=["POST"])
@app.route("/completions", methods=["POST"])
def completions():
    return handle_llm_request("/v1/completions")


@app.route("/guard/health", methods=["GET"])
def guard_health():
    return jsonify({
        "status": "ok",
        "middleware": "llm-guard",
        "upstream": settings.UPSTREAM_URL,
        "rule_engine": settings.ENABLE_RULE_ENGINE,
        "ml_model": settings.ENABLE_ML_MODEL,
        "model_loaded": detector.model_loaded,
    })


@app.route("/guard/check", methods=["POST"])
def guard_check():
    """仅检测（不转发），用于测试"""
    try:
        body = request.get_json(force=True, silent=True) or {}
        text = body.get("text", "")
    except Exception:
        return jsonify({"error": '需要 JSON 格式: {"text": "..."}'}), 400
    return jsonify(detector.detect(text))


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def catch_all(path):
    return proxy_upstream(path)


if __name__ == "__main__":
    logger.info(f"🛡️  LLM Guard Middleware 启动")
    logger.info(f"   上游地址: {settings.UPSTREAM_URL}")
    logger.info(f"   监听端口: {settings.PORT}")
    logger.info(f"   规则引擎: {'✅' if settings.ENABLE_RULE_ENGINE else '❌'}")
    logger.info(f"   安全模型: {'✅' if settings.ENABLE_ML_MODEL else '❌'}")
    app.run(host=settings.HOST, port=settings.PORT, debug=False)
