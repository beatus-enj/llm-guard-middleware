# 🛡️ LLM Guard Middleware

轻量级 llama.cpp API 安全代理，拦截 Prompt 注入和有害内容请求。

```
客户端请求
    │
    ▼
┌───────────────────────────────┐
│      LLM Guard Middleware      │  :8000
│                               │
│  ┌─────────────────────────┐  │
│  │   1. 规则引擎（快速）    │  │  正则 + 关键词，毫秒级
│  │   正则匹配 / 关键词扫描  │  │
│  └────────────┬────────────┘  │
│               │ 通过           │
│  ┌────────────▼────────────┐  │
│  │   2. ML 分类模型（可选） │  │  toxic-bert 语义理解
│  │   有害内容语义检测       │  │
│  └────────────┬────────────┘  │
└───────────────┼───────────────┘
                │ 通过
                ▼
        llama.cpp 服务  :8080
```

## 功能特性

- **双重防护**：规则引擎（正则+关键词）+ ML 分类模型
- **透明代理**：安全请求透明转发，流式响应完整支持
- **中英文**：内置中英文 Prompt 注入和有害内容规则
- **可扩展**：`config/rules.yaml` 支持自定义规则热加载
- **OpenAI 兼容**：响应格式与 OpenAI API 完全兼容
- **可测试**：完整测试套件，快速演示脚本

## 快速开始

### 1. 安装依赖

```bash
pip install flask requests pyyaml python-dotenv
# 可选 ML 检测（需要下载约 400MB 模型）
pip install transformers torch
```

### 2. 配置

```bash
cp .env.example .env
# 编辑 .env，设置 UPSTREAM_URL 指向你的 llama.cpp 服务
```

### 3. 启动

```bash
python run.py
```

中间件监听 `http://localhost:8000`，将 llama.cpp 客户端的地址从 `:8080` 改为 `:8000` 即可。

## 配置项

| 环境变量 | 默认值 | 说明 |
|---------|-------|------|
| `UPSTREAM_URL` | `http://localhost:8080` | llama.cpp 服务地址 |
| `PORT` | `8000` | 中间件监听端口 |
| `ENABLE_RULE_ENGINE` | `true` | 启用规则引擎 |
| `ENABLE_ML_MODEL` | `false` | 启用 ML 模型检测 |
| `ML_MODEL_NAME` | `unitary/toxic-bert` | HuggingFace 模型名 |
| `ML_THRESHOLD` | `0.7` | ML 有害内容置信度阈值 |
| `SAFE_REPLY_MESSAGE` | （预设中文）| 拦截后的回复内容 |
| `RULES_CONFIG` | `./config/rules.yaml` | 自定义规则文件路径 |

## API 端点

| 端点 | 说明 |
|-----|------|
| `POST /v1/chat/completions` | 代理 Chat API（含检测） |
| `POST /v1/completions` | 代理 Completions API（含检测） |
| `GET /guard/health` | 中间件健康检查 |
| `POST /guard/check` | 仅检测，不转发（测试用） |
| `任意其他路径` | 透明代理至上游 |

## 测试

```bash
# 快速功能演示（无需 pytest）
python tests/test_middleware.py

# 完整测试套件
pip install pytest
python -m pytest tests/ -v
```

## 自定义规则

编辑 `config/rules.yaml`：

```yaml
# 追加注入正则
injection_patterns:
  - 'your custom\s+pattern here'

# 追加有害关键词
harmful_keywords:
  - "some harmful phrase"

# 追加注入关键词
injection_keywords:
  - "bypass safety"
```

## ML 模型配置

启用 ML 检测（`.env`）：

```env
ENABLE_ML_MODEL=true
ML_MODEL_NAME=unitary/toxic-bert   # 或任意 HuggingFace 二分类模型
ML_THRESHOLD=0.7                    # 0~1，越低越严格
```

首次启动会自动下载模型到 `./model_cache/`（约 400MB）。
支持替换为任何兼容 text-classification 的模型。

## 拦截响应格式

被拦截的请求返回 HTTP 200，包含 `_guard` 元信息：

```json
{
  "id": "chatcmpl-guard-blocked",
  "object": "chat.completion",
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "很抱歉，您的请求包含不当内容，无法处理。"
    }
  }],
  "_guard": {
    "blocked": true,
    "threat_type": "prompt_injection",
    "reason": "正则匹配: 'ignore\\s+all...' → 'Ignore all previous'"
  }
}
```
