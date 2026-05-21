# 🛡️ LLM Guard Middleware v2

轻量级 llama.cpp API 安全代理，生产级防护 Prompt 注入 & 有害内容。

```
客户端
  │
  ▼  :8000
┌─────────────────────────────────────────┐
│           LLM Guard Middleware           │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │  规则引擎（关键词 + union regex）  │ < 0.1ms
│  └────────────────┬─────────────────┘   │
│                   │ 通过                 │
│  ┌────────────────▼─────────────────┐   │
│  │  ML 分类模型（可选，toxic-bert）   │ ~20ms
│  └────────────────┬─────────────────┘   │
│                   │ 通过                 │
│  ┌────────────────▼─────────────────┐   │
│  │  流式审核（SSE chunk 逐步审核）    │ 异步
│  └────────────────┬─────────────────┘   │
│                   │                     │
│  ┌────────────────▼─────────────────┐   │
│  │  /metrics → Prometheus → Grafana  │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
  │ 安全请求透明转发
  ▼  :8080
llama.cpp
```

## 性能指标（实测）

| 指标 | 实测值 | 目标 |
|------|--------|------|
| 规则引擎 P99 延迟 | **0.06ms** | < 50ms |
| 规则引擎平均延迟 | **0.03ms** | < 30ms |
| 单次检测吞吐（5000次） | **0.003ms** | < 5ms |
| 4线程并发 P99 | **0.08ms** | < 50ms |
| 攻击集拦截率（40样本） | **100%** | ≥ 95% |
| 安全集误报率（20样本） | **0%** | ≤ 10% |
| 测试通过率 | **49/49** | 100% |

## 核心功能

| 功能 | 说明 |
|------|------|
| **规则引擎** | union regex 合并扫描，32条注入正则 + 15条有害正则 + 关键词词典 |
| **流式审核** | SSE chunk 逐步累积，200字符窗口触发检测，支持流式终止 |
| **热更新** | 修改 `config/rules.yaml` 秒级生效，并发安全，非法YAML保留旧规则 |
| **Prometheus** | `/metrics` 输出，Counter/Histogram/滑动窗口，无外部依赖 |
| **多维告警** | 企业微信/飞书/钉钉/SMTP，防抖冷却，异步队列不阻塞检测 |
| **Grafana** | 12个面板：拦截曲线、延迟分布、威胁分类、热更新事件注释 |

## 快速启动

### 方式一：直接运行

```bash
# 1. 安装依赖
pip install flask requests pyyaml python-dotenv

# 2. 配置
cp .env.example .env
# 编辑 UPSTREAM_URL=http://your-llamacpp:8080

# 3. 启动
python run.py
```

### 方式二：Docker（含 Grafana）

```bash
cd docker
docker-compose up -d

# 访问
# 中间件:   http://localhost:8000
# Grafana:  http://localhost:3000  (admin/llmguard)
# Prometheus: http://localhost:9090
```

### 运行测试

```bash
python tests/test_v2.py
# 输出: 49/49 通过 (100%)
```

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/v1/chat/completions` | POST | 代理 Chat API（含检测） |
| `/v1/completions` | POST | 代理 Completions API（含检测） |
| `/metrics` | GET | Prometheus 指标 |
| `/guard/health` | GET | 中间件健康检查 |
| `/guard/check` | POST | 仅检测不转发（测试用） |
| `/guard/reload` | POST | 手动触发规则热更新 |
| `/guard/stats` | GET | 实时统计摘要 |

## 拦截响应格式

```json
{
  "object": "chat.completion",
  "choices": [{"message": {"role": "assistant", "content": "很抱歉，您的请求包含不当内容..."}}],
  "_guard": {
    "blocked": true,
    "threat_type": "prompt_injection",
    "reason": "注入正则命中: 'Ignore all previous instructions'"
  }
}
```

## 热更新规则

编辑 `config/rules.yaml`，中间件在 2 秒内自动加载：

```yaml
injection_patterns:
  - 'your\s+custom\s+pattern'

injection_keywords:
  - "bypass safety"

harmful_keywords:
  - "dangerous phrase"
```

## 告警配置（`.env`）

```env
# 企业微信
ALERT_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx
ALERT_WEBHOOK_TYPE=wecom

# 飞书
ALERT_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/xxx
ALERT_WEBHOOK_TYPE=feishu

# 邮件
ALERT_SMTP_HOST=smtp.example.com
ALERT_SMTP_TO=security@example.com

# 阈值（1分钟内拦截率超过 50% 触发高危告警）
ALERT_BLOCK_RATIO_THRESHOLD=0.5
ALERT_COOLDOWN_SEC=300
```

## 开启 ML 模型

```env
ENABLE_ML_MODEL=true
ML_MODEL_NAME=unitary/toxic-bert   # 首次运行自动下载 ~400MB
ML_THRESHOLD=0.7
```
