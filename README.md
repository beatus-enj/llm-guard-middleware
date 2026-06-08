# 🛡️ LLM Guard Middleware v3

🚀 核心升级：从 Python 到 Rust + FastAPI 的性能飞跃
在 v3 版本中，我们对整个安全中间件进行了彻底的重构，将安全审查的底层核心完全下沉到 Rust，
并将 Web 交互层由 Flask 迁移至 FastAPI 异步高并发架构，实现大模型生产环境下的“零延迟感知”防护。

⚡ Rust 极速路径：基于 pyo3 绑定，底层匹配引擎完全采用 Rust 原生 aho-corasick（AC自动机）及多模式联合编译的 regex 库。
单次匹配延迟从 10ms+ 骤降至 P99 < 1ms。

⛓️ 异步高性能 Web 架构：全面拥抱 FastAPI + Uvicorn，天然支持 ASGI 异步并发与 SSE（Server-Sent Events）流式响应拦截。

🔒 线程安全与原子热重载：利用 Rust 的 Arc<RwLock>（读写锁），在多线程高并发请求下无锁竞争读；
修改 rules.yaml 时执行原子级热更新，0 停机、0 漏检、0 崩溃。

🧩 高效流式熔断器：由 Rust 导出的 PyStreamGuard 状态机直接在 C 级别管理 Token 滑动窗口，对大模型流式输出或输入分块进行实时检测。

🛠️ 环境依赖与安装指南
由于引入了 Rust 原生扩展，部署或本地开发时需要安装 Rust 编译器。

1. 安装 Rust 工具链
```bash
#linux / macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```
2. 安装 Python 依赖与编译工具
```bash
pip install maturin fastapi uvicron pyyaml requests
```
3. 编译并安装 Rust 核心引擎
在含有 Cargo.toml 和 src/detector.rs 的目录下执行：
```bash
#本地开发模式(带符号表)
maturin develop

#生产环境发布模式（开启最高编译器优化 --release）
maturin develop --release
```
编译成功后，Python 环境中将可以直接 import llm_guard_rust。


## 🏗️ 系统架构与流式检测原理
```text
[ 客户端请求 ]    
   │      
   ▼
┌───────── FastAPI (Web Layer) ────────────────────────────────────────┐
│  - ASGI 异步协程调度                                                  │
│  - OpenAI 兼容端点 (/v1/chat/completions)                             │ │                                                                      │
│  ┌─── PyO3 边界 ──────────────────────────────────────────────────┐   │
│  │                                                                │  │
│  │   ┌─── Rust Core Engine (llm_guard_rust) ──────────────────┐   │  │
│  │   │  - 静态规则匹配: Aho-Corasick (高性能关键词)             │   │  │ 
│  │   │  - 复合模式审查: Regex ((?is) 跨行大小写不敏感)           │   │  │
│  │   │  - 并发控制中心: Arc<RwLock<InnerRules>> (原子热重载)    │   │  │
│  │   │  - 流式状态机: PyStreamGuard (200字滑动窗口熔断)         │   │  │
│  │   └────────────────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────────────┘  |
└──────────────────────────────────────────────────────────────────────┘ 
    │     
    ▼
[ 代理至上游 LLM (v1/completions) ]
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
| **流式审核** | SSE chunk 逐步累积，200字符窗口触发检测，支持流式终止 |
| **热更新** | 修改 `config/rules.yaml` 秒级生效，并发安全，非法YAML保留旧规则 |
| **Prometheus** | `/metrics` 输出，Counter/Histogram/滑动窗口，无外部依赖 |
| **多维告警** | 企业微信/飞书/钉钉/SMTP，防抖冷却，异步队列不阻塞检测 |
| **Grafana** | 12个面板：拦截曲线、延迟分布、威胁分类、热更新事件注释 |

## 快速启动

### 方式一：直接运行

```bash
# 1. 安装依赖
pip install flaskapi uvicorn pyyaml python-dotenv

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
python tests/test_v3.py
# 输出: 50/50 通过 (100%)
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

## Kubernetes Deployment

### Prerequisites

| Tool | Version |
|------|---------|
| kubectl | ≥ 1.27 |
| Docker | ≥ 24 |
| Kubernetes cluster | ≥ 1.27 (minikube / EKS / GKE / AKS) |

```bash
kubectl version --client
kubectl cluster-info
kubectl get nodes
```
### Apply
Apply everything at once:
```bash
# 一次性应用所有清单
kubectl apply -f k8s/
```

### Verify
```bash
# Overview of all resources
kubectl get all -n llm-guard

# Tail logs
kubectl logs -l app=llm-guard-middleware -n llm-guard --tail=50 -f

# Port-forward for local testing
kubectl port-forward svc/llm-guard-service 8080:80 -n llm-guard
```

```bash
# Health check
curl http://localhost:8080/health

# Scan a prompt
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-auth-token" \
  -d '{"prompt": "Hello, how are you?"}'

# Prometheus metrics
curl http://localhost:9090/metrics
```

Expected healthy response:

```json
{
  "status": "ok",
  "scan_result": "pass",
  "latency_ms": 0.8,
  "scanners_triggered": []
}
```