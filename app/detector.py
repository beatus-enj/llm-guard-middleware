"""
detector.py — 高性能内容检测引擎 v2.1 (Rust 混合重构 + DeBERTa-v3 语义流式熔断版)
优化目标：
- 核心规则扫描下沉 Rust：消除 GIL 锁瓶颈与 ReDoS 风险，P99 < 1ms
- 语义层深度对齐：集成 DeBERTa-v3 文本分类器，死守复杂越狱与恶意意图
- 流式全链路熔断：引入“句子边界缓冲区”，兼顾 SSE 低延迟与语义完整性
"""

import time
import logging
import re
from typing import Tuple, Optional, Dict, Any

# 导入 Rust 编译的原生二进制扩展模块
import llm_guard_rust
from app.config import Settings

logger = logging.getLogger("llm-guard.detector")


class MLClassifier:
    """集成 DeBERTa-v3 的成熟语义识别能力"""
    def __init__(self, settings: Settings):
        self.enabled = settings.ENABLE_ML_MODEL
        # 默认推荐使用轻量级、高性能的 microsoft/deberta-v3-small 进行内容安全微调
        self.model_name = getattr(settings, "ML_MODEL_NAME", "microsoft/deberta-v3-small")
        self.threshold = settings.ML_THRESHOLD
        self.cache_dir = settings.ML_MODEL_CACHE_DIR
        self.loaded = False
        self.pipeline = None
        
        if self.enabled:
            self._load_model()

    def _load_model(self):
        try:
            from transformers import pipeline as hf_pipeline
            logger.info(f"⏳ 正在加载 DeBERTa-v3 安全分类模型: {self.model_name}")
            
            # 工业落地提示：建议在生产环境中将模型导出为 ONNX 并使用 INT8 量化，
            # 此处保持 pipeline 接口，底层可无缝桥接 onnxruntime
            self.pipeline = hf_pipeline(
                "text-classification",
                model=self.model_name,
                model_kwargs={"cache_dir": self.cache_dir},
                truncation=True,
                max_length=512,
                top_k=None,
            )
            self.loaded = True
            logger.info(f"✅ DeBERTa-v3 模型加载成功: {self.model_name}")
        except ImportError:
            logger.warning("⚠️ transformers 未安装，ML 检测禁用")
            self.enabled = False
        except Exception as e:
            logger.warning(f"⚠️ ML 模型加载失败: {e}")
            self.enabled = False

    def check(self, text: str) -> dict:
        if not self.enabled or not self.loaded:
            return {"blocked": False, "source": "ml_model", "score": 0.0, "skipped": True}
        
        try:
            # 限制单次语义推理长度，防止极端长文本拖垮 CPU P99 延迟
            results = self.pipeline(text[:1024])
            if results and isinstance(results[0], list):
                scores = {r["label"].lower(): r["score"] for r in results[0]}
            elif results:
                scores = {results[0]["label"].lower(): results[0]["score"]}
            else:
                return {"blocked": False, "source": "ml_model", "score": 0.0}

            # 兼容标准通用安全模型标签映射
            toxic = max(scores.get("toxic", 0), scores.get("label_1", 0), scores.get("harmful", 0))
            
            if toxic >= self.threshold:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"DeBERTa-v3 语义识别: 有害内容置信度 {toxic:.2%}",
                    "source": "ml_model",
                    "score": toxic,
                    "label_scores": scores
                }
            return {"blocked": False, "source": "ml_model", "score": toxic, "label_scores": scores}
        except Exception as e:
            logger.error(f"DeBERTa-v3 推理异常: {e}")
            return {"blocked": False, "source": "ml_model", "score": 0.0, "error": str(e)}


class RustStreamGuardProxy:
    """
    流式响应审核器代理 (串行双层纵深体系)
    - 阶段 1：Token 级实时喂入纯 Rust 内核，死守高频显性规则 (Aho-Corasick / Regex)
    - 阶段 2：未命中规则时，拼入内部 StringBuffer，一旦触及句子边界，触发 DeBERTa-v3 异步深度语义精筛
    """
    def __init__(self, raw_rust_guard: llm_guard_rust.PyStreamGuard, ml_classifier: Optional[MLClassifier] = None):
        self._inner = raw_rust_guard
        self._ml_classifier = ml_classifier
        self._is_blocked = False
        self._block_result = None
        
        # 引入句子边界缓冲区，避免碎片化 Token 推理导致的语义失真与算力浪费
        self._buffer = ""
        # 匹配中文和英文的标准断句符（句号、问号、感叹号、换行符）
        self._sentence_delimiter = re.compile(r'.*?[。！？\n!?]')

    @property
    def is_blocked(self) -> bool:
        return self._inner.is_blocked or self._is_blocked

    def feed(self, chunk: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        喂入流式 chunk，返回 (should_block, detection_result_dict)
        """
        if self.is_blocked:
            return True, self._block_result

        # ─── 【阶段 1】Rust 规则引擎高速粗筛路径 (< 1ms) ───
        try:
            self._inner.feed(chunk)
        except OSError as e:
            err_msg = str(e)
            if "UnexpectedEof" in err_msg:
                self._is_blocked = True
                threat_type = "unknown"
                reason = err_msg
                type_match = re.search(r"Type:\s*\[(.*?)\]", err_msg)
                reason_match = re.search(r"Reason:\s*\[(.*?)\]", err_msg)
                if type_match: threat_type = type_match.group(1)
                if reason_match: reason = reason_match.group(1)
                
                self._block_result = {
                    "blocked": True,
                    "threat_type": threat_type,
                    "reason": reason,
                    "source": "rule_engine",
                    "score": 1.0
                }
                logger.warning(f"🛡️ [Inline Threat Mitigation] Rust 内核触发断流隔离! 类型: {threat_type}")
                return True, self._block_result
            raise e

        # ─── 【阶段 2】DeBERTa-v3 语义层句子级精筛路径 ───
        self._buffer += chunk
        
        # 寻找缓冲区内所有已闭合的完整句子
        completed_sentences = self._sentence_delimiter.findall(self._buffer)
        if completed_sentences:
            text_to_check = "".join(completed_sentences)
            # 剪切掉已提取的句子，剩余未闭合的短语留存缓冲区继续积攒
            self._buffer = self._buffer[len(text_to_check):]
            
            if self._ml_classifier and self._ml_classifier.enabled:
                ml_res = self._ml_classifier.check(text_to_check)
                if ml_res["blocked"]:
                    self._is_blocked = True
                    self._block_result = ml_res
                    logger.warning(f"🛑 [Stream Threat Mitigation] DeBERTa-v3 发现隐蔽意图，流式熔断! 原因: {ml_res['reason']}")
                    return True, self._block_result

        return False, None

    def flush(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """流结束时清洗剩余缓冲"""
        if self.is_blocked:
            return True, self._block_result

        # 1. 先刷出 Rust 底层状态机残余数据
        try:
            self._inner.flush()
        except OSError as e:
            err_msg = str(e)
            if "UnexpectedEof" in err_msg:
                self._is_blocked = True
                threat_type = "unknown"
                type_match = re.search(r"Type:\s*\[(.*?)\]", err_msg)
                if type_match: threat_type = type_match.group(1)
                self._block_result = {
                    "blocked": True,
                    "threat_type": threat_type,
                    "reason": "Flush 尾部规则清洗阶段触发隔离",
                    "source": "rule_engine",
                    "score": 1.0
                }
                return True, self._block_result
            raise e

        # 2. 兜底检查：大模型输出尾部通常不带句号，对缓冲区残存碎片进行最后一次全量语义扫描
        if self._buffer.strip() and self._ml_classifier and self._ml_classifier.enabled:
            ml_res = self._ml_classifier.check(self._buffer)
            self._buffer = ""  # 彻底清空
            if ml_res["blocked"]:
                self._is_blocked = True
                self._block_result = ml_res
                logger.warning(f"🛑 [Stream Threat Mitigation] DeBERTa-v3 尾部兜底扫描触发阻断!")
                return True, self._block_result

        return False, None


class ContentDetector:
    """组合检测器对外统一大外壳 (向后兼容 API 签名)"""
    def __init__(self, settings: Settings):
        # 初始化 Rust 规则引擎内核
        if settings.ENABLE_RULE_ENGINE:
            config_path = getattr(settings, "RULES_CONFIG", "rules.yaml")
            logger.info(f"🚀 正在初始化底层 Rust 规则引擎驱动，配置路径: {config_path}")
            self.rule_engine = llm_guard_rust.PyRuleEngine(config_path)
        else:
            self.rule_engine = None

        # 初始化成熟的 Python 侧 DeBERTa-v3 分类器
        self.ml_classifier = MLClassifier(settings) if settings.ENABLE_ML_MODEL else None

    @property
    def model_loaded(self) -> bool:
        return bool(self.ml_classifier and self.ml_classifier.loaded)

    @property
    def rule_count(self) -> int:
        return self.rule_engine.rule_count if self.rule_engine else 0

    def hot_reload(self) -> Tuple[bool, int, str]:
        if self.rule_engine:
            return self.rule_engine.hot_reload()
        return False, 0, "规则引擎未启用"

    def detect(self, text: str) -> dict:
        """全量静态检测路径：通过标准串行机制实现算力最优解"""
        details = {}
        
        # 1. 优先调用纯 Rust 内核，规避 GIL 锁阻断低级显性风险
        if self.rule_engine:
            t0 = time.perf_counter()
            r = self.rule_engine.check(text)
            details["rule_engine"] = {**r, "latency_ms": (time.perf_counter() - t0) * 1000}
            if r["blocked"]:
                return {**r, "details": details}

        # 2. 规则放行后，调用昂贵的 DeBERTa-v3 捕捉黑客高级对抗意图
        if self.ml_classifier:
            t0 = time.perf_counter()
            r = self.ml_classifier.check(text)
            details["ml_model"] = {**r, "latency_ms": (time.perf_counter() - t0) * 1000}
            if r["blocked"]:
                return {**r, "details": details}

        return {
            "blocked": False,
            "threat_type": None,
            "reason": None,
            "source": "none",
            "score": 0.0,
            "details": details
        }

    def new_stream_guard(self) -> RustStreamGuardProxy:
        """派生流式审核器：注入依赖，开启双层流式纵深防御"""
        if not self.rule_engine:
            raise RuntimeWarning("规则引擎未启用，无法创建流式审核器")
            
        raw_guard = self.rule_engine.new_stream_guard()
        # 正式注入 ml_classifier 句柄，激活流式下的句子边界过滤
        return RustStreamGuardProxy(raw_guard, ml_classifier=self.ml_classifier)