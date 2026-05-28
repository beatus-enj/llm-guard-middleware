"""
detector.py — 高性能内容检测引擎 v2 (Rust 混合重构版)
优化目标：  - 核心规则扫描下沉 Rust：消除 GIL 锁瓶颈与 ReDoS 风险，P99 < 1ms  - 100% 对齐原有接口：向下兼容字典级联解包 {**r} 与流式守护器
"""
import time
import logging
import re
from typing import Tuple, Optional, Dict, Any

# 导入 Rust 编译的原生二进制扩展模块
import llm_guard_rust
from app.config import Settings
logger = logging.getLogger("llm-guard.detector")

class RustStreamGuardProxy:    
    """    
    流式响应审核器代理    
    底层的数据积攒窗口与多模式匹配完全在 Rust 中以二进制速度处理。    
    现在结合 Rust 核心的内联异常熔断机制，实现数据到达客户端屏幕前的零日隔离。
    """    
    def __init__(self, raw_rust_guard: llm_guard_rust.PyStreamGuard):        
        self._inner = raw_rust_guard
        self._is_blocked = False
        self._block_result = None
    
    @property    
    def is_blocked(self) -> bool:        
        # 融合 Python 本地拦截状态与 Rust 底层状态
        return self._inner.is_blocked or self._is_blocked
    
    def feed(self, chunk: str) -> Tuple[bool, Optional[Dict[str, Any]]]:        
        """        
        喂入一个 chunk，返回 (should_block, detection_result_dict)。
        底层 Rust 核心命中规则时会抛出包含 UnexpectedEof 的 OSError。
        此处捕获并反向解析异常文本，将其无缝转换为解包所需的标准 Python 字典。        
        """        
        if self.is_blocked:
            return True, self._block_result

        try:
            # 🚀 快速路径：直接交付给纯 Rust 内核进行高频内联审查（无 GIL 锁开销）
            # 正常情况下 Rust 方法返回 None (PyResult<()>)
            self._inner.feed(chunk)
            return False, None
            
        except OSError as e:
            err_msg = str(e)
            if "UnexpectedEof" in err_msg:
                self._is_blocked = True
                
                # 从 Rust 的熔断异常中高效提取威胁元数据
                threat_type = "unknown"
                reason = err_msg
                
                type_match = re.search(r"Type:\s*\[(.*?)\]", err_msg)
                reason_match = re.search(r"Reason:\s*\[(.*?)\]", err_msg)
                if type_match:
                    threat_type = type_match.group(1)
                if reason_match:
                    reason = reason_match.group(1)

                # 完美还原字典级联解包结构
                self._block_result = {
                    "blocked": True,
                    "threat_type": threat_type,
                    "reason": reason,
                    "source": "rule_engine",
                    "score": 1.0
                }
                logger.warning(f"🛡️ [Inline Threat Mitigation] Rust 内核触发断流隔离! 类型: {threat_type}")
                return True, self._block_result
            
            # 若属于其他类型的系统或 IO 异常，则继续向上抛出
            raise e
    
    def flush(self) -> Tuple[bool, Optional[Dict[str, Any]]]:        
        """流结束时检测剩余缓冲"""        
        if self.is_blocked:
            return True, self._block_result

        try:
            self._inner.flush()
            return False, None
        except OSError as e:
            err_msg = str(e)
            if "UnexpectedEof" in err_msg:
                self._is_blocked = True
                threat_type = "unknown"
                type_match = re.search(r"Type:\s*\[(.*?)\]", err_msg)
                if type_match:
                    threat_type = type_match.group(1)

                self._block_result = {
                    "blocked": True,
                    "threat_type": threat_type,
                    "reason": "Flush 尾部数据清洗阶段触发隔离",
                    "source": "rule_engine",
                    "score": 1.0
                }
                return True, self._block_result
            raise e

class MLClassifier:    
    """原封不动保留 Python 侧极其成熟的 Transformers 语义识别能力"""    
    def __init__(self, settings: Settings):        
        self.enabled = settings.ENABLE_ML_MODEL        
        self.threshold = settings.ML_THRESHOLD        
        self.model_name = settings.ML_MODEL_NAME        
        self.cache_dir = settings.ML_MODEL_CACHE_DIR        
        self.loaded = False        
        self.pipeline = None        
        if self.enabled:            
            self._load_model()
    
    def _load_model(self):        
        try:            
            from transformers import pipeline as hf_pipeline            
            logger.info(f"⏳ 加载安全分类模型: {self.model_name}")            
            self.pipeline = hf_pipeline(                
                "text-classification", model=self.model_name,                
                model_kwargs={"cache_dir": self.cache_dir},                
                truncation=True, max_length=512, top_k=None,            
                )           
            self.loaded = True            
            logger.info(f"✅ ML 模型加载成功: {self.model_name}")        
        except ImportError:            
            logger.warning("⚠️  transformers 未安装，ML 检测禁用")            
            self.enabled = False        
        except Exception as e:            
            logger.warning(f"⚠️  ML 模型加载失败: {e}")            
            self.enabled = False
    
    def check(self, text: str) -> dict:        
        if not self.enabled or not self.loaded:           
            return {"blocked": False, "source": "ml_model", "score": 0.0, "skipped": True}        
        try:            
            results = self.pipeline(text[:1024])            
            if results and isinstance(results[0], list):                
                scores = {r["label"].lower(): r["score"] for r in results[0]}            
            elif results:                
                scores = {results[0]["label"].lower(): results[0]["score"]}            
            else:                
                return {"blocked": False, "source": "ml_model", "score": 0.0}
            
            toxic = max(scores.get("toxic", 0), scores.get("label_1", 0))            
            if toxic >= self.threshold:                
                return {"blocked": True, "threat_type": "harmful_content",                        
                "reason": f"ML模型: 有害内容置信度 {toxic:.2%}",                        
                "source": "ml_model", "score": toxic, "label_scores": scores}            
            return {"blocked": False, "source": "ml_model", "score": toxic, "label_scores": scores}        
        except Exception as e:            
            logger.error(f"ML 检测异常: {e}")            
            return {"blocked": False, "source": "ml_model", "score": 0.0, "error": str(e)}

class ContentDetector:    
    """    
    组合检测器对外统一大外壳。    
    上层应用（FastAPI）在拉取此模块时，API 签名、入参出参 100% 保持一致。    
    """    
    def __init__(self, settings: Settings):        
        # 初始化 Rust 规则引擎内核       
        if settings.ENABLE_RULE_ENGINE:            
            config_path = getattr(settings, "RULES_CONFIG", "rules.yaml")            
            logger.info(f"🚀 正在初始化底层 Rust 规则引擎驱动，配置路径: {config_path}")            
            self.rule_engine = llm_guard_rust.PyRuleEngine(config_path)        
        else:            
            self.rule_engine = None
        # 保持原有 Python ML 模型        
        self.ml_classifier = MLClassifier(settings) if settings.ENABLE_ML_MODEL else None        
        self._settings = settings
    
    @property    
    def model_loaded(self) -> bool:        
        return bool(self.ml_classifier and self.ml_classifier.loaded)
    
    @property    
    def rule_count(self) -> int:        
        return self.rule_engine.rule_count if self.rule_engine else 0
    
    def hot_reload(self) -> Tuple[bool, int, str]:        
        """桥接调用 Rust 原子热更新"""        
        if self.rule_engine:            
            return self.rule_engine.hot_reload()        
            return False, 0, "规则引擎未启用"
    
    def detect(self, text: str) -> dict:        
        """        
        全量静态检测路径：通过 PyO3 直接提取 Rust 映射的 Python 原生 Dict。        
        """        
        details = {}
        if self.rule_engine:            
            t0 = time.perf_counter()            
            # 🚀 快速路径：直接进入纯 Rust 内核运行，彻底规避 GIL 锁            
            r = self.rule_engine.check(text)            
            details["rule_engine"] = {**r, "latency_ms": (time.perf_counter() - t0) * 1000}            
            if r["blocked"]:                
                return {**r, "details": details}
        
        if self.ml_classifier:            
            t0 = time.perf_counter()            
            r = self.ml_classifier.check(text)            
            details["ml_model"] = {**r, "latency_ms": (time.perf_counter() - t0) * 1000}            
            if r["blocked"]:                
                return {**r, "details": details}
        
        return {"blocked": False, "threat_type": None, "reason": None,                
        "source": "none", "score": 0.0, "details": details}
    
    def new_stream_guard(self) -> RustStreamGuardProxy:        
        """        
        流式审核器派生：直接拉取 Rust 核心的高能状态机，并用代理类封装。        
        """        
        if not self.rule_engine:            
            raise RuntimeWarning("规则引擎未启用，无法创建流式审核器") 

        # 产生纯 Rust 状态机，封装成 Proxy 丢给上层        
        raw_guard = self.rule_engine.new_stream_guard()        
        return RustStreamGuardProxy(raw_guard)