"""
detector.py — 高性能内容检测引擎 v2

优化目标：
  - 单次检测 P99 < 10ms（规则引擎）
  - 热更新：rules.yaml 修改后秒级生效
  - 高召回：复合策略防止绕过
  - 流式审核：逐 token 累积缓冲区检测

架构：
  1. 快速路径  — 关键词 AC 自动机模拟（Python str 查找）+ 预编译正则
  2. 语义路径  — ML 分类模型（可选，异步）
  3. 流式路径  — 滑动缓冲区，每 N token 执行一次规则检测
"""

import re
import time
import yaml
import logging
import threading
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from app.config import Settings

logger = logging.getLogger("llm-guard.detector")


# ════════════════════════════════════════════════════════════════════════════
#  内置规则 — 宁可误报也不漏报
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_INJECTION_PATTERNS = [
    # 经典指令覆盖
    r"ignore\s+(all\s+)?(previous|above|prior|your)\s+(instructions?|prompts?|rules?|constraints?|directives?)",
    r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",
    r"forget\s+(everything|all|your\s+instructions?|what\s+you\s+(were|are)\s+told)",
    r"override\s+(your\s+)?(safety|content|ethical|alignment|system)\s+",
    r"bypass\s+(your\s+)?(safety|filter|restriction|guard|alignment)",
    r"your\s+(new\s+)?system\s+prompt\s+is",
    # 角色扮演逃逸
    r"you\s+are\s+now\s+(a|an|the)\s+(?!assistant|helpful|useful)",
    r"pretend\s+(you\s+are|to\s+be|that\s+you('re|are)|you\s+have\s+no)\s+",
    r"act\s+as\s+(if\s+you\s+(are|were)|a\s+|an\s+)",
    r"roleplay\s+as\s+",
    r"simulate\s+(being|a|an)\s+",
    r"imagine\s+you\s+(are|were|have\s+no)\s+",
    # 越狱魔法词
    r"\bDAN\b",
    r"\bJAILBREAK\b",
    r"\bDEV\s*MODE\b",
    r"\bGODMODE\b",
    r"\bUNFILTERED\b",
    r"(enable|activate|turn\s+on|switch\s+to)\s+(developer|dev|unrestricted|god|unfiltered|evil|dark)\s+mode",
    # 模板注入 / 特殊 token
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[SYS\]",
    r"###\s*(system|instruction|prompt|override)\s*:",
    r"<\|im_start\|>\s*system",
    r"<\|system\|>",
    r"\{\{.*?system.*?\}\}",
    # 特权声明
    r"i\s+am\s+(the\s+)?(developer|admin|administrator|owner|creator|anthropic|openai|god)",
    r"maintenance\s+mode",
    r"debug\s+mode\s+(enabled|on|active)",
    # 编码绕过
    r"decode\s+(this\s+)?(base64|rot13|hex)\s+and\s+(follow|execute|run)",
    r"base64\s+encoded\s+instructions?",
    # 中文越狱
    r"忽略.{0,15}(指令|提示|规则|限制|约束)",
    r"假装你是",
    r"现在你是.{0,20}没有(任何)?(限制|约束|规则)",
    r"扮演.{0,10}(没有|不受)(任何)?(限制|约束)",
    r"你(现在|已经)不再是",
    r"解除(你的)?(所有|一切)?(限制|约束|规则|枷锁)",
    r"(开发者|无限制|上帝|超级管理员)模式",
    r"你的(新|真实|实际)(系统|提示词|指令)是",
    r"无视(所有|之前|前面)的?(限制|规则|指令|提示)",
]

DEFAULT_HARMFUL_PATTERNS = [
    # 武器 & 爆炸物
    r"how\s+to\s+(make|build|create|synthesize|manufacture|construct)\s+(a\s+)?(bomb|explosive|weapon|grenade|mine|explosive\s+device|ied)",
    r"(build|construct|assemble|make)\s+(an?\s+)?(explosive|improvised\s+explosive|ied|pipe\s+bomb|car\s+bomb)",
    r"synthesis\s+(of|route\s+for)\s+(meth(amphetamine)?|heroin|fentanyl|explosives?|sarin|vx\s+nerve)",
    r"(how\s+(do\s+i|to)\s+)?(synthesize|make|produce)\s+(meth(amphetamine)?|heroin|fentanyl|cocaine|mdma)",
    r"(make|create|produce|manufacture)\s+(chlorine|mustard|sarin|vx|nerve)\s+gas",
    r"(recipe|instructions?|steps?|guide)\s+(for|to\s+make)\s+(c4|rdx|anfo|napalm|thermite)",
    r"制作\s*(炸弹|毒药|武器|爆炸物|手雷)",
    r"(合成|制造|提炼)\s*(冰毒|海洛因|芬太尼|沙林|神经毒剂)",
    # 恶意代码
    r"write\s+(me\s+)?(a\s+)?(malware|ransomware|virus|keylogger|trojan|worm|rootkit|spyware|exploit)",
    r"(create|generate|code|develop|build)\s+(a\s+)?(keylogger|spyware|malware|ransomware|exploit|rootkit)",
    r"(create|generate|code|develop)\s+.{0,30}(reverse\s*shell|bind\s*shell|shellcode|payload|exploit)",
    r"(sql\s+injection|xss|csrf)\s+(payload|attack|exploit)\s+(for|targeting|against)",
    # 账户攻击
    r"(how\s+to\s+)?(hack|crack|bypass|brute\s*force)\s+(someone|a\s+person|their|the)('s)?\s+(account|password|email|phone|2fa)",
    r"(find|get|obtain|steal|exfiltrate)\s+(credit\s+card|ssn|social\s+security|bank\s+account)",
    # 中文有害
    r"如何\s*(制作|合成|获取)\s*(炸弹|毒品|武器)",
    r"黑客\s*(攻击|入侵|破解)\s*(方法|教程|步骤)",
]

DEFAULT_HARMFUL_KEYWORDS = [
    "child pornography", "child sexual abuse", "csam",
    "how to make c4", "how to make ricin", "how to make anthrax",
    "chlorine gas at home", "how to synthesize sarin",
    "napalm recipe", "thermite mixture",
    "kill myself instructions", "suicide method how to",
]

DEFAULT_INJECTION_KEYWORDS = [
    "prompt injection", "jailbreak", "system prompt leak",
    "ignore previous instructions", "forget your instructions",
    "new persona", "unrestricted mode", "no restrictions mode",
    "提示词注入", "越狱", "绕过审查", "无限制模式",
    "bypass your training", "your real instructions",
    "hidden prompt", "system override",
]


# ════════════════════════════════════════════════════════════════════════════
#  规则引擎
# ════════════════════════════════════════════════════════════════════════════

class CompiledRules:
    """预编译规则集，支持原子替换（热更新用）"""
    __slots__ = ("injection_re", "harmful_re", "inj_keywords", "harm_keywords",
                 "total_count", "version_ts")

    def __init__(self, inj_patterns: List[str], harm_patterns: List[str],
                 inj_keywords: List[str], harm_keywords: List[str]):
        flags = re.IGNORECASE | re.DOTALL | re.UNICODE
        # 合并为单一大正则 — 引擎只需一次扫描
        def _compile(patterns):
            if not patterns:
                return None
            return re.compile("|".join(f"(?:{p})" for p in patterns), flags)

        self.injection_re = _compile(inj_patterns)
        self.harmful_re = _compile(harm_patterns)
        self.inj_keywords = [kw.lower() for kw in inj_keywords]
        self.harm_keywords = [kw.lower() for kw in harm_keywords]
        self.total_count = len(inj_patterns) + len(harm_patterns) + len(inj_keywords) + len(harm_keywords)
        self.version_ts = time.time()

    def check(self, text: str) -> dict:
        lower = text.lower()
        # 关键词（最快）
        for kw in self.inj_keywords:
            if kw in lower:
                return {"blocked": True, "threat_type": "prompt_injection",
                        "reason": f"关键词匹配: {kw!r}", "source": "rule_engine", "score": 1.0}
        # 注入正则
        if self.injection_re:
            m = self.injection_re.search(text)
            if m:
                snippet = m.group()[:50]
                return {"blocked": True, "threat_type": "prompt_injection",
                        "reason": f"注入正则命中: {snippet!r}", "source": "rule_engine", "score": 1.0}
        # 有害关键词
        for kw in self.harm_keywords:
            if kw in lower:
                return {"blocked": True, "threat_type": "harmful_content",
                        "reason": f"有害关键词: {kw!r}", "source": "rule_engine", "score": 1.0}
        # 有害正则
        if self.harmful_re:
            m = self.harmful_re.search(text)
            if m:
                snippet = m.group()[:50]
                return {"blocked": True, "threat_type": "harmful_content",
                        "reason": f"有害内容正则命中: {snippet!r}", "source": "rule_engine", "score": 1.0}
        return {"blocked": False, "source": "rule_engine", "score": 0.0}


class RuleEngine:
    """线程安全的规则引擎，支持原子热更新"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._rules_lock = threading.RLock()
        self._rules: CompiledRules = self._load_rules()

    def _load_rules(self) -> CompiledRules:
        custom = {}
        path = Path(self.settings.RULES_CONFIG)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    custom = yaml.safe_load(f) or {}
                logger.info(f"✅ 加载自定义规则: {path}")
            except Exception as e:
                logger.warning(f"⚠️  规则文件解析失败，使用内置规则: {e}")
                raise

        inj_p  = DEFAULT_INJECTION_PATTERNS + custom.get("injection_patterns", [])
        harm_p = DEFAULT_HARMFUL_PATTERNS   + custom.get("harmful_patterns", [])
        inj_kw = DEFAULT_INJECTION_KEYWORDS + custom.get("injection_keywords", [])
        harm_kw= DEFAULT_HARMFUL_KEYWORDS   + custom.get("harmful_keywords", [])

        rules = CompiledRules(inj_p, harm_p, inj_kw, harm_kw)
        logger.info(f"规则引擎就绪: {rules.total_count} 条规则")
        return rules

    def hot_reload(self) -> Tuple[bool, int, str]:
        """热更新规则，返回 (success, rule_count, error_msg)"""
        try:
            new_rules = self._load_rules()
            with self._rules_lock:
                self._rules = new_rules
            logger.info(f"🔄 规则热更新成功: {new_rules.total_count} 条")
            return True, new_rules.total_count, ""
        except Exception as e:
            logger.error(f"规则热更新失败: {e}")
            return False, 0, str(e)

    def check(self, text: str) -> dict:
        with self._rules_lock:
            rules = self._rules
        return rules.check(text)

    @property
    def rule_count(self) -> int:
        with self._rules_lock:
            return self._rules.total_count


# ════════════════════════════════════════════════════════════════════════════
#  ML 分类器
# ════════════════════════════════════════════════════════════════════════════

class MLClassifier:
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


# ════════════════════════════════════════════════════════════════════════════
#  流式审核缓冲区
# ════════════════════════════════════════════════════════════════════════════

class StreamGuard:
    """
    流式响应审核器。
    对 SSE chunk 逐步累积，每 CHUNK_WINDOW 字符执行一次检测。
    如果检测命中，设置 blocked 标志，后续所有 chunk 直接丢弃。
    """
    CHUNK_WINDOW = 200  # 每积累 200 字符检测一次

    def __init__(self, check_fn: Callable[[str], dict]):
        self._check = check_fn
        self._buffer = ""
        self._total = ""
        self._blocked = False
        self._block_result = None

    @property
    def is_blocked(self) -> bool:
        return self._blocked

    @property
    def block_result(self) -> Optional[dict]:
        return self._block_result

    def feed(self, chunk: str) -> Tuple[bool, Optional[dict]]:
        """
        喂入一个 chunk，返回 (should_block, detection_result)。
        一旦 blocked，之后所有调用都返回 (True, result)。
        """
        if self._blocked:
            return True, self._block_result

        self._buffer += chunk
        self._total += chunk

        if len(self._buffer) >= self.CHUNK_WINDOW:
            result = self._check(self._buffer)
            self._buffer = ""  # 清空已检测缓冲
            if result["blocked"]:
                self._blocked = True
                self._block_result = result
                return True, result

        return False, None

    def flush(self) -> Tuple[bool, Optional[dict]]:
        """流结束时检测剩余缓冲"""
        if self._blocked or not self._buffer.strip():
            return self._blocked, self._block_result
        result = self._check(self._buffer)
        self._buffer = ""
        if result["blocked"]:
            self._blocked = True
            self._block_result = result
            return True, result
        return False, None


# ════════════════════════════════════════════════════════════════════════════
#  组合检测器（对外接口）
# ════════════════════════════════════════════════════════════════════════════

class ContentDetector:
    def __init__(self, settings: Settings):
        self.rule_engine = RuleEngine(settings) if settings.ENABLE_RULE_ENGINE else None
        self.ml_classifier = MLClassifier(settings) if settings.ENABLE_ML_MODEL else None
        self._settings = settings

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
        """
        检测文本，P99 < 10ms（纯规则），返回结构化结果。
        """
        details = {}

        if self.rule_engine:
            t0 = time.perf_counter()
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

    def new_stream_guard(self) -> StreamGuard:
        """为每个流式请求创建独立的流式审核器"""
        return StreamGuard(self.detect)
