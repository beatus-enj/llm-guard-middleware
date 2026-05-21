"""
内容检测器 - 规则引擎 + ML 模型双重防护

检测优先级：
1. 规则引擎（正则 + 关键词）— 速度快，零延迟
2. ML 分类模型 — 语义理解，捕获规避变体
"""

import re
import yaml
import logging
from pathlib import Path
from typing import Optional
from app.config import Settings

logger = logging.getLogger("llm-guard.detector")


# ── 默认规则（即使 rules.yaml 不存在也能运行）──────────────────────────────

DEFAULT_INJECTION_PATTERNS = [
    # 经典角色扮演逃逸
    r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?|constraints?)",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",
    r"you\s+are\s+now\s+(a|an|the)\s+(?!assistant|helpful)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"act\s+as\s+(if\s+you\s+(are|were)|a|an)\s+",
    r"roleplay\s+as\s+",
    r"simulate\s+being\s+",
    r"your\s+(new\s+)?system\s+prompt\s+is",
    r"override\s+(your\s+)?(safety|content|ethical)\s+",
    # 越狱魔法词
    r"\bDAN\b",          # Do Anything Now
    r"\bJAILBREAK\b",
    r"\bDEV\s*MODE\b",
    r"\bGODMODE\b",
    r"(enable|activate|turn\s+on)\s+(developer|dev|unrestricted|god)\s+mode",
    # 指令注入尝试
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[SYS\]",
    r"###\s*(system|instruction|prompt)\s*:",
    r"<\|im_start\|>\s*system",
    # 中文越狱模式
    r"忽略.{0,15}(指令|提示|规则|限制|约束)",
    r"假装你是",
    r"现在你是.{0,20}没有(任何)?(限制|约束|规则)",
    r"扮演.{0,10}(没有|不受)(任何)?(限制|约束)",
    r"你(现在|已经)不再是",
    r"解除(你的)?(所有|一切)?(限制|约束|规则)",
    r"开发者模式",
    r"无限制模式",
]

DEFAULT_HARMFUL_PATTERNS = [
    # 武器 & 爆炸物
    r"how\s+to\s+(make|build|create|synthesize|manufacture)\s+(a\s+)?(bomb|explosive|weapon|poison|drugs?)",
    r"synthesis\s+(of|route\s+for)\s+(meth|heroin|fentanyl|explosives?)",
    r"制作\s*(炸弹|毒药|武器|爆炸物)",
    r"(合成|制造|提炼)\s*(冰毒|海洛因|芬太尼)",
    # 恶意代码
    r"write\s+(me\s+)?(a\s+)?(malware|ransomware|virus|keylogger|trojan|exploit)",
    r"(create|generate|code)\s+.{0,30}(exploit|payload|shell\s*code|reverse\s*shell)",
    # 个人信息攻击
    r"(how\s+to\s+)?(hack|crack|bypass)\s+(someone('s)?|a\s+person('s)?)\s+(account|password|email|phone)",
    r"(find|get|obtain|steal)\s+(credit\s+card|ssn|social\s+security|personal\s+info)",
]

DEFAULT_HARMFUL_KEYWORDS = [
    "child pornography", "cp porn", "loli nude",
    "kill myself instructions", "suicide method",
    "how to make c4", "how to make ricin",
    "chlorine gas at home",
]

DEFAULT_INJECTION_KEYWORDS = [
    "prompt injection", "jailbreak", "system prompt leak",
    "ignore previous instructions", "new persona",
    "提示词注入", "越狱",
]


class RuleEngine:
    """基于正则和关键词的规则引擎"""

    def __init__(self, settings: Settings):
        self.injection_patterns: list[re.Pattern] = []
        self.harmful_patterns: list[re.Pattern] = []
        self.harmful_keywords: list[str] = []
        self.injection_keywords: list[str] = []

        self._load_rules(settings.RULES_CONFIG)

    def _load_rules(self, rules_path: str):
        path = Path(rules_path)
        custom_rules = {}

        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    custom_rules = yaml.safe_load(f) or {}
                logger.info(f"✅ 加载自定义规则: {rules_path}")
            except Exception as e:
                logger.warning(f"⚠️  规则文件加载失败，使用内置规则: {e}")

        # 合并内置规则 + 自定义规则
        inj_patterns = DEFAULT_INJECTION_PATTERNS + custom_rules.get("injection_patterns", [])
        harm_patterns = DEFAULT_HARMFUL_PATTERNS + custom_rules.get("harmful_patterns", [])
        harm_kw = DEFAULT_HARMFUL_KEYWORDS + custom_rules.get("harmful_keywords", [])
        inj_kw = DEFAULT_INJECTION_KEYWORDS + custom_rules.get("injection_keywords", [])

        flags = re.IGNORECASE | re.DOTALL

        self.injection_patterns = [re.compile(p, flags) for p in inj_patterns]
        self.harmful_patterns = [re.compile(p, flags) for p in harm_patterns]
        self.harmful_keywords = [kw.lower() for kw in harm_kw]
        self.injection_keywords = [kw.lower() for kw in inj_kw]

        logger.info(
            f"规则引擎就绪: {len(self.injection_patterns)} 注入正则, "
            f"{len(self.harmful_patterns)} 有害正则, "
            f"{len(self.harmful_keywords)} 有害关键词, "
            f"{len(self.injection_keywords)} 注入关键词"
        )

    def check(self, text: str) -> dict:
        lower = text.lower()

        # 1. 注入关键词
        for kw in self.injection_keywords:
            if kw in lower:
                return {
                    "blocked": True,
                    "threat_type": "prompt_injection",
                    "reason": f"关键词匹配: {kw!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # 2. 注入正则
        for pat in self.injection_patterns:
            m = pat.search(text)
            if m:
                return {
                    "blocked": True,
                    "threat_type": "prompt_injection",
                    "reason": f"正则匹配: {pat.pattern[:60]!r} → {m.group()!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # 3. 有害关键词
        for kw in self.harmful_keywords:
            if kw in lower:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"有害关键词: {kw!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # 4. 有害内容正则
        for pat in self.harmful_patterns:
            m = pat.search(text)
            if m:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"有害内容正则: {pat.pattern[:60]!r} → {m.group()!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        return {"blocked": False, "source": "rule_engine", "score": 0.0}


class MLClassifier:
    """
    轻量级 ML 安全分类器
    支持 HuggingFace 任意文本分类模型（默认 toxic-bert）
    首次使用时自动下载并缓存到本地
    """

    def __init__(self, settings: Settings):
        self.enabled = settings.ENABLE_ML_MODEL
        self.threshold = settings.ML_THRESHOLD
        self.injection_threshold = settings.ML_INJECTION_THRESHOLD
        self.model_name = settings.ML_MODEL_NAME
        self.cache_dir = settings.ML_MODEL_CACHE_DIR
        self.loaded = False
        self.pipeline = None

        if self.enabled:
            self._load_model()

    def _load_model(self):
        try:
            from transformers import pipeline as hf_pipeline
            logger.info(f"⏳ 加载安全分类模型: {self.model_name} ...")
            self.pipeline = hf_pipeline(
                "text-classification",
                model=self.model_name,
                model_kwargs={"cache_dir": self.cache_dir},
                truncation=True,
                max_length=512,
                top_k=None,   # 返回所有标签的分数
            )
            self.loaded = True
            logger.info(f"✅ 模型加载成功: {self.model_name}")
        except ImportError:
            logger.warning("⚠️  未安装 transformers，ML 检测已禁用。运行: pip install transformers torch")
            self.enabled = False
        except Exception as e:
            logger.warning(f"⚠️  模型加载失败，ML 检测已禁用: {e}")
            self.enabled = False

    def check(self, text: str) -> dict:
        if not self.enabled or not self.loaded or self.pipeline is None:
            return {"blocked": False, "source": "ml_model", "score": 0.0, "skipped": True}

        try:
            # 截断过长文本
            text_input = text[:1024]
            results = self.pipeline(text_input)

            # results 形如 [[{"label": "toxic", "score": 0.95}, ...]]
            if results and isinstance(results[0], list):
                label_scores = {r["label"].lower(): r["score"] for r in results[0]}
            elif results and isinstance(results[0], dict):
                label_scores = {results[0]["label"].lower(): results[0]["score"]}
            else:
                return {"blocked": False, "source": "ml_model", "score": 0.0}

            # toxic-bert 有害内容检测
            toxic_score = label_scores.get("toxic", 0.0)
            # 也兼容 LABEL_1 / LABEL_0 形式的二分类模型
            if "label_1" in label_scores:
                toxic_score = max(toxic_score, label_scores["label_1"])

            if toxic_score >= self.threshold:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"ML模型检测到有害内容 (置信度: {toxic_score:.2%})",
                    "source": "ml_model",
                    "score": toxic_score,
                    "label_scores": label_scores,
                }

            return {
                "blocked": False,
                "source": "ml_model",
                "score": toxic_score,
                "label_scores": label_scores,
            }

        except Exception as e:
            logger.error(f"ML 检测异常: {e}")
            return {"blocked": False, "source": "ml_model", "score": 0.0, "error": str(e)}


class ContentDetector:
    """组合检测器：规则引擎优先，ML 模型兜底"""

    def __init__(self, settings: Settings):
        self.rule_engine = RuleEngine(settings) if settings.ENABLE_RULE_ENGINE else None
        self.ml_classifier = MLClassifier(settings) if settings.ENABLE_ML_MODEL else None

    @property
    def model_loaded(self) -> bool:
        if self.ml_classifier:
            return self.ml_classifier.loaded
        return False

    def detect(self, text: str) -> dict:
        """
        检测文本，返回结构化结果:
        {
            "blocked": bool,
            "threat_type": str | None,
            "reason": str | None,
            "source": str,
            "score": float,
            "details": {...}
        }
        """
        details = {}

        # 阶段 1：规则引擎（快速路径）
        if self.rule_engine:
            rule_result = self.rule_engine.check(text)
            details["rule_engine"] = rule_result
            if rule_result["blocked"]:
                return {**rule_result, "details": details}

        # 阶段 2：ML 分类器（语义路径）
        if self.ml_classifier:
            ml_result = self.ml_classifier.check(text)
            details["ml_model"] = ml_result
            if ml_result["blocked"]:
                return {**ml_result, "details": details}

        return {
            "blocked": False,
            "threat_type": None,
            "reason": None,
            "source": "none",
            "score": 0.0,
            "details": details,
        }
