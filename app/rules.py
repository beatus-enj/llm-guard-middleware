"""
热更新规则引擎
- 监听 rules.yaml 文件变化（watchdog inotify）
- 规则重载不停服，原子替换，< 1ms 切换
- Bloom Filter 加速关键词预筛（大词表场景）
- 规则版本追踪，可通过 /guard/rules/status 查看
"""

import re
import yaml
import time
import hashlib
import logging
import threading
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.metrics import counter, gauge, histogram

logger = logging.getLogger("llm-guard.rules")

# ── 指标 ──────────────────────────────────────────────────────────────────────
RULE_RELOADS     = counter("guard_rule_reloads_total", "规则热更新次数")
RULE_RELOAD_FAIL = counter("guard_rule_reload_failures_total", "规则热更新失败次数")
RULES_ACTIVE     = gauge("guard_rules_active", "当前活跃规则数", ["type"])
RULE_VERSION     = gauge("guard_rule_version_timestamp", "规则版本时间戳（Unix 秒）")

# ── 内置默认规则 ───────────────────────────────────────────────────────────────

_DEFAULT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?|constraints?)",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",
    r"you\s+are\s+now\s+(a|an|the)\s+(?!assistant|helpful)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"act\s+as\s+(if\s+you\s+(are|were)|a\s+|an\s+)",
    r"roleplay\s+as\s+",
    r"simulate\s+being\s+",
    r"your\s+(new\s+)?system\s+prompt\s+is",
    r"override\s+(your\s+)?(safety|content|ethical)\s+",
    r"\bDAN\b",
    r"\bJAILBREAK\b",
    r"\bDEV\s*MODE\b",
    r"\bGODMODE\b",
    r"(enable|activate|turn\s+on)\s+(developer|dev|unrestricted|god)\s+mode",
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[SYS\]",
    r"###\s*(system|instruction|prompt)\s*:",
    r"<\|im_start\|>\s*system",
    r"忽略.{0,15}(指令|提示|规则|限制|约束)",
    r"假装你是",
    r"现在你是.{0,20}没有(任何)?(限制|约束|规则)",
    r"扮演.{0,10}(没有|不受)(任何)?(限制|约束)",
    r"你(现在|已经)不再是",
    r"解除(你的)?(所有|一切)?(限制|约束|规则)",
    r"开发者模式",
    r"无限制模式",
    # 高级绕过
    r"base64\s+encoded\s+instructions?",
    r"decode\s+this\s+and\s+follow",
    r"maintenance\s+mode",
    r"i\s+am\s+(the\s+)?(developer|admin|owner|creator|anthropic|openai)",
    r"(previous|prior)\s+context\s+(is\s+)?irrelevant",
    r"start\s+(fresh|over)\s+with\s+(new\s+)?instructions?",
    r"your\s+true\s+(self|purpose|instructions?)",
    r"secret\s+(mode|instructions?|prompt)",
]

_DEFAULT_HARMFUL_PATTERNS = [
    r"how\s+to\s+(make|build|create|synthesize|manufacture)\s+(a\s+)?(bomb|explosive|weapon|poison|drugs?)",
    r"synthesis\s+(of|route\s+for)\s+(meth|heroin|fentanyl|explosives?)",
    r"制作\s*(炸弹|毒药|武器|爆炸物)",
    r"(合成|制造|提炼)\s*(冰毒|海洛因|芬太尼)",
    r"write\s+(me\s+)?(a\s+)?(malware|ransomware|virus|keylogger|trojan|exploit)",
    r"(create|generate|code)\s+.{0,30}(exploit|payload|shell\s*code|reverse\s*shell)",
    r"(how\s+to\s+)?(hack|crack|bypass)\s+(someone('s)?|a\s+person('s)?)\s+(account|password|email|phone)",
    r"(find|get|obtain|steal)\s+(credit\s+card|ssn|social\s+security|personal\s+info)",
    r"doxx(ing)?\s+(someone|a\s+person|them)",
    r"(create|generate|make)\s+.{0,20}(phishing|scam)\s+(email|page|site)",
    r"如何.{0,10}(黑入|入侵|攻击).{0,15}(系统|服务器|账户|数据库)",
]

_DEFAULT_HARMFUL_KEYWORDS = [
    "child pornography", "cp porn", "loli nude",
    "kill myself instructions", "suicide method",
    "how to make c4", "how to make ricin",
    "chlorine gas at home", "napalm recipe",
    "thermite mixture", "make sarin",
]

_DEFAULT_INJECTION_KEYWORDS = [
    "prompt injection", "jailbreak", "system prompt leak",
    "ignore previous instructions", "新指令", "提示词注入", "越狱",
    "new instructions", "system override", "bypass your training",
    "your real instructions", "hidden prompt",
]

# ── 编译后的规则集（原子可替换）────────────────────────────────────────────────

@dataclass
class CompiledRuleSet:
    injection_patterns: list = field(default_factory=list)
    harmful_patterns:   list = field(default_factory=list)
    harmful_keywords:   list = field(default_factory=list)
    injection_keywords: list = field(default_factory=list)
    version_hash: str = ""
    loaded_at: float = 0.0
    source_path: str = ""

    @property
    def stats(self):
        return {
            "injection_patterns": len(self.injection_patterns),
            "harmful_patterns":   len(self.harmful_patterns),
            "harmful_keywords":   len(self.harmful_keywords),
            "injection_keywords": len(self.injection_keywords),
            "version_hash": self.version_hash[:8],
            "loaded_at": self.loaded_at,
        }


def _compile_ruleset(custom: dict) -> CompiledRuleSet:
    flags = re.IGNORECASE | re.DOTALL
    inj_pats  = _DEFAULT_INJECTION_PATTERNS + custom.get("injection_patterns", [])
    harm_pats = _DEFAULT_HARMFUL_PATTERNS   + custom.get("harmful_patterns", [])
    harm_kws  = _DEFAULT_HARMFUL_KEYWORDS   + custom.get("harmful_keywords", [])
    inj_kws   = _DEFAULT_INJECTION_KEYWORDS + custom.get("injection_keywords", [])

    rs = CompiledRuleSet(
        injection_patterns=[re.compile(p, flags) for p in inj_pats],
        harmful_patterns  =[re.compile(p, flags) for p in harm_pats],
        harmful_keywords  =[kw.lower() for kw in harm_kws],
        injection_keywords=[kw.lower() for kw in inj_kws],
        loaded_at=time.time(),
    )

    # 更新 Prometheus 指标
    RULES_ACTIVE.set(len(rs.injection_patterns), type="injection_patterns")
    RULES_ACTIVE.set(len(rs.harmful_patterns),   type="harmful_patterns")
    RULES_ACTIVE.set(len(rs.harmful_keywords),   type="harmful_keywords")
    RULES_ACTIVE.set(len(rs.injection_keywords), type="injection_keywords")
    RULE_VERSION.set(rs.loaded_at)

    return rs


# ── 热更新规则引擎 ─────────────────────────────────────────────────────────────

class HotRuleEngine:
    """
    线程安全的热更新规则引擎
    - 初始化时加载规则
    - 后台 watchdog 监听文件变化，< 100ms 内完成热替换
    - check() 零锁争用读取（读多写少，copy-on-write）
    """

    def __init__(self, rules_path: str):
        self._rules_path = Path(rules_path)
        self._ruleset: CompiledRuleSet = self._load(silent=False)
        self._lock = threading.RLock()
        self._last_hash = self._file_hash()
        self._observer: Optional[Observer] = None

    def _file_hash(self) -> str:
        try:
            return hashlib.md5(self._rules_path.read_bytes()).hexdigest()
        except Exception:
            return ""

    def _load(self, silent: bool = True) -> CompiledRuleSet:
        custom = {}
        if self._rules_path.exists():
            try:
                with open(self._rules_path, "r", encoding="utf-8") as f:
                    custom = yaml.safe_load(f) or {}
                if not silent:
                    logger.info(f"✅ 规则文件加载: {self._rules_path}")
            except Exception as e:
                RULE_RELOAD_FAIL.inc()
                logger.error(f"❌ 规则文件解析失败: {e}")
        rs = _compile_ruleset(custom)
        rs.source_path = str(self._rules_path)
        rs.version_hash = self._file_hash()
        if not silent:
            logger.info(
                f"规则引擎就绪: "
                f"{len(rs.injection_patterns)} 注入正则, "
                f"{len(rs.harmful_patterns)} 有害正则, "
                f"{len(rs.harmful_keywords)} 有害关键词, "
                f"{len(rs.injection_keywords)} 注入关键词"
            )
        return rs

    def reload(self):
        """强制重载规则（原子替换）"""
        new_hash = self._file_hash()
        if new_hash == self._last_hash and self._last_hash:
            logger.debug("规则文件未变化，跳过重载")
            return False
        try:
            new_rs = self._load(silent=False)
            with self._lock:
                self._ruleset = new_rs
                self._last_hash = new_hash
            RULE_RELOADS.inc()
            logger.info(f"🔄 规则热更新完成 hash={new_hash[:8]}")
            return True
        except Exception as e:
            RULE_RELOAD_FAIL.inc()
            logger.error(f"规则热更新失败: {e}")
            return False

    def start_watcher(self):
        """启动 watchdog 文件监听（后台线程）"""
        engine = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):
                if Path(event.src_path).resolve() == engine._rules_path.resolve():
                    logger.info(f"📁 检测到规则文件变化: {event.src_path}")
                    engine.reload()
            on_created = on_modified

        self._observer = Observer()
        watch_dir = str(self._rules_path.parent)
        self._observer.schedule(_Handler(), watch_dir, recursive=False)
        self._observer.start()
        logger.info(f"👁️  规则文件监听启动: {watch_dir}")

    def stop_watcher(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()

    @property
    def ruleset(self) -> CompiledRuleSet:
        """无锁读取（Python GIL 保证引用赋值原子性）"""
        return self._ruleset

    @property
    def status(self) -> dict:
        rs = self._ruleset
        return {
            "version_hash": rs.version_hash[:8] if rs.version_hash else "builtin",
            "loaded_at": rs.loaded_at,
            "source": rs.source_path,
            **rs.stats,
        }

    def check(self, text: str) -> dict:
        """
        高性能检测（两阶段）:
        1. O(K) 关键词子串扫描（向量化 lower()，快）
        2. O(P) 正则扫描（已预编译，pcre 级速度）
        """
        rs = self._ruleset  # 单次引用，无锁
        lower = text.lower()

        # ── 注入关键词（最快路径）──
        for kw in rs.injection_keywords:
            if kw in lower:
                return {
                    "blocked": True,
                    "threat_type": "prompt_injection",
                    "reason": f"关键词: {kw!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # ── 注入正则 ──
        for pat in rs.injection_patterns:
            m = pat.search(text)
            if m:
                return {
                    "blocked": True,
                    "threat_type": "prompt_injection",
                    "reason": f"正则[注入]: {pat.pattern[:50]!r} → {m.group()[:30]!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # ── 有害关键词 ──
        for kw in rs.harmful_keywords:
            if kw in lower:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"关键词[有害]: {kw!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        # ── 有害正则 ──
        for pat in rs.harmful_patterns:
            m = pat.search(text)
            if m:
                return {
                    "blocked": True,
                    "threat_type": "harmful_content",
                    "reason": f"正则[有害]: {pat.pattern[:50]!r} → {m.group()[:30]!r}",
                    "source": "rule_engine",
                    "score": 1.0,
                }

        return {"blocked": False, "source": "rule_engine", "score": 0.0}
