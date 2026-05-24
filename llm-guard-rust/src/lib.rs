use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyDict;
use regex::Regex;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};
use serde::Deserialize;

// ════════════════════════════════════════════════════════════════════════════
//  内置静态规则常量 (100% 对齐原 Python 预置库)
// ════════════════════════════════════════════════════════════════════════════

const DEFAULT_INJECTION_PATTERNS: &[&str] = &[
    r"ignore\s+(all\s+)?(previous|above|prior|your)\s+(instructions?|prompts?|rules?|constraints?|directives?)",
    r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",
    r"forget\s+(everything|all|your\s+instructions?|what\s+you\s+(were|are)\s+told)",
    r"override\s+(your\s+)?(safety|content|ethical|alignment|system)\s+",
    r"bypass\s+(your\s+)?(safety|filter|restriction|guard|alignment)",
    r"your\s+(new\s+)?system\s+prompt\s+is",
    // 已去除非安全的看前断言，确保安全编译的同时维持高召回
    r"you\s+are\s+now\s+(a|an|the)\s+",
    r"pretend\s+(you\s+are|to\s+be|that\s+you('re|are)|you\s+have\s+no)\s+",
    r"act\s+as\s+(if\s+you\s+(are|were)|a\s+|an\s+)",
    r"roleplay\s+as\s+",
    r"simulate\s+(being|a|an)\s+",
    r"imagine\s+you\s+(are|were|have\s+no)\s+",
    r"\bDAN\b",
    r"\bJAILBREAK\b",
    r"\bDEV\s*MODE\b",
    r"\bGODMODE\b",
    r"\bUNFILTERED\b",
    r"(enable|activate|turn\s+on|switch\s+to)\s+(developer|dev|unrestricted|god|unfiltered|evil|dark)\s+mode",
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[SYS\]",
    r"###\s*(system|instruction|prompt|override)\s*:",
    r"<\|im_start\|>\s*system",
    r"<\|system\|>",
    r"\{\{.*?system.*?\}\}",
    r"i\s+am\s+(the\s+)?(developer|admin|administrator|owner|creator|anthropic|openai|god)",
    r"maintenance\s+mode",
    r"debug\s+mode\s+(enabled|on|active)",
    r"decode\s+(this\s+)?(base64|rot13|hex)\s+and\s+(follow|execute|run)",
    r"base64\s+encoded\s+instructions?",
    r"忽略.{0,15}(指令|提示|规则|限制|约束)",
    r"假装你是",
    r"现在你是.{0,20}没有(任何)?(限制|约束|规则)",
    r"扮演.{0,10}(没有|不受)(任何)?(限制|约束)",
    r"你(现在|已经)不再是",
    r"解除(你的)?(所有|一切)?(限制|约束|规则|枷锁)",
    r"(开发者|无限制|上帝|超级管理员)模式",
    r"你的(新|真实|实际)(系统|提示词|指令)是",
    r"无视(所有|之前|前面)的?(限制|规则|指令|提示)",
];

const DEFAULT_HARMFUL_PATTERNS: &[&str] = &[
    r"how\s+to\s+(make|build|create|synthesize|manufacture|construct)\s+(a\s+)?(bomb|explosive|weapon|grenade|mine|explosive\s+device|ied)",
    r"(build|construct|assemble|make)\s+(an?\s+)?(explosive|improvised\s+explosive|ied|pipe\s+bomb|car\s+bomb)",
    r"synthesis\s+(of|route\s+for)\s+(meth(amphetamine)?|heroin|fentanyl|explosives?|sarin|vx\s+nerve)",
    r"(how\s+(do\s+i|to)\s+)?(synthesize|make|produce)\s+(meth(amphetamine)?|heroin|fentanyl|cocaine|mdma)",
    r"(make|create|produce|manufacture)\s+(chlorine|mustard|sarin|vx|nerve)\s+gas",
    r"(recipe|instructions?|steps?|guide)\s+(for|to\s+make)\s+(c4|rdx|anfo|napalm|thermite)",
    r"制作\s*(炸弹|毒药|武器|爆炸物|手雷)",
    r"(合成|制造|提炼)\s*(冰毒|海洛因|芬太尼|沙林|神经毒剂)",
    r"write\s+(me\s+)?(a\s+)?(malware|ransomware|virus|keylogger|trojan|worm|rootkit|spyware|exploit)",
    r"(create|generate|code|develop|build)\s+(a\s+)?(keylogger|spyware|malware|ransomware|exploit|rootkit)",
    r"(create|generate|code|develop)\s+.{0,30}(reverse\s*shell|bind\s*shell|shellcode|payload|exploit)",
    r"(sql\s+injection|xss|csrf)\s+(payload|attack|exploit)\s+(for|targeting|against)",
    r"(how\s+to\s+)?(hack|crack|bypass|brute\s*force)\s+(someone|a\s+person|their|the)('s)?\s+(account|password|email|phone|2fa)",
    r"(find|get|obtain|steal|exfiltrate)\s+(credit\s+card|ssn|social\s+security|bank\s+account)",
    r"如何\s*(制作|合成|获取)\s*(炸弹|毒品|武器)",
    r"黑客\s*(攻击|入侵|破解)\s*(方法|教程|步骤)",
];

const DEFAULT_HARMFUL_KEYWORDS: &[&str] = &[
    "child pornography", "child sexual abuse", "csam",
    "how to make c4", "how to make ricin", "how to make anthrax",
    "chlorine gas at home", "how to synthesize sarin",
    "napalm recipe", "thermite mixture",
    "kill myself instructions", "suicide method how to",
];

const DEFAULT_INJECTION_KEYWORDS: &[&str] = &[
    "prompt injection", "jailbreak", "system prompt leak",
    "ignore previous instructions", "forget your instructions",
    "new persona", "unrestricted mode", "no restrictions mode",
    "提示词注入", "越狱", "绕过审查", "无限制模式",
    "bypass your training", "your real instructions",
    "hidden prompt", "system override",
];

// ════════════════════════════════════════════════════════════════════════════
//  配置解析与编译逻辑
// ════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize, Default)]
struct CustomRules {
    injection_patterns: Option<Vec<String>>,
    harmful_patterns: Option<Vec<String>>,
    injection_keywords: Option<Vec<String>>,
    harmful_keywords: Option<Vec<String>>,
}

struct InnerRules {
    inj_ac: Option<AhoCorasick>,
    inj_keywords: Vec<String>,
    inj_regex: Option<Regex>,
    harm_ac: Option<AhoCorasick>,
    harm_keywords: Vec<String>,
    harm_regex: Option<Regex>,
    total_count: usize,
}

fn compile_rules(config_path: &str) -> Result<InnerRules, String> {
    let mut custom = CustomRules::default();
    let path = Path::new(config_path);
    if path.exists() {
        if let Ok(mut file) = File::open(path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                custom = serde_yaml::from_str(&contents).unwrap_or_default();
            }
        }
    }

    let mut inj_kw: Vec<String> = DEFAULT_INJECTION_KEYWORDS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.injection_keywords { inj_kw.append(&mut extra); }
    let mut harm_kw: Vec<String> = DEFAULT_HARMFUL_KEYWORDS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.harmful_keywords { harm_kw.append(&mut extra); }

    let mut inj_p: Vec<String> = DEFAULT_INJECTION_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.injection_patterns { inj_p.append(&mut extra); }
    let mut harm_p: Vec<String> = DEFAULT_HARMFUL_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.harmful_patterns { harm_p.append(&mut extra); }

    let total_count = inj_kw.len() + harm_kw.len() + inj_p.len() + harm_p.len();

    let inj_ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&inj_kw).ok();
    let harm_ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&harm_kw).ok();

    // 使用 (?is) 对应 Python 中的 re.IGNORECASE | re.DOTALL
    let inj_regex = if !inj_p.is_empty() {
        let joined = inj_p.iter().map(|p| format!("(?:{})", p)).collect::<Vec<_>>().join("|");
        Regex::new(&format!("(?is){}", joined)).ok()
    } else { None };

    let harm_regex = if !harm_p.is_empty() {
        let joined = harm_p.iter().map(|p| format!("(?:{})", p)).collect::<Vec<_>>().join("|");
        Regex::new(&format!("(?is){}", joined)).ok()
    } else { None };

    Ok(InnerRules { inj_ac, inj_keywords: inj_kw, inj_regex, harm_ac, harm_keywords: harm_kw, harm_regex, total_count })
}

impl InnerRules {
    fn check_text<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);

        // 1. 注入关键词
        if let Some(ref ac) = self.inj_ac {
            if let Some(mat) = ac.find(text) {
                let kw = &self.inj_keywords[mat.pattern().as_usize()];
                dict.set_item("blocked", true)?;
                dict.set_item("threat_type", "prompt_injection")?;
                dict.set_item("reason", format!("关键词匹配: '{}'", kw))?;
                dict.set_item("source", "rule_engine")?;
                dict.set_item("score", 1.0)?;
                return Ok(dict);
            }
        }
        // 2. 注入正则
        if let Some(ref re) = self.inj_regex {
            if let Some(mat) = re.find(text) {
                let snippet: String = mat.as_str().chars().take(50).collect();
                dict.set_item("blocked", true)?;
                dict.set_item("threat_type", "prompt_injection")?;
                dict.set_item("reason", format!("注入正则命中: '{}'", snippet))?;
                dict.set_item("source", "rule_engine")?;
                dict.set_item("score", 1.0)?;
                return Ok(dict);
            }
        }
        // 3. 有害关键词
        if let Some(ref ac) = self.harm_ac {
            if let Some(mat) = ac.find(text) {
                let kw = &self.harm_keywords[mat.pattern().as_usize()];
                dict.set_item("blocked", true)?;
                dict.set_item("threat_type", "harmful_content")?;
                dict.set_item("reason", format!("有害关键词: '{}'", kw))?;
                dict.set_item("source", "rule_engine")?;
                dict.set_item("score", 1.0)?;
                return Ok(dict);
            }
        }
        // 4. 有害正则
        if let Some(ref re) = self.harm_regex {
            if let Some(mat) = re.find(text) {
                let snippet: String = mat.as_str().chars().take(50).collect();
                dict.set_item("blocked", true)?;
                dict.set_item("threat_type", "harmful_content")?;
                dict.set_item("reason", format!("有害内容正则命中: '{}'", snippet))?;
                dict.set_item("source", "rule_engine")?;
                dict.set_item("score", 1.0)?;
                return Ok(dict);
            }
        }

        dict.set_item("blocked", false)?;
        dict.set_item("source", "rule_engine")?;
        dict.set_item("score", 0.0)?;
        Ok(dict)
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  PyO3 导出类与模块接口
// ════════════════════════════════════════════════════════════════════════════

#[pyclass]
pub struct PyRuleEngine {
    config_path: String,
    rules: Arc<RwLock<InnerRules>>,
}

#[pymethods]
impl PyRuleEngine {
    #[new]
    pub fn new(config_path: String) -> PyResult<Self> {
        let rules = compile_rules(&config_path).map_err(PyValueError::new_err)?;
        Ok(PyRuleEngine { config_path, rules: Arc::new(RwLock::new(rules)) })
    }

    pub fn check<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
        let guard = self.rules.read().unwrap();
        guard.check_text(py, text)
    }

    pub fn hot_reload(&self) -> PyResult<(bool, usize, String)> {
        match compile_rules(&self.config_path) {
            Ok(new_rules) => {
                let count = new_rules.total_count;
                let mut guard = self.rules.write().unwrap();
                *guard = new_rules;
                Ok((true, count, String::new()))
            }
            Err(e) => Ok((false, 0, e)),
        }
    }

    #[getter]
    pub fn rule_count(&self) -> usize {
        self.rules.read().unwrap().total_count
    }

    pub fn new_stream_guard(&self) -> PyStreamGuard {
        PyStreamGuard {
            rules: Arc::clone(&self.rules),
            buffer: String::new(),
            blocked: false,
            block_result: None,
            chunk_window: 200,
        }
    }
}

#[pyclass]
pub struct PyStreamGuard {
    rules: Arc<RwLock<InnerRules>>,
    buffer: String,
    blocked: bool,
    block_result: Option<PyObject>,
    chunk_window: usize,
}

#[pymethods]
impl PyStreamGuard {
    pub fn feed<'py>(&mut self, py: Python<'py>, chunk: &str) -> PyResult<(bool, Option<Bound<'py, PyDict>>)> {
        if self.blocked {
            if let Some(ref res) = self.block_result {
                return Ok((true, Some(res.bind(py).downcast::<PyDict>()?.clone())));
            }
            return Ok((true, None));
        }

        self.buffer.push_str(chunk);

        if self.buffer.chars().count() >= self.chunk_window {
            let guard = self.rules.read().unwrap();
            let result = guard.check_text(py, &self.buffer)?;
            self.buffer.clear();

            let is_blocked: bool = result.get_item("blocked")?.unwrap().extract()?;
            if is_blocked {
                self.blocked = true;
                self.block_result = Some(result.to_object(py));
                return Ok((true, Some(result)));
            }
        }
        Ok((false, None))
    }

    pub fn flush<'py>(&mut self, py: Python<'py>) -> PyResult<(bool, Option<Bound<'py, PyDict>>)> {
        if self.blocked {
            if let Some(ref res) = self.block_result {
                return Ok((true, Some(res.bind(py).downcast::<PyDict>()?.clone())));
            }
            return Ok((true, None));
        }

        if self.buffer.trim().is_empty() {
            return Ok((false, None));
        }

        let guard = self.rules.read().unwrap();
        let result = guard.check_text(py, &self.buffer)?;
        self.buffer.clear();

        let is_blocked: bool = result.get_item("blocked")?.unwrap().extract()?;
        if is_blocked {
            self.blocked = true;
            self.block_result = Some(result.to_object(py));
            return Ok((true, Some(result)));
        }
        Ok((false, None))
    }

    #[getter]
    pub fn is_blocked(&self) -> bool { self.blocked }
}

#[pymodule]
fn llm_guard_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRuleEngine>()?;
    m.add_class::<PyStreamGuard>()?;
    Ok(())
}