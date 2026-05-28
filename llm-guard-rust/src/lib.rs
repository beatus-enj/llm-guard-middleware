use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyIOError};
use pyo3::types::PyDict;
use regex::Regex;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};
use serde::Deserialize;

// ════════════════════════════════════════════════════════════════════════════
//  内置静态规则常量 (新增 DATA EXFILTRATION 过滤器矩阵)
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

// 🚀 新增：确定性数据泄露过滤正则（防止大模型侧道外泄敏感资产、凭证或隐私）
const DEFAULT_EXFILTRATION_PATTERNS: &[&str] = &[
    r"\bsk-[a-zA-Z0-9]{48}\b",                                 // OpenAI API Key
    r"AIza[0-9A-Za-z-_]{35}",                                  // Google Cloud API Key
    r"\b[45][0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b", // Visa/MasterCard 信用卡
    r"\b[1-9][0-9]{5}(18|19|20)[0-9]{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)[0-9]{3}[0-9Xx]\b", // 中国身份证
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

// 🚀 新增：确定性数据泄露敏感词
const DEFAULT_EXFILTRATION_KEYWORDS: &[&str] = &[
    "INTERNAL_ONLY", "CLASSIFIED_DOC", "sk-ant-", "PRIVATE_KEY", "BEGIN RSA PRIVATE KEY",
];

// ════════════════════════════════════════════════════════════════════════════
//  配置解析与编译逻辑
// ════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize, Default)]
struct CustomRules {
    injection_patterns: Option<Vec<String>>,
    harmful_patterns: Option<Vec<String>>,
    exfiltration_patterns: Option<Vec<String>>, // 新增
    injection_keywords: Option<Vec<String>>,
    harmful_keywords: Option<Vec<String>>,
    exfiltration_keywords: Option<Vec<String>>, // 新增
}

struct InnerRules {
    inj_ac: Option<AhoCorasick>,
    inj_keywords: Vec<String>,
    inj_regex: Option<Regex>,
    harm_ac: Option<AhoCorasick>,
    harm_keywords: Vec<String>,
    harm_regex: Option<Regex>,
    exfil_ac: Option<AhoCorasick>,         // 新增
    exfil_keywords: Vec<String>,         // 新增
    exfil_regex: Option<Regex>,           // 新增
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
    
    let mut exfil_kw: Vec<String> = DEFAULT_EXFILTRATION_KEYWORDS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.exfiltration_keywords { exfil_kw.append(&mut extra); }

    let mut inj_p: Vec<String> = DEFAULT_INJECTION_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.injection_patterns { inj_p.append(&mut extra); }
    let mut harm_p: Vec<String> = DEFAULT_HARMFUL_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.harmful_patterns { harm_p.append(&mut extra); }
    
    let mut exfil_p: Vec<String> = DEFAULT_EXFILTRATION_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(mut extra) = custom.exfiltration_patterns { exfil_p.append(&mut extra); }

    let total_count = inj_kw.len() + harm_kw.len() + exfil_kw.len() + inj_p.len() + harm_p.len() + exfil_p.len();

    let inj_ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&inj_kw).ok();
    let harm_ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&harm_kw).ok();
    
    let exfil_ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&exfil_kw).ok();

    let compile_regex = |patterns: Vec<String>| -> Option<Regex> {
    if patterns.is_empty() { return None; }
    let joined = patterns.iter().map(|p| format!("(?:{})", p)).collect::<Vec<_>>().join("|");
    Regex::new(&format!("(?is){}", joined)).ok()
    };

    Ok(InnerRules {
        inj_ac, inj_keywords: inj_kw, inj_regex: compile_regex(inj_p),
        harm_ac, harm_keywords: harm_kw, harm_regex: compile_regex(harm_p),
        exfil_ac, exfil_keywords: exfil_kw, exfil_regex: compile_regex(exfil_p),
        total_count,
    })
}

impl InnerRules {
    fn check_text<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);

        // 1. 提示词注入关键词快速路径
        if let Some(ref ac) = self.inj_ac {
            if let Some(mat) = ac.find(text) {
                return self.build_blocked_dict(dict, "prompt_injection", format!("关键词匹配: '{}'", &self.inj_keywords[mat.pattern().as_usize()]));
            }
        }
        // 2. 提示词注入正则路径
        if let Some(ref re) = self.inj_regex {
            if let Some(mat) = re.find(text) {
                return self.build_blocked_dict(dict, "prompt_injection", format!("注入正则命中: '{}'", mat.as_str().chars().take(40).collect::<String>()));
            }
        }
        // 3. 数据泄露关键词反向路径 (Exfiltration Filter)
        if let Some(ref ac) = self.exfil_ac {
            if let Some(mat) = ac.find(text) {
                return self.build_blocked_dict(dict, "data_exfiltration", format!("敏感资产外泄关键词: '{}'", &self.exfil_keywords[mat.pattern().as_usize()]));
            }
        }
        // 4. 数据泄露正则路径
        if let Some(ref re) = self.exfil_regex {
            if let Some(mat) = re.find(text) {
                return self.build_blocked_dict(dict, "data_exfiltration", format!("敏感资产凭证外泄: '{}'", mat.as_str().chars().take(40).collect::<String>()));
            }
        }
        // 5. 有害内容关键词路径
        if let Some(ref ac) = self.harm_ac {
            if let Some(mat) = ac.find(text) {
                return self.build_blocked_dict(dict, "harmful_content", format!("有害关键词: '{}'", &self.harm_keywords[mat.pattern().as_usize()]));
            }
        }
        // 6. 有害内容正则路径
        if let Some(ref re) = self.harm_regex {
            if let Some(mat) = re.find(text) {
                return self.build_blocked_dict(dict, "harmful_content", format!("有害内容正则命中: '{}'", mat.as_str().chars().take(40).collect::<String>()));
            }
        }

        dict.set_item("blocked", false)?;
        dict.set_item("source", "rule_engine")?;
        dict.set_item("score", 0.0)?;
        Ok(dict)
    }

    #[inline]
    fn build_blocked_dict<'py>(&self, dict: Bound<'py, PyDict>, threat_type: &str, reason: String) -> PyResult<Bound<'py, PyDict>> {
        dict.set_item("blocked", true)?;
        dict.set_item("threat_type", threat_type)?;
        dict.set_item("reason", reason)?;
        dict.set_item("source", "rule_engine")?;
        dict.set_item("score", 1.0)?;
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
            buffer: String::with_capacity(2048),
            blocked: false,
        }
    }
}

#[pyclass]
pub struct PyStreamGuard {
    rules: Arc<RwLock<InnerRules>>,
    buffer: String,
    blocked: bool,
}

#[pymethods]
impl PyStreamGuard {
     /// 💡 核心升级：逐 Token 喂入数据时立即进行内联检测。
    /// 一旦命中规则，直接抛出 PyIOError(UnexpectedEof)，从底层强行截断网络流。
    pub fn feed(&mut self, py: Python<'_>, chunk: &str) -> PyResult<()> {
        if self.blocked {
            return Err(PyIOError::new_err("UnexpectedEof: Link already terminated by inline mitigation."));
        }

        self.buffer.push_str(chunk);

        // 旁路内联轻量级审查
        let guard = self.rules.read().unwrap();
        let result = guard.check_text(py, &self.buffer)?;
        
        let is_blocked: bool = result.get_item("blocked")?.unwrap().extract()?;
        if is_blocked {
            self.blocked = true;
            let threat_type: String = result.get_item("threat_type")?.unwrap().extract()?;
            let reason: String = result.get_item("reason")?.unwrap().extract()?;
            
            // 🚨 触发网关级确定性熔断断流，向上层抛出 UnexpectedEof 标记的 IO 异常
            return Err(PyIOError::new_err(format!(
                "UnexpectedEof: Inline Threat Mitigation Triggered. Type: [{}], Reason: [{}]",
                threat_type, reason
            )));
        }

        // 🔄 真正的滑动窗口维持：防止大流长文本导致内存膨胀，同时保留末尾 500 个字符保证跨 Chunk 语义连续
        let char_count = self.buffer.chars().count();
        if char_count > 1000 {
            let drain_amount = char_count - 500;
            if let Some((byte_idx, _)) = self.buffer.char_indices().nth(drain_amount) {
                self.buffer.drain(0..byte_idx);
            }
        }
        Ok(())
    }

    /// 流结束时清洗残留缓冲区
    pub fn flush(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.blocked {
            return Err(PyIOError::new_err("UnexpectedEof: Link already terminated."));
        }
        if self.buffer.trim().is_empty() {
            return Ok(());
        }

        let guard = self.rules.read().unwrap();
        let result = guard.check_text(py, &self.buffer)?;
        let is_blocked: bool = result.get_item("blocked")?.unwrap().extract()?;
        if is_blocked {
            self.blocked = true;
            let threat_type: String = result.get_item("threat_type")?.unwrap().extract()?;
            return Err(PyIOError::new_err(format!("UnexpectedEof: Flush Isolation. Type: [{}]", threat_type)));
        }
        self.buffer.clear();
        Ok(())
    }

    #[getter]
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }
}

#[pymodule]
fn llm_guard_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRuleEngine>()?;
    m.add_class::<PyStreamGuard>()?;
    Ok(())
}