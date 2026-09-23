/**
 * =============================================================================
 * techniqueLexicon.js — 通用技战术词表与「全文多命中」抽取
 * =============================================================================
 */

/** 通用关键词 → 技术（中英安全运营/分析报告常用表述） */
const KEYWORD_RULES = [
  // --- 初始访问 / 利用 ---
  { terms: ['sql injection', 'sql注入', 'sql 注入', 'sqli', 'union select', '数据库注入', '延时注入'], primary: 'T1190', secondary: ['T1059'], confidence: 0.91 },
  { terms: ['远程命令执行', '远程代码执行', '命令执行漏洞', 'rce'], primary: 'T1190', secondary: ['T1059'], confidence: 0.9 },
  { terms: ['路径遍历', '目录遍历', 'path traversal', '../'], primary: 'T1190', secondary: ['T1222'], tactics: ['TA0001', 'TA0005'], confidence: 0.9 },
  { terms: ['缓冲区溢出', '缓存溢出', '堆溢出', '栈溢出', 'overflow'], primary: 'T1190', secondary: ['T1203'], confidence: 0.87 },
  { terms: ['phishing', '钓鱼', 'spearphish', '仿冒邮件', '鱼叉'], primary: 'T1566', secondary: ['T1204'], confidence: 0.9 },
  { terms: ['面向公众', '公开应用', 'public-facing', 'web服务器进行攻击', '拿下了web'], primary: 'T1190', secondary: [], confidence: 0.8 },

  // --- 侦察 / 目标研究 ---
  { terms: ['研究目标', '目标研究', '选定目标', '高价值目标'], primary: 'T1590', secondary: ['T1589'], confidence: 0.84 },
  { terms: ['收集受害者', '受害者网络', '网络信息收集', 'gather victim network'], primary: 'T1590', secondary: [], confidence: 0.86 },
  { terms: ['身份信息', '组织架构调研', '关键人员', 'gather victim identity'], primary: 'T1589', secondary: [], confidence: 0.84 },
  { terms: ['whois', 'osint', '信息收集', '主动扫描', '侦察'], primary: 'T1595', secondary: ['T1589'], confidence: 0.8 },
  { terms: ['主要针对', '针对性研究', '特定行业', '身份信息', '组织架构调研'], primary: 'T1589', secondary: [], confidence: 0.8 },
  { terms: ['主要针对', '针对性研究', '特定行业'], primary: 'T1590', secondary: ['T1589'], confidence: 0.78 },

  // --- 发现 / 扫描 ---
  { terms: ['nmap', '端口扫描', 'port scan', 'masscan', '网络扫描'], primary: 'T1046', secondary: ['T1595'], confidence: 0.88 },
  { terms: ['内网扫描', '对内网', '服务器或pc进行扫描', '主机扫描', '服务发现'], primary: 'T1046', secondary: ['T1018'], confidence: 0.87 },
  { terms: ['帐户枚举', '账户枚举', '账号枚举', '用户枚举'], primary: 'T1087', secondary: ['T1018'], confidence: 0.88 },

  // --- 横向移动 / 远程服务 ---
  { terms: ['lateral', '横向移动', 'psexec', 'wmi lateral', '跳板', '作为跳板'], primary: 'T1021', secondary: ['T1210'], confidence: 0.88 },
  { terms: ['rdp', '远程桌面', '3389', '远程服务'], primary: 'T1021', secondary: ['T1133'], confidence: 0.82 },
  { terms: ['pass the hash', 'pth', 'ntlm relay'], primary: 'T1550', secondary: ['T1021'], confidence: 0.91 },

  // --- 凭证 ---
  { terms: ['弱口令', '口令猜测', '弱密码', '默认口令'], primary: 'T1110', secondary: ['T1552'], confidence: 0.88 },
  { terms: ['弱口令', '未保护凭证', '明文密码', '配置文件密码', 'unsecured credentials'], primary: 'T1552', secondary: [], confidence: 0.84 },
  { terms: ['bruteforce', '暴力破解', 'password spray', '密码喷洒'], primary: 'T1110', secondary: ['T1078'], confidence: 0.86 },
  { terms: ['mimikatz', 'lsass', '凭证转储', 'credential dump'], primary: 'T1003', secondary: [], confidence: 0.93 },

  // --- 执行 / 持久化 / 工具投递 ---
  { terms: ['powershell', 'pwsh', '-enc ', 'encodedcommand', '命令解释器', '脚本执行'], primary: 'T1059', secondary: ['T1106'], confidence: 0.86 },
  { terms: ['webshell', 'chopper', 'godzilla', '蚁剑'], primary: 'T1505', secondary: ['T1190'], confidence: 0.89 },
  { terms: ['植入恶意', '恶意代码', '投放木马', 'ingress tool', '工具传输', '传上远控'], primary: 'T1105', secondary: [], confidence: 0.86 },
  { terms: ['远端控制', '远程控制工具', '远控软件', ' remote access trojan'], primary: 'T1219', secondary: ['T1105'], confidence: 0.87 },
  { terms: [/\brat\b/i, 'rat工具', '安装远控'], primary: 'T1219', secondary: ['T1105', 'T1059'], confidence: 0.88 },
  { terms: ['创建服务', '系统服务', '修改系统进程', '注册为服务'], primary: 'T1543', secondary: [], confidence: 0.82 },
  { terms: ['schtasks', '计划任务', 'cron', 'startup folder', '开机启动'], primary: 'T1053', secondary: ['T1547'], confidence: 0.86 },
  { terms: ['process hollowing', 'dll注入', 'process injection', '进程注入'], primary: 'T1055', secondary: [], confidence: 0.9 },

  // --- C2 / 隧道 / 代理 ---
  { terms: ['c2', 'beacon', 'cobalt strike', '命令与控制', '回连'], primary: 'T1071', secondary: ['T1573'], confidence: 0.86 },
  { terms: ['非标准端口', 'non-standard port', '非常用端口'], primary: 'T1571', secondary: [], confidence: 0.84 },
  { terms: ['非应用层协议', 'non-application layer', '自定义协议'], primary: 'T1095', secondary: [], confidence: 0.82 },
  { terms: ['应用层协议', 'http隧道', 'https回连', '伪装成http'], primary: 'T1071', secondary: [], confidence: 0.83 },
  { terms: ['虚拟隧道', '协议隧道', 'dns tunnel', 'dns隧道'], primary: 'T1572', secondary: ['T1090'], confidence: 0.85 },
  { terms: ['直连通道', '直连的通道', '建立起直连', '直连', '绕过代理出站'], primary: 'T1090', secondary: ['T1071'], confidence: 0.84 },
  { terms: ['直连通道', '直连的通道', '建立起直连', 'c2通道'], primary: 'T1071', secondary: [], confidence: 0.82 },
  { terms: ['代理服务器', 'proxy chain', 'socks代理'], primary: 'T1090', secondary: [], confidence: 0.82 },

  // --- 防御规避 ---
  { terms: ['disable defender', '关闭defender', 'tamper protection', '削弱防御'], primary: 'T1562', secondary: ['T1070'], confidence: 0.9 },
  { terms: ['禁用代理', '关闭代理', '代理设置', 'ie代理', '修改代理'], primary: 'T1562', secondary: [], confidence: 0.86 },
  { terms: ['clear log', '清除日志', 'wevtutil', '指标清除', '清除痕迹'], primary: 'T1070', secondary: ['T1562'], confidence: 0.87 },
  { terms: ['uac bypass', 'uac绕过', 'cmstp'], primary: 'T1548', secondary: ['T1055'], confidence: 0.88 },

  // --- 收集 / 渗出 ---
  { terms: ['screen capture', '截屏', 'screenshot'], primary: 'T1113', secondary: [], confidence: 0.85 },
  { terms: ['本地文件', '来自本地系统', '收集文档', '会议记录', '机敏文件', '敏感文件'], primary: 'T1005', secondary: [], confidence: 0.84 },
  { terms: ['打包压缩', '归档', 'zip打包', 'archive collected'], primary: 'T1560', secondary: [], confidence: 0.82 },
  { terms: ['大量文件', '传回', '回传数据', '卷货', '数据窃取'], primary: 'T1041', secondary: ['T1005'], confidence: 0.86 },
  { terms: ['exfil', '外泄', '渗出', '数据外传', 'exfiltration over c2'], primary: 'T1041', secondary: ['T1048'], confidence: 0.87 },
  { terms: ['dns tunnel', '备用通道渗出'], primary: 'T1048', secondary: ['T1071'], confidence: 0.85 },

  // --- 影响 / 其他 IDS ---
  { terms: ['ransomware', '勒索', '.encrypted', 'wannacry'], primary: 'T1485', secondary: ['T1489'], confidence: 0.92 },
  { terms: ['信息泄露', '信息泄漏', 'phpinfo'], primary: 'T1592', secondary: ['T1082'], confidence: 0.82 },
  { terms: ['xmltools', 'xxe'], primary: 'T1190', secondary: [], confidence: 0.86 }
];

function termToSearchable(term) {
  if (term instanceof RegExp) return { type: 're', re: term };
  return { type: 'str', value: String(term).toLowerCase() };
}

function findTermIndex(hayLower, hayOrig, term) {
  const t = termToSearchable(term);
  if (t.type === 're') {
    const m = t.re.exec(hayOrig);
    if (!m) {
      // reset lastIndex for global regex safety
      t.re.lastIndex = 0;
      const m2 = hayOrig.match(t.re);
      if (!m2) return -1;
      return hayOrig.search(t.re);
    }
    const idx = m.index;
    t.re.lastIndex = 0;
    return idx;
  }
  return hayLower.indexOf(t.value);
}

function snippetAround(text, index, len) {
  if (!text) return '';
  const start = Math.max(0, index - 36);
  const end = Math.min(text.length, index + (len || 8) + 72);
  let snip = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) snip = `…${snip}`;
  if (end < text.length) snip = `${snip}…`;
  return snip;
}

/**
 * 词表多命中：同一技术只保留最早、置信度更高者
 */
function findKeywordHits(text) {
  const orig = String(text || '');
  if (!orig) return [];
  const lower = orig.toLowerCase();
  const byTech = new Map();

  for (const rule of KEYWORD_RULES) {
    let bestIdx = -1;
    let bestLen = 0;
    for (const term of rule.terms) {
      const idx = findTermIndex(lower, orig, term);
      if (idx >= 0 && (bestIdx < 0 || idx < bestIdx)) {
        bestIdx = idx;
        bestLen = term instanceof RegExp ? (orig.slice(idx).match(term) || [''])[0].length : String(term).length;
      }
    }
    if (bestIdx < 0) continue;

    const hit = {
      techId: rule.primary,
      secondary: rule.secondary || [],
      tactics: rule.tactics || [],
      confidence: rule.confidence,
      index: bestIdx,
      snippet: snippetAround(orig, bestIdx, bestLen),
      source: 'lexicon'
    };
    const prev = byTech.get(hit.techId);
    if (!prev || hit.index < prev.index || (hit.index === prev.index && hit.confidence > prev.confidence)) {
      byTech.set(hit.techId, hit);
    }
  }

  return [...byTech.values()].sort((a, b) => a.index - b.index || b.confidence - a.confidence);
}

/**
 * ATTCK 语料名命中（技术中文名等），置信度略低于词表
 */
function findCorpusHits(text, attck) {
  const orig = String(text || '');
  if (!orig || !attck) return [];
  const lower = orig.toLowerCase();
  const byTech = new Map();

  for (const kw of attck.keywords || []) {
    for (const term of kw.terms || []) {
      if (!term) continue;
      const t = String(term);
      // 过短英文词（如 web）易误伤叙述正文，语料侧提高门槛
      const isAscii = /^[\x00-\x7f]+$/.test(t);
      if (isAscii && t.length < 4) continue;
      if (!isAscii && t.length < 2) continue;
      const idx = lower.indexOf(t.toLowerCase());
      if (idx < 0) continue;
      const confidence = Number((0.72 + Math.min(0.08, t.length * 0.004)).toFixed(2));
      const hit = {
        techId: kw.techniqueId,
        secondary: [],
        tactics: kw.tacticId ? [kw.tacticId] : [],
        confidence,
        index: idx,
        snippet: snippetAround(orig, idx, t.length),
        source: 'corpus'
      };
      const prev = byTech.get(hit.techId);
      if (!prev || hit.confidence > prev.confidence || (hit.confidence === prev.confidence && hit.index < prev.index)) {
        byTech.set(hit.techId, hit);
      }
      break;
    }
  }
  return [...byTech.values()];
}

/**
 * 合并词表 + 语料；同技术优先词表；可选把 secondary 展开为邻近弱命中
 */
function findAllTechniqueHits(text, attck, options = {}) {
  const { expandSecondary = true } = options;
  const primaryHits = findKeywordHits(text);
  const corpus = findCorpusHits(text, attck);
  const byTech = new Map();

  for (const h of primaryHits) byTech.set(h.techId, h);
  for (const h of corpus) {
    if (!byTech.has(h.techId)) byTech.set(h.techId, h);
  }

  if (expandSecondary) {
    for (const h of primaryHits) {
      for (const sec of h.secondary || []) {
        if (byTech.has(sec)) continue;
        // 仅当正文里也能找到与 secondary 相关的弱线索时才展开？——过严。
        // 泛化策略：secondary 作为「同句伴随技术」弱命中，index 微调，置信度打折。
        byTech.set(sec, {
          techId: sec,
          secondary: [],
          tactics: h.tactics || [],
          confidence: Math.max(0.7, Number((h.confidence * 0.9).toFixed(2))),
          index: h.index + 1,
          snippet: h.snippet,
          source: 'lexicon-secondary'
        });
      }
    }
  }

  return [...byTech.values()].sort((a, b) => a.index - b.index || b.confidence - a.confidence);
}

/** 单条告警：取置信度最高的一条（兼容原 heuristicMap） */
function findBestTechniqueHit(text, attck) {
  const hits = findAllTechniqueHits(text, attck, { expandSecondary: false });
  if (!hits.length) return null;
  return hits.reduce((a, b) => (b.confidence > a.confidence ? b : a));
}

module.exports = {
  KEYWORD_RULES,
  findKeywordHits,
  findCorpusHits,
  findAllTechniqueHits,
  findBestTechniqueHit
};
