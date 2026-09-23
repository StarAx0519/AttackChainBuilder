/**
 * =============================================================================
 * mapper.js — 威胁告警 → ATT&CK 技战术自动映射
 * =============================================================================
 *
 * 【整体策略】
 *   1) 规则映射（优先）：攻击类型字段规范化后查 ATTACK_TYPE_RULES
 *      输出形态：{ primary:"Txxxx", secondary:["Txxxx"], confidence:0.xx }
 *   2) 启发式映射：在 title/description 等文本中匹配关键词 / ATTCK 语料名
 *   3) 仍无法匹配时给低置信度默认技术，避免链路断档
 *
 * 【质量评估】
 *   ≥0.90 excellent | ≥0.80 good | ≥0.70 fair | <0.70 poor
 *
 * 【enrichMapping】
 *   把纯规则结果补全为：技术名、战术 ID/中英文名、KillChain 序号、质量等级
 * =============================================================================
 */

/** 置信度 → 质量等级对照表（从高到低匹配） */
const QUALITY_LEVELS = [
  { min: 0.9, level: 'excellent', label: '高置信度映射' },
  { min: 0.8, level: 'good', label: '可靠映射' },
  { min: 0.7, level: 'fair', label: '需人工复核' },
  { min: 0, level: 'poor', label: '建议补充分析' }
];

/** 映射方式英文码 → 界面中文（内部仍存英文码便于筛选/兼容） */
const METHOD_LABELS = {
  explicit: '文中标明',
  rule: '类型规则',
  heuristic: '关键词启发',
  fallback: '默认设定'
};

/** 攻击类型 → { primary, secondary, confidence } */
const ATTACK_TYPE_RULES = {
  sql_injection: { primary: 'T1190', secondary: ['T1059', 'T1505'], confidence: 0.92 },
  sqli: { primary: 'T1190', secondary: ['T1059'], confidence: 0.91 },
  xss: { primary: 'T1059', secondary: ['T1185', 'T1566'], confidence: 0.85 },
  phishing: { primary: 'T1566', secondary: ['T1204', 'T1598'], confidence: 0.94 },
  spearphishing: { primary: 'T1566', secondary: ['T1204'], confidence: 0.93 },
  brute_force: { primary: 'T1078', secondary: ['T1110', 'T1133'], confidence: 0.88 },
  password_spray: { primary: 'T1078', secondary: ['T1110'], confidence: 0.86 },
  ransomware: { primary: 'T1485', secondary: ['T1489', 'T1486'], confidence: 0.95 },
  malware: { primary: 'T1204', secondary: ['T1059', 'T1547'], confidence: 0.82 },
  trojan: { primary: 'T1204', secondary: ['T1059', 'T1071'], confidence: 0.84 },
  rat: { primary: 'T1071', secondary: ['T1059', 'T1547'], confidence: 0.87 },
  c2: { primary: 'T1071', secondary: ['T1573'], confidence: 0.9 },
  command_and_control: { primary: 'T1071', secondary: ['T1573'], confidence: 0.9 },
  port_scan: { primary: 'T1046', secondary: ['T1595'], confidence: 0.91 },
  network_scan: { primary: 'T1046', secondary: ['T1595', 'T1018'], confidence: 0.89 },
  vulnerability_scan: { primary: 'T1595', secondary: ['T1046'], confidence: 0.9 },
  lateral_movement: { primary: 'T1021', secondary: ['T1210', 'T1550'], confidence: 0.88 },
  pass_the_hash: { primary: 'T1550', secondary: ['T1021'], confidence: 0.93 },
  privilege_escalation: { primary: 'T1055', secondary: ['T1548', 'T1134'], confidence: 0.86 },
  process_injection: { primary: 'T1055', secondary: ['T1059'], confidence: 0.92 },
  credential_dump: { primary: 'T1003', secondary: ['T1056', 'T1550'], confidence: 0.94 },
  mimikatz: { primary: 'T1003', secondary: ['T1056'], confidence: 0.96 },
  defense_evasion: { primary: 'T1562', secondary: ['T1070', 'T1553'], confidence: 0.85 },
  disable_security: { primary: 'T1562', secondary: ['T1070'], confidence: 0.9 },
  persistence: { primary: 'T1547', secondary: ['T1053', 'T1574'], confidence: 0.87 },
  scheduled_task: { primary: 'T1053', secondary: ['T1547'], confidence: 0.91 },
  data_exfiltration: { primary: 'T1048', secondary: ['T1567'], confidence: 0.9 },
  dns_tunnel: { primary: 'T1048', secondary: ['T1071'], confidence: 0.92 },
  discovery: { primary: 'T1046', secondary: ['T1087', 'T1018'], confidence: 0.83 },
  account_discovery: { primary: 'T1087', secondary: ['T1018'], confidence: 0.88 },
  collection: { primary: 'T1113', secondary: ['T1530'], confidence: 0.8 },
  screen_capture: { primary: 'T1113', secondary: [], confidence: 0.9 },
  web_shell: { primary: 'T1505', secondary: ['T1190', 'T1059'], confidence: 0.91 },
  rce: { primary: 'T1190', secondary: ['T1059', 'T1106'], confidence: 0.89 },
  remote_code_execution: { primary: 'T1190', secondary: ['T1059'], confidence: 0.89 },
  ddos: { primary: 'T1489', secondary: ['T1498'], confidence: 0.84 },
  dos: { primary: 'T1489', secondary: [], confidence: 0.82 },
  keylogger: { primary: 'T1056', secondary: ['T1003'], confidence: 0.9 },
  vpn_exploit: { primary: 'T1133', secondary: ['T1190'], confidence: 0.88 },
  usb_malware: { primary: 'T1200', secondary: ['T1204'], confidence: 0.87 },
  powershell: { primary: 'T1059', secondary: ['T1106'], confidence: 0.9 },
  wmi: { primary: 'T1047', secondary: ['T1059'], confidence: 0.91 },
  rdp: { primary: 'T1021', secondary: ['T1133'], confidence: 0.88 },
  smb: { primary: 'T1210', secondary: ['T1021'], confidence: 0.87 },
  recon: { primary: 'T1595', secondary: ['T1589', 'T1590'], confidence: 0.85 },
  reconnaissance: { primary: 'T1595', secondary: ['T1589'], confidence: 0.85 },
  domain_spoof: { primary: 'T1583', secondary: ['T1566'], confidence: 0.84 },
  impact: { primary: 'T1485', secondary: ['T1489'], confidence: 0.82 },
  data_destruction: { primary: 'T1485', secondary: ['T1489'], confidence: 0.91 },
  info_leak: { primary: 'T1592', secondary: ['T1082'], confidence: 0.86 },
  // 路径遍历：利用公开应用进入 + 文件/目录权限相关规避（多战术多技术）
  path_traversal: {
    primary: 'T1190',
    secondary: ['T1222'],
    tactics: ['TA0001', 'TA0005'],
    confidence: 0.9
  },
  buffer_overflow: { primary: 'T1190', secondary: ['T1203'], confidence: 0.87 }
};

/** 中文/常见别名 → 规则键 */
const TYPE_ALIASES = {
  'sql注入': 'sql_injection',
  'sql 注入': 'sql_injection',
  sql注入攻击: 'sql_injection',
  '跨站脚本': 'xss',
  钓鱼: 'phishing',
  钓鱼邮件: 'phishing',
  网络钓鱼: 'phishing',
  暴力破解: 'brute_force',
  撞库: 'brute_force',
  勒索软件: 'ransomware',
  勒索: 'ransomware',
  木马: 'trojan',
  恶意软件: 'malware',
  远控: 'rat',
  远程控制: 'rat',
  端口扫描: 'port_scan',
  网络扫描: 'network_scan',
  漏洞扫描: 'vulnerability_scan',
  横向移动: 'lateral_movement',
  权限提升: 'privilege_escalation',
  进程注入: 'process_injection',
  凭证窃取: 'credential_dump',
  凭据转储: 'credential_dump',
  防御规避: 'defense_evasion',
  关闭杀软: 'disable_security',
  持久化: 'persistence',
  计划任务: 'scheduled_task',
  数据外泄: 'data_exfiltration',
  数据渗出: 'data_exfiltration',
  dns隧道: 'dns_tunnel',
  发现: 'discovery',
  账户枚举: 'account_discovery',
  截屏: 'screen_capture',
  webshell: 'web_shell',
  'web shell': 'web_shell',
  远程代码执行: 'rce',
  拒绝服务: 'ddos',
  键盘记录: 'keylogger',
  侦察: 'reconnaissance',
  powershell执行: 'powershell',
  rdp劫持: 'rdp',
  数据破坏: 'data_destruction',
  远程命令执行: 'rce',
  远程代码执行: 'rce',
  延时注入: 'sql_injection',
  路径遍历: 'path_traversal',
  帐户枚举: 'account_discovery',
  账户枚举: 'account_discovery',
  信息泄露: 'info_leak',
  信息泄漏: 'info_leak',
  缓冲区溢出: 'buffer_overflow',
  缓存溢出: 'buffer_overflow'
};

const { findBestTechniqueHit, KEYWORD_RULES } = require('./techniqueLexicon');

/** @deprecated 兼容导出；实际词表在 techniqueLexicon.js */
const HEURISTIC_KEYWORDS = KEYWORD_RULES;

/**
 * 把各种写法的攻击类型归一成规则表的 key
 * 例："SQL注入" / "sql-injection" / "SQL Injection" → sql_injection
 */
function normalizeAttackType(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toLowerCase().replace(/[\s_-]+/g, '_');
  if (ATTACK_TYPE_RULES[s]) return s;
  const spaced = String(raw).trim().toLowerCase();
  if (TYPE_ALIASES[spaced]) return TYPE_ALIASES[spaced];
  if (TYPE_ALIASES[String(raw).trim()]) return TYPE_ALIASES[String(raw).trim()];
  // 模糊包含：告警类型字段里夹杂中文描述时也能命中
  for (const [alias, key] of Object.entries(TYPE_ALIASES)) {
    if (spaced.includes(alias) || String(raw).includes(alias)) return key;
  }
  for (const key of Object.keys(ATTACK_TYPE_RULES)) {
    if (spaced.includes(key.replace(/_/g, ' ')) || spaced.includes(key)) return key;
  }
  return null;
}

/** 按置信度返回质量等级与中文说明 */
function getQuality(confidence) {
  for (const q of QUALITY_LEVELS) {
    if (confidence >= q.min) {
      return { level: q.level, label: q.label };
    }
  }
  return { level: 'poor', label: '建议补充分析' };
}

/** 语料未收录时的技术→战术兜底（Enterprise 常见编号，含子技术主编号） */
const TECHNIQUE_TACTIC_FALLBACK = {
  T1505: 'TA0003',
  T1110: 'TA0006',
  T1486: 'TA0040',
  T1498: 'TA0040',
  T1185: 'TA0005',
  T1105: 'TA0011',
  T1566: 'TA0001',
  T1055: 'TA0004',
  T1021: 'TA0008',
  T1190: 'TA0001',
  T1222: 'TA0005',
  T1547: 'TA0003',
  T1053: 'TA0003'
};

/** 常见子技术中文别名（叙述文案匹配用） */
const TECHNIQUE_NAME_HINTS = {
  T1190: '利用公开应用 / 远程代码执行',
  'T1566.001': '鱼叉式钓鱼邮件附件',
  T1566: '网络钓鱼',
  'T1055.012': '进程镂空',
  T1055: '进程注入',
  'T1021.002': 'SMB 远程服务',
  T1021: '远程服务',
  T1486: '勒索软件数据加密',
  T1485: '数据破坏',
  T1222: '文件和目录权限修改',
  T1087: '账户发现',
  T1592: '收集受害者主机信息',
  T1059: '命令和脚本解释器'
};

/**
 * 把规则命中结果 enrich 成前端/链路可用的完整映射对象
 * 支持多技术（primary + secondary）与多战术（tactics[] 或由各技术推导）
 * @param {{primary,secondary,confidence,tactics?}} mapping
 * @param {object} attck loadAttckData 的返回值
 * @param {'rule'|'heuristic'|'fallback'|'explicit'} method
 */
function enrichMapping(mapping, attck, method) {
  const primary = mapping.primary || null;
  const secondary = [...new Set((mapping.secondary || []).filter((t) => t && t !== primary))];
  const allTechIds = primary ? [primary, ...secondary] : [...secondary];

  const techniqueDetails = allTechIds.map((tid) => {
    const meta = resolveTechTactic(tid, attck, null);
    return {
      id: tid,
      name: meta.techniqueName,
      tacticId: meta.tacticId,
      tacticName: meta.tacticName
    };
  });

  // 显式多战术优先；否则汇总各技术默认战术
  let tacticIds = [];
  if (Array.isArray(mapping.tactics) && mapping.tactics.length) {
    tacticIds = [...new Set(mapping.tactics)];
  } else {
    tacticIds = [
      ...new Set(techniqueDetails.map((t) => t.tacticId).filter(Boolean))
    ];
  }

  const tacticDetails = tacticIds.map((ta) => {
    const t = attck.killChainOrder.find((x) => x.id === ta);
    return {
      id: ta,
      name: t ? t.name : ta,
      nameEn: t ? t.nameEn : ta,
      order: t ? t.order : 99
    };
  });

  const primaryTactic = tacticDetails[0] || null;
  const primaryTech = techniqueDetails[0] || null;
  const quality = getQuality(mapping.confidence);

  return {
    primary: primary || (primaryTech ? primaryTech.id : null),
    secondary,
    techniques: techniqueDetails,
    tactics: tacticDetails,
    tacticIds,
    confidence: mapping.confidence,
    quality: quality.level,
    qualityLabel: quality.label,
    method,
    methodLabel: METHOD_LABELS[method] || method,
    techniqueName: primaryTech ? primaryTech.name : primary || null,
    // 兼容旧前端：主战术仍放在 tacticId/tacticName
    tacticId: primaryTactic ? primaryTactic.id : null,
    tacticName: primaryTactic ? primaryTactic.name : null,
    tacticNameEn: primaryTactic ? primaryTactic.nameEn : null,
    killChainOrder: primaryTactic ? primaryTactic.order : 99
  };
}

/** 单技术 → 战术解析 */
function resolveTechTactic(techId, attck, tacticOverride) {
  const base = (techId || '').split('.')[0];
  const tech =
    attck.techniqueById[techId] || attck.techniqueById[base] || null;
  const tacticId =
    tacticOverride ||
    (tech && tech.tacticId) ||
    TECHNIQUE_TACTIC_FALLBACK[base] ||
    TECHNIQUE_TACTIC_FALLBACK[techId] ||
    null;
  const tactic = attck.killChainOrder.find((t) => t.id === tacticId) || null;
  return {
    techniqueName:
      (tech && tech.name) ||
      TECHNIQUE_NAME_HINTS[techId] ||
      TECHNIQUE_NAME_HINTS[base] ||
      techId,
    tacticId,
    tacticName: tactic ? tactic.name : null,
    tacticNameEn: tactic ? tactic.nameEn : null,
    killChainOrder: tactic ? tactic.order : 99
  };
}

function guessTacticFromTechnique(techId, attck) {
  return resolveTechTactic(techId, attck, null).tacticId;
}

/** 一级：基于攻击类型的确定性规则映射 */
function ruleMap(attackType, attck) {
  const key = normalizeAttackType(attackType);
  if (!key || !ATTACK_TYPE_RULES[key]) return null;
  const rule = ATTACK_TYPE_RULES[key];
  return enrichMapping({ ...rule }, attck, 'rule');
}

/**
 * 二级：启发式通用映射（词表 + ATTCK 语料，取最高置信度）
 */
function heuristicMap(text, attck) {
  if (!text) return null;
  const best = findBestTechniqueHit(text, attck);
  if (!best) return null;
  return enrichMapping(
    {
      primary: best.techId,
      secondary: best.secondary || [],
      tactics: best.tactics && best.tactics.length ? best.tactics : undefined,
      confidence: best.confidence
    },
    attck,
    'heuristic'
  );
}

const {
  parseEventTimeInfo,
  parseEventTimeFromText,
  extractExplicitTechniqueIds,
  isNarrativeCase,
  expandNarrativeAlert,
  resolveTechniqueMeta,
  resolveTacticOnlyMeta
} = require('./narrativeExpand');
const { normalizeAlertFields } = require('./alertNormalize');

/**
 * 入库前规范化：字段别名归一 → 叙述案例拆条 → 补时间/显式技术
 * @param {{expandNarrative?:boolean}} [opts]
 */
function normalizeAlerts(alerts, attck, opts = {}) {
  const expandNarrative = opts.expandNarrative !== false;
  const out = [];
  for (const raw of alerts || []) {
    const alert = normalizeAlertFields({
      ...raw,
      description: raw.description || raw.desc || raw.text || raw.message || null
    });

    if (expandNarrative && isNarrativeCase(alert)) {
      out.push(...expandNarrativeAlert(alert, attck));
      continue;
    }

    if (!alert.timestamp && !alert.time) {
      const info = parseEventTimeInfo(
        [alert.title, alert.description, alert.text, alert.message, alert.desc]
          .filter(Boolean)
          .join(' ')
      );
      if (info.iso) {
        alert.timestamp = info.iso;
        alert.timePrecision = info.precision;
        alert.timeDisplay = info.display;
      }
    }
    if (!alert.explicitTechniqueId) {
      const ids = extractExplicitTechniqueIds(
        [alert.description, alert.desc, alert.text, alert.title, alert.message]
          .filter(Boolean)
          .join(' ')
      );
      if (ids.length === 1) alert.explicitTechniqueId = ids[0];
    }
    out.push(alert);
  }
  return out;
}

/**
 * 正文已写明 Txxxx / 或仅战术时，直接高置信度映射
 */
function explicitTechniqueMap(techId, attck, tacticOverride) {
  if (!techId && !tacticOverride) return null;
  if (!techId && tacticOverride) {
    return enrichMapping(
      {
        primary: null,
        secondary: [],
        tactics: [tacticOverride],
        confidence: 0.88
      },
      attck,
      'explicit'
    );
  }
  return enrichMapping(
    {
      primary: techId,
      secondary: techId.includes('.') ? [techId.split('.')[0]] : [],
      tactics: tacticOverride ? [tacticOverride] : undefined,
      confidence: 0.96
    },
    attck,
    'explicit'
  );
}

/**
 * 叙述散文经关键词/词表推断出的技术（文中并无 Txxxx），标为 heuristic
 */
function inferredTechniqueMap(techId, attck, tacticOverride, confidenceHint) {
  if (!techId) return null;
  const conf =
    typeof confidenceHint === 'number' && confidenceHint > 0
      ? Math.min(0.9, Math.max(0.55, confidenceHint))
      : 0.72;
  return enrichMapping(
    {
      primary: techId,
      secondary: techId.includes('.') ? [techId.split('.')[0]] : [],
      tactics: tacticOverride ? [tacticOverride] : undefined,
      confidence: conf
    },
    attck,
    'heuristic'
  );
}

/**
 * 对单条告警执行完整映射流水线
 * 兼容字段：attackType/type/alertType、title/name、description/text/message、timestamp/time 等
 * 优先：文中写明的 explicitTechniqueId → 叙述推断 inferredTechniqueId → 规则 → 启发 → 兜底
 * @param {{enableExplicit?:boolean,enableRule?:boolean,enableHeuristic?:boolean,enableFallback?:boolean}} [opts]
 */
function mapAlert(alert, attck, opts = {}) {
  const enableExplicit = opts.enableExplicit !== false;
  const enableRule = opts.enableRule !== false;
  const enableHeuristic = opts.enableHeuristic !== false;
  const enableFallback = opts.enableFallback !== false;

  // 再归一一次，防止未走 normalizeAlerts 的调用路径漏字段
  alert = require('./alertNormalize').normalizeAlertFields(alert);

  const attackType = alert.attackType || alert.type || alert.alertType || alert.category || '';
  const textBlob = [
    attackType,
    alert.title,
    alert.name,
    alert.description,
    alert.desc,
    alert.text,
    alert.message,
    alert.detail,
    alert.signature,
    alert.raw,
    alert.device,
    Array.isArray(alert.cve) ? alert.cve.join(' ') : alert.cve
  ]
    .filter(Boolean)
    .join(' ');

  let mapping = null;

  // 0a) 文中真实写出的 T/TA（或仅战术步骤）
  if (enableExplicit) {
    if (alert.tacticOnly || (!alert.explicitTechniqueId && !alert.inferredTechniqueId && alert.tacticOverride && !alert._fromProse)) {
      mapping = explicitTechniqueMap(null, attck, alert.tacticOverride);
    } else if (alert.explicitTechniqueId) {
      mapping = explicitTechniqueMap(
        alert.explicitTechniqueId,
        attck,
        alert.tacticOverride || null
      );
    }
  }
  // 0b) 无编号散文经词表推断（不得标成「文中标明」）
  if (!mapping && enableHeuristic && alert.inferredTechniqueId) {
    mapping = inferredTechniqueMap(
      alert.inferredTechniqueId,
      attck,
      alert.tacticOverride || null,
      alert.mappingConfidenceHint
    );
  }
  if (!mapping && enableHeuristic && alert._fromProse && alert.tacticOverride && !alert.inferredTechniqueId) {
    // 散文仅命中战术时，仍属启发而非「文中标明」
    mapping = enrichMapping(
      {
        primary: null,
        secondary: [],
        tactics: [alert.tacticOverride],
        confidence: alert.mappingConfidenceHint || 0.7
      },
      attck,
      'heuristic'
    );
  }
  if (!mapping && enableExplicit) {
    const ids = extractExplicitTechniqueIds(textBlob);
    if (ids.length === 1) {
      mapping = explicitTechniqueMap(ids[0], attck, alert.tacticOverride || null);
    }
  }

  // 1) 规则：优先用 attackType；否则用描述文本做类型归一再查规则
  if (!mapping && enableRule) {
    mapping = ruleMap(attackType, attck);
  }
  if (!mapping && enableRule && textBlob) {
    mapping = ruleMap(textBlob, attck);
  }
  if (!mapping && enableHeuristic) {
    mapping = heuristicMap(textBlob, attck);
  } else if (mapping && mapping.method === 'rule' && enableHeuristic) {
    const h = heuristicMap(textBlob, attck);
    if (h && h.primary && h.primary !== mapping.primary && !(mapping.secondary || []).includes(h.primary)) {
      mapping.secondary = [...new Set([...(mapping.secondary || []), h.primary])];
    }
  }

  if (!mapping && enableFallback) {
    mapping = enrichMapping(
      { primary: 'T1190', secondary: [], confidence: 0.55 },
      attck,
      'fallback'
    );
    mapping.techniqueName = '未明确匹配（默认初始访问启发式）';
  }
  if (!mapping) {
    mapping = enrichMapping(
      { primary: null, secondary: [], confidence: 0 },
      attck,
      'none'
    );
    mapping.techniqueName = '未映射';
  }

  const { normalizeTimestamp } = require('./alertNormalize');
  const ts =
    normalizeTimestamp(alert.timestamp) ||
    normalizeTimestamp(alert.time) ||
    normalizeTimestamp(alert.eventTime) ||
    normalizeTimestamp(alert.createdAt) ||
    parseEventTimeInfo(textBlob).iso ||
    null;

  const description =
    alert.description ||
    alert.desc ||
    alert.text ||
    alert.message ||
    alert.detail ||
    alert.signature ||
    alert.raw ||
    null;

  const timePrecision = alert.timePrecision || (ts ? 'exact' : 'unknown');
  const timeDisplay =
    alert.timeDisplay ||
    (ts ? new Date(ts).toISOString().replace('T', ' ').slice(0, 19) : null);

  return {
    alertId: alert.id || alert.alertId || alert._id || null,
    timestamp: ts,
    timePrecision,
    timeDisplay,
    stepIndex: alert.stepIndex || null,
    stepLabel: alert.stepLabel || null,
    attackType: attackType || mapping.techniqueName || 'unknown',
    title: alert.title || alert.name || description || attackType || '未命名告警',
    srcIp: alert.srcIp || alert.sourceIp || alert.src || null,
    dstIp: alert.dstIp || alert.destIp || alert.dst || null,
    host: alert.host || alert.hostname || null,
    destNodeId: alert.destNodeId || alert.dnode || null,
    srcNodeId: alert.srcNodeId || alert.snode || null,
    device: alert.device || null,
    description,
    severity: alert.severity || alert.level || 'medium',
    mapping,
    original: alert.original || alert
  };
}

/**
 * @param {{expandNarrative?:boolean,enableExplicit?:boolean,enableRule?:boolean,enableHeuristic?:boolean,enableFallback?:boolean}} [opts]
 */
function mapAlertsBatch(alerts, attck, opts = {}) {
  const normalized = normalizeAlerts(alerts, attck, opts);
  return normalized.map((a) => mapAlert(a, attck, opts));
}

module.exports = {
  ATTACK_TYPE_RULES,
  TYPE_ALIASES,
  QUALITY_LEVELS,
  METHOD_LABELS,
  normalizeAttackType,
  getQuality,
  enrichMapping,
  ruleMap,
  heuristicMap,
  mapAlert,
  mapAlertsBatch,
  normalizeAlerts,
  expandNarrativeAlert,
  extractExplicitTechniqueIds,
  parseEventTimeFromText
};
