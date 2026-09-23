const fs = require('fs');
const path = require('path');

/**
 * Kill Chain 战术顺序（与 MITRE ATT&CK Enterprise 对齐）
 * order 越小越靠攻击早期；链路分组、覆盖矩阵都按此排序。
 */
const KILL_CHAIN_ORDER = [
  { id: 'TA0043', name: '侦察', nameEn: 'Reconnaissance', order: 1 },
  { id: 'TA0042', name: '资源开发', nameEn: 'Resource Development', order: 2 },
  { id: 'TA0001', name: '初始访问', nameEn: 'Initial Access', order: 3 },
  { id: 'TA0002', name: '执行', nameEn: 'Execution', order: 4 },
  { id: 'TA0003', name: '持久化', nameEn: 'Persistence', order: 5 },
  { id: 'TA0004', name: '权限提升', nameEn: 'Privilege Escalation', order: 6 },
  { id: 'TA0005', name: '防御规避', nameEn: 'Defense Evasion', order: 7 },
  { id: 'TA0006', name: '凭证访问', nameEn: 'Credential Access', order: 8 },
  { id: 'TA0007', name: '发现', nameEn: 'Discovery', order: 9 },
  { id: 'TA0008', name: '横向移动', nameEn: 'Lateral Movement', order: 10 },
  { id: 'TA0009', name: '数据收集', nameEn: 'Collection', order: 11 },
  { id: 'TA0011', name: '命令与控制', nameEn: 'Command and Control', order: 12 },
  { id: 'TA0010', name: '渗出', nameEn: 'Exfiltration', order: 13 },
  { id: 'TA0040', name: '影响', nameEn: 'Impact', order: 14 }
];

/**
 * 从某战术下的长文本中，切分并解析每一条“攻击主技术”
 * @param {string} text  ATTCK.json 中该战术的 text 字段
 * @param {string} tacticId 如 TA0001
 * @returns {Array<{id,name,tacticId,subTechniques}>}
 */
function parseTechniqueBlock(text, tacticId) {
  const techniques = [];
  // 按 ①②③… 或 “1、攻击主技术” 做超前分割（保留分隔符所在段）
  const parts = text.split(/(?=[①②③④⑤⑥⑦⑧⑨⑩⑪⑫]|[0-9]+[、．.]\s*攻击主技术)/);

  for (const part of parts) {
    if (!part || part.trim().length < 10) continue;

    // 抽取主技术编号 / 名称
    const techMatch = part.match(/攻击主技术的编号[：:]\s*(T\d{4}(?:\.\d{3})?)/);
    const nameMatch = part.match(/攻击主技术的名称[：:]\s*([^，,（(]+)/);
    if (!techMatch) continue;

    const techniqueId = techMatch[1];
    const techniqueName = nameMatch ? nameMatch[1].trim() : techniqueId;

    // 抽取子技术：T1595.001（扫描IP块）
    const subTechniques = [];
    const subRegex = /(T\d{4}\.\d{3})\s*[（(]([^）)]+)[）)]/g;
    let m;
    while ((m = subRegex.exec(part)) !== null) {
      subTechniques.push({ id: m[1], name: m[2].trim() });
    }

    techniques.push({
      id: techniqueId,
      name: techniqueName,
      tacticId,
      subTechniques
    });
  }
  return techniques;
}

/**
 * 加载并解析整个 ATTCK.json
 * @param {string} jsonPath 文件路径
 */
function loadAttckData(jsonPath) {
  const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const tactics = [...KILL_CHAIN_ORDER];
  const techniques = [];
  const techniqueById = {};
  const keywords = [];

  for (const item of raw) {
    const title = item.title || '';
    const text = item.text || '';

    // 仅处理“技术清单”类条目（含 TA 编号且正文含攻击主技术）
    let tacticId = null;
    const m1 = title.match(/TA\d{4}/);
    const m2 = title.match(/攻击战术编号为\s*(TA\d{4})/);
    if (m2) tacticId = m2[1];
    else if (m1 && /包含的攻击技术|攻击战术编号为/.test(title)) tacticId = m1[0];

    if (tacticId && text.includes('攻击主技术')) {
      const techs = parseTechniqueBlock(text, tacticId);
      for (const t of techs) {
        techniques.push(t);
        techniqueById[t.id] = t;

        // 子技术也建索引，便于以后按 Txxxx.yyy 反查战术
        for (const sub of t.subTechniques) {
          techniqueById[sub.id] = {
            id: sub.id,
            name: sub.name,
            tacticId,
            parentId: t.id,
            subTechniques: []
          };
        }

        // 关键词索引：给启发式映射用
        keywords.push({
          techniqueId: t.id,
          tacticId,
          terms: extractKeywords(t.name)
        });
      }
    }
  }

  return {
    tactics,
    techniques,
    techniqueById,
    keywords,
    killChainOrder: KILL_CHAIN_ORDER
  };
}

/** 从技术名称提取中英文关键词（去括号、拆英文单词） */
function extractKeywords(name) {
  const terms = [];
  const cn = name.replace(/[（(].*?[）)]/g, '').trim();
  if (cn) terms.push(cn.toLowerCase());
  const en = name.match(/[A-Za-z][A-Za-z0-9\s/-]+/);
  if (en) {
    en[0]
      .toLowerCase()
      .split(/[\s/-]+/)
      .filter((w) => w.length > 2)
      .forEach((w) => terms.push(w));
  }
  return [...new Set(terms)];
}

/**
 * 按常见部署路径自动寻找 ATTCK.json
 * 本机仓库：../data/ATTCK.json；云服务器：/home/www/...
 */
function getDefaultAttckPath() {
  const candidates = [
    path.join(__dirname, '../../data/ATTCK.json'),
    path.join(__dirname, '../data/ATTCK.json'),
    '/home/www/backend/data/ATTCK.json',
    '/home/www/data/ATTCK.json',
    path.join(process.cwd(), 'data/ATTCK.json'),
    path.join(process.cwd(), '../data/ATTCK.json')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

module.exports = {
  KILL_CHAIN_ORDER,
  loadAttckData,
  getDefaultAttckPath,
  extractKeywords
};
