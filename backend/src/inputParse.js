const { parseLooseAlertText, normalizeAlertList } = require('./alertNormalize');

function looksLikeXml(s) {
  return /^\s*</.test(s) && /<\/\w+>/.test(s);
}

function looksLikeCef(s) {
  return /CEF:\d+\|/i.test(s) || /^\s*CEF:/im.test(s);
}

function looksLikeLeef(s) {
  return /LEEF:\d+\.\d+\|/i.test(s);
}

function decodeXmlEntities(s) {
  return String(s || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/**
 * 极简 XML：抽取重复节点为对象（不依赖外部库，离线可用）
 */
function parseXmlAlerts(text) {
  const s = String(text || '');
  const tagCandidates = [
    'Alert',
    'alert',
    'Event',
    'event',
    'Record',
    'record',
    'Log',
    'log',
    'Incident',
    'item',
    'Item'
  ];
  let items = [];
  for (const tag of tagCandidates) {
    const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'gi');
    let m;
    const found = [];
    while ((m = re.exec(s)) !== null) {
      found.push(m[1]);
    }
    if (found.length) {
      items = found;
      break;
    }
  }
  if (!items.length) {
    // 单根：把一级子标签收成一条
    const inner = s.replace(/<\?xml[^>]*\?>/i, '').trim();
    const root = inner.match(/^<(\w+)[^>]*>([\s\S]*)<\/\1>$/);
    if (root) items = [root[2]];
  }

  const alerts = [];
  for (const block of items) {
    const obj = {};
    const fieldRe = /<(\w+)[^>]*>([^<]*)<\/\1>/g;
    let fm;
    while ((fm = fieldRe.exec(block)) !== null) {
      const key = fm[1];
      const val = decodeXmlEntities(fm[2]).trim();
      if (!val) continue;
      if (obj[key] == null) obj[key] = val;
      else if (Array.isArray(obj[key])) obj[key].push(val);
      else obj[key] = [obj[key], val];
    }
    // 属性也收一点
    const attrRe = /(\w+)="([^"]*)"/g;
    let am;
    while ((am = attrRe.exec(block)) !== null) {
      if (obj[am[1]] == null) obj[am[1]] = decodeXmlEntities(am[2]);
    }
    if (Object.keys(obj).length) alerts.push(obj);
  }
  return alerts;
}

function parseCefLine(line) {
  const idx = line.search(/CEF:\d+\|/i);
  if (idx < 0) return null;
  const body = line.slice(idx);
  const parts = body.split('|');
  if (parts.length < 8) return null;
  const ext = parts.slice(7).join('|');
  const obj = {
    cefVersion: parts[0].replace(/^CEF:/i, ''),
    deviceVendor: parts[1],
    deviceProduct: parts[2],
    deviceVersion: parts[3],
    signatureId: parts[4],
    name: parts[5],
    title: parts[5],
    severity: parts[6],
    attackType: parts[5],
    description: parts[5]
  };
  // extension: key=value 空格分隔，值可含空格直到下一 key=
  const extRe = /([a-zA-Z0-9.]+)=((?:\\=|\\\||[^ =]|(?<=\S) )+?)(?=\s+[a-zA-Z0-9.]+=|$)/g;
  let m;
  while ((m = extRe.exec(ext)) !== null) {
    const k = m[1];
    const v = m[2].replace(/\\=/g, '=').replace(/\\\|/g, '|').trim();
    obj[k] = v;
  }
  // 常见 CEF 扩展映射提示字段（归一层还会再处理）
  if (obj.src) obj.srcIp = obj.src;
  if (obj.dst) obj.dstIp = obj.dst;
  if (obj.dhost) obj.host = obj.dhost;
  if (obj.shost && !obj.host) obj.host = obj.shost;
  if (obj.msg) obj.description = obj.msg;
  if (obj.cs1 && !obj.attackType) obj.attackType = obj.cs1;
  return obj;
}

function parseCefAlerts(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map(parseCefLine)
    .filter(Boolean);
}

function parseLeefLine(line) {
  const idx = line.search(/LEEF:\d+\.\d+\|/i);
  if (idx < 0) return null;
  const body = line.slice(idx);
  const parts = body.split('|');
  if (parts.length < 5) return null;
  const obj = {
    leefVersion: parts[0].replace(/^LEEF:/i, ''),
    deviceVendor: parts[1],
    deviceProduct: parts[2],
    deviceVersion: parts[3],
    title: parts[4],
    name: parts[4],
    attackType: parts[4]
  };
  const ext = parts.slice(5).join('|');
  const sep = ext.includes('\t') ? '\t' : '|';
  for (const pair of ext.split(sep)) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    obj[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  if (obj.src) obj.srcIp = obj.src;
  if (obj.dst) obj.dstIp = obj.dst;
  if (obj.msg) obj.description = obj.msg;
  return obj;
}

function parseLeefAlerts(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map(parseLeefLine)
    .filter(Boolean);
}

function detectDelimiter(headerLine) {
  const commas = (headerLine.match(/,/g) || []).length;
  const tabs = (headerLine.match(/\t/g) || []).length;
  const semis = (headerLine.match(/;/g) || []).length;
  if (tabs >= commas && tabs >= semis && tabs > 0) return '\t';
  if (semis > commas) return ';';
  return ',';
}

function splitCsvLine(line, delim) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else inQ = !inQ;
      continue;
    }
    if (ch === delim && !inQ) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim());
}

function parseDelimitedAlerts(text) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .filter((l) => l.trim() && !l.trim().startsWith('#'));
  if (lines.length < 1) return [];

  const delim = detectDelimiter(lines[0]);
  const headerParts = splitCsvLine(lines[0], delim).map((h) => h.replace(/^\uFEFF/, ''));
  const headerLooksLikeFields =
    headerParts.length >= 2 &&
    headerParts.some((h) =>
      /time|date|type|title|name|src|dst|host|desc|message|severity|ip|alert/i.test(h)
    );

  if (headerLooksLikeFields) {
    const alerts = [];
    for (let i = 1; i < lines.length; i++) {
      const cols = splitCsvLine(lines[i], delim);
      if (!cols.length || cols.every((c) => !c)) continue;
      const obj = {};
      headerParts.forEach((h, idx) => {
        if (cols[idx] != null && cols[idx] !== '') obj[h] = cols[idx];
      });
      alerts.push(obj);
    }
    return alerts;
  }

  // 无表头：按经典顺序猜测
  return lines.map((line, i) => {
    const parts = splitCsvLine(line, delim);
    if (parts.length >= 2) {
      return {
        id: `line-${i + 1}`,
        timestamp: isLikelyDate(parts[0]) ? parts[0] : undefined,
        attackType: isLikelyDate(parts[0]) ? parts[1] : parts[0],
        title: parts[2] || parts[1] || parts[0],
        srcIp: parts[3] || null,
        dstIp: parts[4] || null,
        host: parts[5] || null,
        description: parts.slice(isLikelyDate(parts[0]) ? 6 : 5).join(delim) || line
      };
    }
    return { id: `line-${i + 1}`, attackType: line, title: line, description: line };
  });
}

function isLikelyDate(s) {
  if (!s) return false;
  if (/^\d{10,13}$/.test(s)) return true;
  return !Number.isNaN(Date.parse(s));
}

function parseNdjson(text) {
  const alerts = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    if (!(t.startsWith('{') || t.startsWith('['))) continue;
    const loose = parseLooseAlertText(t);
    if (loose.length) alerts.push(...loose);
  }
  return alerts;
}

function parseKeyValueBlocks(text) {
  const blocks = String(text || '')
    .split(/\n\s*\n+|^\s*-{3,}\s*$|^\s*={3,}\s*$/m)
    .map((b) => b.trim())
    .filter(Boolean);
  const alerts = [];
  for (const block of blocks) {
    const lines = block.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length < 2) continue;
    const kvCount = lines.filter((l) => /^[\w.\-]+\s*[:=]\s*.+/.test(l.trim())).length;
    if (kvCount < 2) continue;
    const obj = {};
    for (const line of lines) {
      const m = line.trim().match(/^([\w.\-]+)\s*[:=]\s*(.*)$/);
      if (m) obj[m[1]] = m[2].trim();
    }
    if (Object.keys(obj).length >= 2) alerts.push(obj);
  }
  return alerts;
}

function parseStixLike(parsed) {
  if (!parsed || typeof parsed !== 'object') return [];
  if (Array.isArray(parsed.objects)) {
    return parsed.objects
      .filter((o) => o && (o.type === 'indicator' || o.type === 'malware' || o.type === 'attack-pattern' || o.type === 'observed-data' || o.name || o.pattern))
      .map((o) => ({
        id: o.id,
        title: o.name || o.type,
        attackType: o.type,
        description: o.description || o.pattern || JSON.stringify(o),
        timestamp: o.created || o.modified,
        techniqueIds: (o.kill_chain_phases || [])
          .map((p) => p.phase_name)
          .filter(Boolean)
      }));
  }
  return [];
}

/**
 * 统一入口：任意文本 → 告警对象数组（再交给 normalizeAlertList）
 */
function parseAlertsFromText(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return [];

  // 1) CEF / LEEF（优先，避免被当普通行）
  if (looksLikeCef(trimmed)) {
    const cef = parseCefAlerts(trimmed);
    if (cef.length) return normalizeAlertList(cef);
  }
  if (looksLikeLeef(trimmed)) {
    const leef = parseLeefAlerts(trimmed);
    if (leef.length) return normalizeAlertList(leef);
  }

  // 2) XML
  if (looksLikeXml(trimmed)) {
    const xml = parseXmlAlerts(trimmed);
    if (xml.length) return normalizeAlertList(xml);
  }

  // 3) JSON / Python dict / {title,text}
  // 外形像 JSON 时只走宽松 JSON 路径，失败则返回空，避免尾逗号等瑕疵被当成 CSV/叙述整段误解析
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const loose = parseLooseAlertText(trimmed);
    if (loose.length) {
      // STIX bundle?
      if (loose.length === 1 && loose[0].objects) {
        const stix = parseStixLike(loose[0]);
        if (stix.length) return normalizeAlertList(stix);
      }
      return normalizeAlertList(loose);
    }
    return [];
  }

  // 4) NDJSON（多行 JSON 对象）
  const nd = parseNdjson(trimmed);
  if (nd.length >= 1 && trimmed.split(/\r?\n/).filter((l) => l.trim().startsWith('{')).length >= 2) {
    return normalizeAlertList(nd);
  }

  // 5) key=value 多段
  const kv = parseKeyValueBlocks(trimmed);
  if (kv.length) return normalizeAlertList(kv);

  // 6) CSV / TSV / 分号表
  if (
    trimmed.includes(',') ||
    trimmed.includes('\t') ||
    (trimmed.includes(';') && trimmed.split(/\r?\n/).length >= 2)
  ) {
    const rows = parseDelimitedAlerts(trimmed);
    if (rows.length) return normalizeAlertList(rows);
  }

  // 7) 单行 NDJSON 尝试
  if (nd.length) return normalizeAlertList(nd);

  // 8) 叙述型 / 纯文本：整段作为一条（或按 --- 切开）
  const blocks = trimmed
    .split(/^\s*-{3,}\s*$/m)
    .map((b) => b.trim())
    .filter(Boolean);
  if (blocks.length > 1) {
    return normalizeAlertList(
      blocks.map((b, i) => ({
        id: `text-${i + 1}`,
        title: b.slice(0, 40),
        text: b,
        description: b
      }))
    );
  }

  return normalizeAlertList([
    {
      id: 'text-1',
      title: trimmed.slice(0, 48),
      text: trimmed,
      description: trimmed
    }
  ]);
}

module.exports = {
  parseAlertsFromText,
  parseXmlAlerts,
  parseCefAlerts,
  parseLeefAlerts,
  parseDelimitedAlerts
};
