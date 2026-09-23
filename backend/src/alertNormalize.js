function stripBom(text) {
  return String(text || '')
    .replace(/^\uFEFF/, '')
    .trim();
}

/**
 * 去掉 JSON/类 JSON 中的行注释与块注释（不破坏字符串内容）
 */
function stripJsonComments(text) {
  const s = String(text || '');
  let out = '';
  let i = 0;
  let inStr = false;
  let quote = '';
  let escaped = false;
  while (i < s.length) {
    const ch = s[i];
    const next = s[i + 1];
    if (inStr) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) inStr = false;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = true;
      quote = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === '/' && next === '/') {
      i += 2;
      while (i < s.length && s[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/**
 * 修复常见粘贴瑕疵：尾逗号、智能引号、undefined、BOM、注释
 */
function repairJsonish(text) {
  let s = stripBom(text);
  if (!s) return s;
  s = s.replace(/[\u201C\u201D\u201E\u00AB\u00BB]/g, '"').replace(/[\u2018\u2019]/g, "'");
  s = stripJsonComments(s);
  s = s.replace(/\bundefined\b/g, 'null');
  // 反复去掉 ,] 或 ,}（含空白/换行）
  let prev;
  do {
    prev = s;
    s = s.replace(/,(\s*[}\]])/g, '$1');
  } while (s !== prev);
  return s.trim();
}

function tryJsonParse(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: err };
  }
}

/** Python / 单引号字典 → 近似 JSON */
function toJsonishFromPython(text) {
  return repairJsonish(
    String(text || '')
      .replace(/\bNone\b/g, 'null')
      .replace(/\bTrue\b/g, 'true')
      .replace(/\bFalse\b/g, 'false')
      .replace(/'/g, '"')
  );
}

/** 仅替换键/值上的单引号，尽量保留描述里的撇号语义 */
function toJsonishFromSingleQuotes(text) {
  const fixedKeys = String(text || '').replace(/'([^']+)'\s*:/g, '"$1":');
  const fixedVals = fixedKeys.replace(/:\s*'([^']*)'/g, (_m, v) => {
    const esc = String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `: "${esc}"`;
  });
  return repairJsonish(fixedVals);
}

/**
 * 从看似破损的数组/对象文本中抽取可解析的 {...} 对象（兜底）
 */
function extractJsonObjects(text) {
  const s = repairJsonish(text);
  const out = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === '{') {
      if (depth === 0) start = i;
      depth++;
      continue;
    }
    if (ch === '}') {
      if (depth <= 0) continue;
      depth--;
      if (depth === 0 && start >= 0) {
        const slice = s.slice(start, i + 1);
        const parsed = tryJsonParse(repairJsonish(slice));
        if (parsed.ok && parsed.value && typeof parsed.value === 'object' && !Array.isArray(parsed.value)) {
          out.push(parsed.value);
        } else {
          const py = tryJsonParse(toJsonishFromPython(slice));
          if (py.ok && py.value && typeof py.value === 'object' && !Array.isArray(py.value)) {
            out.push(py.value);
          }
        }
        start = -1;
      }
    }
  }
  return out;
}

/**
 * 将文本解析为告警对象数组（尽量宽容）
 */
function parseLooseAlertText(text) {
  const trimmed = stripBom(text);
  if (!trimmed) return [];

  const candidates = [
    trimmed,
    repairJsonish(trimmed),
    toJsonishFromPython(trimmed),
    toJsonishFromSingleQuotes(trimmed)
  ];

  const seen = new Set();
  for (const candidate of candidates) {
    if (!candidate || seen.has(candidate)) continue;
    seen.add(candidate);
    const parsed = tryJsonParse(candidate);
    if (parsed.ok) return asAlertArray(parsed.value);
  }

  // 数组/对象外形明显但整体解析失败时，尝试逐个抽取对象
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const objs = extractJsonObjects(trimmed);
    if (objs.length) return objs;
  }

  return [];
}

function asAlertArray(parsed) {
  if (!parsed) return [];
  if (Array.isArray(parsed)) return parsed.filter((x) => x != null);
  if (parsed.alerts && Array.isArray(parsed.alerts)) return parsed.alerts;
  if (parsed.data && Array.isArray(parsed.data)) return parsed.data;
  if (parsed.events && Array.isArray(parsed.events)) return parsed.events;
  if (parsed.records && Array.isArray(parsed.records)) return parsed.records;
  if (parsed.Results && Array.isArray(parsed.Results)) return parsed.Results;
  if (parsed.items && Array.isArray(parsed.items)) return parsed.items;
  if (typeof parsed === 'object') return [parsed];
  return [];
}

function normalizeTimestamp(raw) {
  if (raw == null || raw === '' || raw === '-') return null;
  if (typeof raw === 'number' || /^\d+$/.test(String(raw))) {
    let n = Number(raw);
    if (!Number.isFinite(n)) return null;
    if (n > 0 && n < 1e11) n *= 1000;
    const d = new Date(n);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function pick(...vals) {
  for (const v of vals) {
    if (v == null) continue;
    if (typeof v === 'object' && !Array.isArray(v)) {
      // nested {ip: "..."} / {address: "..."}
      const nested = pick(v.ip, v.address, v.value, v.name);
      if (nested != null) return nested;
      continue;
    }
    const s = String(v).trim();
    if (!s || s === '-' || s === 'null' || s === 'undefined') continue;
    return typeof v === 'string' ? s : v;
  }
  return null;
}

function dig(obj, paths) {
  for (const p of paths) {
    if (!p) continue;
    const parts = String(p).split('.');
    let cur = obj;
    let ok = true;
    for (const part of parts) {
      if (cur == null || typeof cur !== 'object') {
        ok = false;
        break;
      }
      cur = cur[part];
    }
    if (ok && cur != null && cur !== '') return cur;
  }
  return null;
}

/**
 * 将单条原始告警归一为映射引擎统一字段
 */
function normalizeAlertFields(raw) {
  if (!raw || typeof raw !== 'object') return raw;

  const desc = pick(
    raw.desc,
    raw.description,
    raw.text,
    raw.message,
    raw.msg,
    raw.detail,
    raw.details,
    raw.signature,
    raw.sig_name,
    raw.Summary,
    raw.event_description,
    raw.alert_description,
    raw.content,
    dig(raw, ['event.description', 'alert.description', 'payload.summary'])
  );

  const title = pick(
    raw.title,
    raw.name,
    raw.Name,
    raw.alert_name,
    raw.alertName,
    raw.event_name,
    raw.EventName,
    raw.rule_name,
    raw.RuleName,
    raw.signature,
    raw.sig_name,
    raw.cat,
    desc
  );

  const srcIp = pick(
    raw.srcIp,
    raw.sourceIp,
    raw.src_ip,
    raw.source_ip,
    raw.src,
    raw.source,
    raw.sip,
    raw.SourceAddress,
    raw.sourceAddress,
    raw.srcaddr,
    raw.client_ip,
    raw.attacker,
    raw.attacker_ip,
    dig(raw, ['source.ip', 'src.ip', 'client.ip', 'actor.ip'])
  );

  const dstIp = pick(
    raw.dstIp,
    raw.destIp,
    raw.dst_ip,
    raw.dest_ip,
    raw.destinationIp,
    raw.dst,
    raw.destination,
    raw.dip,
    raw.DestinationAddress,
    raw.destAddress,
    raw.dstaddr,
    raw.target,
    raw.target_ip,
    raw.victim,
    dig(raw, ['destination.ip', 'dst.ip', 'target.ip', 'server.ip'])
  );

  const host = pick(
    raw.host,
    raw.hostname,
    raw.host_name,
    raw.dst_host,
    raw.src_host,
    raw.dhost,
    raw.shost,
    raw.computer,
    raw.Computer,
    raw.device_name,
    raw.asset_name,
    dig(raw, ['host.name', 'device.hostname', 'agent.hostname'])
  );

  const destNodeId = pick(raw.dnode, raw.destNode, raw.dest_node_id);
  const srcNodeId = pick(raw.snode, raw.srcNode, raw.src_node_id);
  const device = pick(
    raw.device,
    raw.sensor,
    raw.engine,
    raw.DeviceProduct,
    raw.deviceProduct,
    raw.product,
    raw.vendor
  );

  const timestamp = normalizeTimestamp(
    pick(
      raw.timestamp,
      raw.time,
      raw.eventTime,
      raw.event_time,
      raw.createdAt,
      raw.created,
      raw.log_time,
      raw.LogTime,
      raw.start,
      raw.StartTime,
      raw.occur_time,
      raw.detect_time,
      dig(raw, ['event.created', '@timestamp', 'event.ingested'])
    )
  );

  const attackType = pick(
    raw.attackType,
    raw.attack_type,
    raw.type,
    raw.alertType,
    raw.alert_type,
    raw.category,
    raw.Category,
    raw.cat,
    raw.threat_type,
    raw.ThreatName,
    raw.virus_name,
    raw.malware,
    raw.event_type,
    raw.EventType,
    raw.rule,
    dig(raw, ['threat.technique.name', 'rule.name', 'event.category'])
  );

  const severity = pick(
    raw.severity,
    raw.Severity,
    raw.level,
    raw.priority,
    raw.risk,
    raw.RiskLevel,
    dig(raw, ['event.severity', 'threat.severity'])
  );

  return {
    ...raw,
    id: pick(raw.id, raw.alertId, raw.alert_id, raw._id, raw.ba_id, raw.uuid, raw.event_id),
    title,
    description: desc,
    text: pick(raw.text, desc),
    attackType,
    srcIp,
    dstIp,
    host,
    destNodeId,
    srcNodeId,
    device,
    timestamp,
    severity,
    cve: pick(raw.cve, raw.CVE, raw.cve_id),
    original: raw
  };
}

function normalizeAlertList(list) {
  return (list || [])
    .filter((x) => x != null && typeof x === 'object')
    .map(normalizeAlertFields);
}

module.exports = {
  parseLooseAlertText,
  normalizeAlertFields,
  normalizeAlertList,
  normalizeTimestamp,
  repairJsonish,
  extractJsonObjects
};
