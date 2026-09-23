/**
 * contentHash.js — 告警/映射/链路内容指纹（批次级 + 条目级，用于入库去重）
 */
const crypto = require('crypto');

function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
    .join(',')}}`;
}

function sha256(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

/** 从解析后的原始告警列表计算批次指纹（映射前） */
function hashAlertsInput(alerts) {
  const norm = (alerts || []).map((a) => ({
    id: a.id || a.alertId || null,
    timestamp: a.timestamp || a.time || null,
    attackType: a.attackType || a.type || null,
    title: a.title || a.name || null,
    srcIp: a.srcIp || a.sourceIp || null,
    dstIp: a.dstIp || a.destIp || null,
    host: a.host || a.hostname || null,
    description: a.description || a.desc || a.text || a.message || null,
    text: a.text || null
  }));
  return sha256(stableStringify(norm));
}

/** 从已映射结果计算批次指纹（无 contentHash 时的回退） */
function hashMappedAlerts(mapped) {
  const norm = (mapped || []).map((m) => itemPayloadMapped(m));
  return sha256(stableStringify(norm));
}

function itemPayloadMapped(m) {
  return {
    alertId: m.alertId || m.id || null,
    timestamp: m.timestamp || null,
    attackType: m.attackType || null,
    title: m.title || null,
    srcIp: m.srcIp || null,
    dstIp: m.dstIp || null,
    host: m.host || null,
    description: m.description || null,
    stepIndex: m.stepIndex || null,
    stepLabel: m.stepLabel || null
  };
}

/** 单条已映射告警指纹（用于判断库中是否已有该条） */
function itemHashMappedAlert(m) {
  return sha256(stableStringify(itemPayloadMapped(m)));
}

function itemPayloadChain(c) {
  return {
    name: c.name || null,
    alertCount: c.alertCount || 0,
    techniques: [...(c.techniques || [])].sort(),
    coveredTactics: [...(c.coveredTactics || [])].sort(),
    timeline: (c.timeline || []).map((t) => ({
      title: t.title || null,
      technique: t.technique || null,
      techniques: t.techniques || null,
      stepLabel: t.stepLabel || null
    }))
  };
}

function hashChains(chains) {
  const norm = (chains || []).map((c) => itemPayloadChain(c));
  return sha256(stableStringify(norm));
}

/** 单条攻击链路指纹 */
function itemHashChain(c) {
  return sha256(stableStringify(itemPayloadChain(c)));
}

/**
 * 根据条目指纹集合与库中命中数判定入库类型
 * @returns {'all_new'|'all_exist'|'partial'}
 */
function classifyPersistKind(total, existedCount) {
  if (!total) return 'all_new';
  if (existedCount <= 0) return 'all_new';
  if (existedCount >= total) return 'all_exist';
  return 'partial';
}

/** 从已有文档中取出现次数最多的 batchId */
function majorityBatchId(existingDocs, fallback) {
  const counts = new Map();
  for (const d of existingDocs || []) {
    if (!d || !d.batchId) continue;
    counts.set(d.batchId, (counts.get(d.batchId) || 0) + 1);
  }
  let best = fallback;
  let bestN = 0;
  for (const [id, n] of counts) {
    if (n > bestN) {
      best = id;
      bestN = n;
    }
  }
  return best || fallback;
}

/**
 * 入库 / 映射用的 batchId 策略：
 * - all_exist（本次结果全部已在库中，含子集）：复用原 batchId，且不应再落库
 * - partial / all_new：必须使用新的 batchId（newBatchId）
 */
function resolvePersistBatchId(persistKind, sessionBatchId, existingDocs, newBatchId) {
  if (persistKind === 'all_exist') {
    return majorityBatchId(existingDocs, sessionBatchId);
  }
  return newBatchId || sessionBatchId;
}

/** 面向用户的入库提示（简洁、不带技术细节堆砌） */
function userPersistMessage(mode, persistKind, { total = 0, existed = 0, added = 0 } = {}) {
  if (persistKind === 'all_exist') {
    if (mode === 'alerts') {
      return `这 ${total} 条映射结果已在库中（与已有数据相同或为其子集），未重复保存。`;
    }
    if (mode === 'chains') {
      return `该批次的攻击链路已在库中，未重复保存。`;
    }
    return `该批次的统计与覆盖数据已在库中，未重复保存。`;
  }
  if (persistKind === 'partial') {
    if (mode === 'alerts') {
      return `已保存本批 ${total} 条映射结果（新增 ${added} 条；另有 ${existed} 条与库中已有内容相同）。`;
    }
    if (mode === 'chains') {
      return `已保存本批 ${total} 条攻击链路。`;
    }
    return `已保存本批统计与覆盖数据。`;
  }
  if (mode === 'alerts') return `已新保存 ${total} 条映射结果。`;
  if (mode === 'chains') return `已新保存 ${total} 条攻击链路。`;
  return `已新保存统计与覆盖数据。`;
}

function userPersistTitle(persistKind) {
  if (persistKind === 'all_exist') return '已存在，无需重复入库';
  if (persistKind === 'partial') return '保存成功';
  return '保存成功';
}

module.exports = {
  stableStringify,
  sha256,
  hashAlertsInput,
  hashMappedAlerts,
  hashChains,
  itemHashMappedAlert,
  itemHashChain,
  classifyPersistKind,
  majorityBatchId,
  resolvePersistBatchId,
  userPersistMessage,
  userPersistTitle
};
