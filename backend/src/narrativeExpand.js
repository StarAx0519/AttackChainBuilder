const { findAllTechniqueHits, findKeywordHits } = require('./techniqueLexicon');

function pad2(n) {
  return String(Number(n)).padStart(2, '0');
}

function toIsoDate(y, mo, d) {
  const dt = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), 0, 0, 0));
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString();
}

function parseEventTimeInfo(text) {
  if (!text) return { iso: null, precision: 'unknown', display: null };
  const s = String(text);

  let m = s.match(/(\d{4})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日/);
  if (m) {
    return {
      iso: toIsoDate(m[1], m[2], m[3]),
      precision: 'day',
      display: `${m[1]}-${pad2(m[2])}-${pad2(m[3])}`
    };
  }
  m = s.match(/(\d{4})\s*年\s*(\d{1,2})\s*月/);
  if (m) {
    return {
      iso: toIsoDate(m[1], m[2], 1),
      precision: 'month',
      display: `${m[1]}年${Number(m[2])}月`
    };
  }
  m = s.match(/(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (m) {
    return {
      iso: toIsoDate(m[1], m[2], m[3]),
      precision: 'day',
      display: `${m[1]}-${pad2(m[2])}-${pad2(m[3])}`
    };
  }
  if (!Number.isNaN(Date.parse(s)) && /\d{4}-\d{2}-\d{2}T/.test(s)) {
    return { iso: new Date(s).toISOString(), precision: 'exact', display: null };
  }
  return { iso: null, precision: 'unknown', display: null };
}

function parseEventTimeFromText(text) {
  return parseEventTimeInfo(text).iso;
}

function extractExplicitTechniqueIds(text) {
  if (!text) return [];
  const re = /\b(T\d{4}(?:\.\d{3})?)\b/gi;
  const seen = new Set();
  const ids = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const norm = m[1].toUpperCase();
    if (!seen.has(norm)) {
      seen.add(norm);
      ids.push(norm);
    }
  }
  return ids;
}

function extractExplicitTacticIds(text) {
  if (!text) return [];
  const re = /\b(TA\d{4})\b/gi;
  const seen = new Set();
  const ids = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const id = m[1].toUpperCase();
    if (!seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  }
  return ids;
}

function snippetAroundId(text, id) {
  if (!text || !id) return null;
  const idx = text.toUpperCase().indexOf(String(id).toUpperCase());
  if (idx < 0) {
    return text.length > 160 ? `${text.slice(0, 160)}…` : text;
  }
  const start = Math.max(0, idx - 50);
  const end = Math.min(text.length, idx + String(id).length + 60);
  let snip = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) snip = `…${snip}`;
  if (end < text.length) snip = `${snip}…`;
  return snip;
}

const TECHNIQUE_TACTIC_FALLBACK = {
  T1505: 'TA0003',
  T1110: 'TA0006',
  T1552: 'TA0006',
  T1486: 'TA0040',
  T1498: 'TA0040',
  T1185: 'TA0005',
  T1105: 'TA0011',
  T1566: 'TA0001',
  T1055: 'TA0004',
  T1021: 'TA0008',
  T1190: 'TA0001',
  T1547: 'TA0003',
  T1543: 'TA0003',
  T1053: 'TA0003',
  T1595: 'TA0043',
  T1590: 'TA0043',
  T1589: 'TA0043',
  T1046: 'TA0007',
  T1219: 'TA0011',
  T1571: 'TA0011',
  T1572: 'TA0011',
  T1095: 'TA0011',
  T1090: 'TA0011',
  T1071: 'TA0011',
  T1562: 'TA0005',
  T1070: 'TA0005',
  T1041: 'TA0010',
  T1048: 'TA0010',
  T1005: 'TA0009',
  T1560: 'TA0009',
  T1059: 'TA0002',
  T1078: 'TA0001',
  T1068: 'TA0004',
  T1222: 'TA0005',
  T1018: 'TA0007'
};

const TECHNIQUE_NAME_HINTS = {
  T1190: '利用面向公众的应用程序',
  T1590: '收集受害者网络信息',
  T1589: '收集受害者身份信息',
  T1595: '主动扫描',
  T1021: '远程服务',
  T1110: '暴力破解',
  T1552: '未保护的凭证',
  T1046: '网络服务发现',
  T1105: '入口工具传输',
  T1059: '命令与脚本解释器',
  T1543: '创建或修改系统进程',
  T1571: '非标准端口',
  T1095: '非应用层协议',
  T1562: '削弱防御',
  T1070: '指标清除',
  T1090: '代理',
  T1071: '应用层协议',
  T1041: '通过 C2 通道渗出',
  T1005: '来自本地系统的数据',
  T1560: '归档收集的数据',
  T1566: '网络钓鱼',
  T1055: '进程注入',
  T1219: '远程访问软件',
  T1572: '协议隧道'
};

function resolveTechniqueMeta(techId, attck, tacticOverride) {
  const base = (techId || '').split('.')[0];
  const tech =
    (attck.techniqueById && (attck.techniqueById[techId] || attck.techniqueById[base])) ||
    null;
  const tacticId =
    tacticOverride ||
    (tech && tech.tacticId) ||
    TECHNIQUE_TACTIC_FALLBACK[base] ||
    TECHNIQUE_TACTIC_FALLBACK[techId] ||
    null;
  const tactic = (attck.killChainOrder || []).find((t) => t.id === tacticId) || null;
  return {
    techniqueName:
      (tech && tech.name) ||
      TECHNIQUE_NAME_HINTS[techId] ||
      TECHNIQUE_NAME_HINTS[base] ||
      techId,
    hintName: TECHNIQUE_NAME_HINTS[techId] || TECHNIQUE_NAME_HINTS[base] || null,
    tacticId,
    tacticName: tactic ? tactic.name : null,
    tacticNameEn: tactic ? tactic.nameEn : null,
    killChainOrder: tactic ? tactic.order : 99
  };
}

function resolveTacticOnlyMeta(tacticId, attck) {
  const tactic = (attck.killChainOrder || []).find((t) => t.id === tacticId) || null;
  return {
    techniqueName: '（文中仅提及战术，未给出技术编号）',
    hintName: tactic ? tactic.name : tacticId,
    tacticId: tacticId || null,
    tacticName: tactic ? tactic.name : null,
    tacticNameEn: tactic ? tactic.nameEn : null,
    killChainOrder: tactic ? tactic.order : 99
  };
}

function extractNarrativeSteps(text, attck) {
  if (!text) return [];
  const events = [];
  const taRe = /\b(TA\d{4})\b/gi;
  const tRe = /\b(T\d{4}(?:\.\d{3})?)\b/gi;
  let m;
  while ((m = taRe.exec(text)) !== null) {
    events.push({ kind: 'tactic', id: m[1].toUpperCase(), index: m.index });
  }
  while ((m = tRe.exec(text)) !== null) {
    events.push({ kind: 'tech', id: m[1].toUpperCase(), index: m.index });
  }
  events.sort((a, b) => a.index - b.index || (a.kind === 'tactic' ? -1 : 1));

  const steps = [];
  const linkedTas = new Set();
  const seenTech = new Set();

  for (const ev of events) {
    if (ev.kind !== 'tech') continue;
    if (seenTech.has(ev.id)) continue;
    seenTech.add(ev.id);

    const windowBefore = 180;
    const windowAfter = 90;
    let bestBefore = null;
    let bestBeforeDist = Infinity;
    let bestAfter = null;
    let bestAfterDist = Infinity;
    for (const e2 of events) {
      if (e2.kind !== 'tactic') continue;
      const dist = e2.index - ev.index;
      if (dist <= 0 && dist >= -windowBefore) {
        const ad = -dist;
        if (ad < bestBeforeDist) {
          bestBeforeDist = ad;
          bestBefore = e2.id;
        }
      } else if (dist > 0 && dist <= windowAfter) {
        if (dist < bestAfterDist) {
          bestAfterDist = dist;
          bestAfter = e2.id;
        }
      }
    }
    let bestTa = bestBefore;
    if (bestAfter && (!bestBefore || bestAfterDist + 20 < bestBeforeDist)) {
      bestTa = bestAfter;
    }

    if (bestTa) linkedTas.add(bestTa);
    steps.push({
      kind: 'technique',
      techId: ev.id,
      tacticOverride: bestTa || null,
      index: ev.index,
      snippet: snippetAroundId(text, ev.id)
    });
  }

  for (const ev of events) {
    if (ev.kind !== 'tactic') continue;
    if (linkedTas.has(ev.id)) continue;
    if (steps.some((s) => s.tacticOverride === ev.id)) continue;
    linkedTas.add(ev.id);
    const tactic = (attck.killChainOrder || []).find((t) => t.id === ev.id);
    steps.push({
      kind: 'tactic_only',
      techId: null,
      tacticOverride: ev.id,
      index: ev.index,
      snippet: snippetAroundId(text, ev.id),
      tacticName: tactic ? tactic.name : ev.id
    });
  }

  steps.sort((a, b) => a.index - b.index);
  return steps;
}

function splitProseSegments(text) {
  const s = String(text || '').trim();
  if (!s) return [];

  const trySplit = (re, labelFn) => {
    const marks = [];
    let m;
    const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    while ((m = r.exec(s)) !== null) {
      marks.push({ index: m.index, label: labelFn(m, marks.length + 1) });
    }
    if (marks.length < 2) return null;
    const segs = [];
    for (let i = 0; i < marks.length; i++) {
      const start = marks[i].index;
      const end = i + 1 < marks.length ? marks[i + 1].index : s.length;
      const chunk = s.slice(start, end).trim();
      if (chunk.length < 8) continue;
      segs.push({
        text: chunk,
        offset: start,
        label: marks[i].label,
        stepNo: i + 1
      });
    }
    return segs.length >= 2 ? segs : null;
  };

  let segs =
    trySplit(/第[一二三四五六七八九十百零〇两\d]+步/g, (m) => m[0]) ||
    trySplit(/Step\s*\d+/gi, (m) => m[0]) ||
    trySplit(/步骤\s*\d+/g, (m) => m[0]) ||
    trySplit(/(?:^|\n)\s*[(（]?\d+[)）、.．:：]\s+/gm, (_m, n) => `段落${n}`);

  if (segs) {
    if (segs[0].offset > 48) {
      segs[0] = {
        ...segs[0],
        text: `${s.slice(0, segs[0].offset).trim()}\n${segs[0].text}`,
        offset: 0
      };
    }
    return segs;
  }

  const paras = s
    .split(/\n\s*\n+/)
    .map((p) => p.trim())
    .filter((p) => p.length >= 40);
  if (paras.length >= 2) {
    let off = 0;
    return paras.map((p, i) => {
      const idx = s.indexOf(p, off);
      off = idx + p.length;
      return { text: p, offset: idx >= 0 ? idx : 0, label: `段落${i + 1}`, stepNo: i + 1 };
    });
  }

  return [{ text: s, offset: 0, label: null, stepNo: null }];
}

function extractProseNarrativeSteps(text, attck) {
  if (!text || String(text).length < 80) return [];

  const segments = splitProseSegments(text);
  const useSegments = segments.length >= 2 && !!segments[0].label;
  const byTech = new Map();

  const ingest = (hits, baseOffset, segMeta) => {
    for (const h of hits) {
      const absIndex = baseOffset + (h.index || 0);
      const prev = byTech.get(h.techId);
      if (prev && prev.index <= absIndex && prev.confidence >= h.confidence) continue;

      const meta = resolveTechniqueMeta(
        h.techId,
        attck,
        (h.tactics && h.tactics[0]) || null
      );
      const phase = meta.tacticName || null;
      const stepLabel = segMeta.label
        ? `${segMeta.label}${phase ? ` · ${phase}` : ''}`
        : phase
          ? `叙述命中 · ${phase}`
          : '叙述命中';

      byTech.set(h.techId, {
        kind: 'technique',
        techId: h.techId,
        secondary: h.secondary || [],
        tacticOverride: meta.tacticId || (h.tactics && h.tactics[0]) || null,
        index: absIndex,
        snippet: h.snippet || null,
        confidence: h.confidence,
        fromProse: true,
        phase,
        narrativeStepNo: segMeta.stepNo,
        stepLabel,
        segmentLabel: segMeta.label,
        source: h.source
      });
    }
  };

  if (useSegments) {
    for (const seg of segments) {
      const hits = findAllTechniqueHits(seg.text, attck, { expandSecondary: false });
      ingest(hits, seg.offset, seg);
    }
  } else {
    const hits = findAllTechniqueHits(text, attck, { expandSecondary: false });
    ingest(hits, 0, { label: null, stepNo: null });
  }

  const steps = [...byTech.values()].sort(
    (a, b) =>
      (a.narrativeStepNo || 0) - (b.narrativeStepNo || 0) ||
      a.index - b.index ||
      b.confidence - a.confidence
  );

  if (!useSegments) {
    steps.forEach((s, i) => {
      s.narrativeStepNo = i + 1;
      if (!s.stepLabel || s.stepLabel === '叙述命中') {
        s.stepLabel = s.phase ? `攻击行为 · ${s.phase}` : `攻击行为 ${i + 1}`;
      }
    });
  }

  return steps;
}

function looksLikeProseNarrative(alert, body) {
  const s = String(body || '');
  if (s.length < 100) return false;

  if (alert.srcIp && alert.dstIp && s.length < 280) {
    const hasEnum = /第[一二三四五六七八九十\d]+步|Step\s*\d+|步骤\s*\d+/i.test(s);
    if (!hasEnum) return false;
  }

  const hits = findKeywordHits(s);
  if (hits.length >= 2) return true;
  if (s.length >= 200 && hits.length >= 1) return true;
  if (alert.title && s.length >= 180 && /攻击|入侵|漏洞|横向|外泄|钓鱼|注入/.test(s)) {
    return true;
  }
  return false;
}

function isNarrativeCase(alert) {
  const body = alert.text || alert.description || alert.message || '';
  if (String(body).length < 80) return false;
  if (alert._fromNarrative) return false;
  const techs = extractExplicitTechniqueIds(body);
  const tactics = extractExplicitTacticIds(body);
  if (techs.length + tactics.length >= 1) {
    if (alert.attackType && alert.primaryTechnique && techs.length <= 1 && tactics.length === 0) {
      return false;
    }
    return true;
  }
  return looksLikeProseNarrative(alert, body);
}

function expandNarrativeAlert(alert, attck) {
  const body = alert.text || alert.description || alert.message || '';
  let steps = extractNarrativeSteps(body, attck);
  if (!steps.length) {
    steps = extractProseNarrativeSteps(body, attck);
  }
  if (!steps.length) return [alert];

  const timeInfo = parseEventTimeInfo(
    [alert.timestamp, alert.time, body, alert.title].filter(Boolean).join(' ')
  );
  const caseTitle = alert.title || alert.name || '叙述型攻击案例';

  return steps.map((step, idx) => {
    const stepLabel = step.stepLabel || `攻击步骤${idx + 1}`;
    const meta = step.techId
      ? resolveTechniqueMeta(step.techId, attck, step.tacticOverride)
      : resolveTacticOnlyMeta(step.tacticOverride, attck);
    const techPart = step.techId || step.tacticOverride || '';

    return {
      id: `${alert.id || alert.alertId || 'case'}-step${idx + 1}`,
      timestamp: timeInfo.iso,
      timePrecision: timeInfo.precision,
      timeDisplay: timeInfo.display,
      stepIndex: step.narrativeStepNo || idx + 1,
      stepLabel,
      attackType: meta.hintName || step.techId || step.tacticOverride || 'narrative',
      title: [caseTitle, stepLabel, techPart].filter(Boolean).join(' · '),
      description: step.snippet || body,
      // 映射用局部片段，避免整篇原文再被当成「正文写明技术编号」
      text: step.snippet || body,
      srcIp: alert.srcIp || null,
      dstIp: alert.dstIp || null,
      host: alert.host || null,
      severity: alert.severity || 'high',
      // 仅当步骤来自文中真实 T/TA 编号时写入 explicit；散文关键词命中走 inferred
      explicitTechniqueId: step.fromProse ? null : step.techId || null,
      inferredTechniqueId: step.fromProse ? step.techId || null : null,
      tacticOverride: step.tacticOverride || meta.tacticId || null,
      tacticOnly: step.kind === 'tactic_only',
      mappingConfidenceHint: step.confidence || null,
      phase: step.phase || meta.tacticName || null,
      _fromNarrative: true,
      _fromProse: !!step.fromProse,
      _caseTitle: caseTitle,
      original: alert
    };
  });
}

module.exports = {
  parseEventTimeInfo,
  parseEventTimeFromText,
  extractExplicitTechniqueIds,
  extractExplicitTacticIds,
  extractNarrativeSteps,
  extractProseNarrativeSteps,
  isNarrativeCase,
  expandNarrativeAlert,
  resolveTechniqueMeta,
  resolveTacticOnlyMeta,
  TECHNIQUE_NAME_HINTS,
  TECHNIQUE_TACTIC_FALLBACK
};
