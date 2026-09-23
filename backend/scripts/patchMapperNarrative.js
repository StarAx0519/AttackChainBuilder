const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/mapper.js');
let s = fs.readFileSync(file, 'utf8');

const start = s.indexOf('/**\r\n * 从叙述文本解析事件时间');
const end = s.indexOf('/**\r\n * 对单条告警执行完整映射流水线');
if (start < 0 || end < 0) {
  console.error('markers not found', start, end);
  process.exit(1);
}

const insert = `const {
  parseEventTimeInfo,
  parseEventTimeFromText,
  extractExplicitTechniqueIds,
  isNarrativeCase,
  expandNarrativeAlert,
  resolveTechniqueMeta,
  resolveTacticOnlyMeta
} = require('./narrativeExpand');

/**
 * 入库前规范化：叙述案例拆条；补全 text→description；解析中文时间
 */
function normalizeAlerts(alerts, attck) {
  const out = [];
  for (const raw of alerts || []) {
    const alert = {
      ...raw,
      description: raw.description || raw.text || raw.message || null
    };

    if (isNarrativeCase(alert)) {
      out.push(...expandNarrativeAlert(alert, attck));
      continue;
    }

    if (!alert.timestamp && !alert.time) {
      const info = parseEventTimeInfo(
        [alert.title, alert.description, alert.text, alert.message].filter(Boolean).join(' ')
      );
      if (info.iso) {
        alert.timestamp = info.iso;
        alert.timePrecision = info.precision;
        alert.timeDisplay = info.display;
      }
    }
    if (!alert.explicitTechniqueId) {
      const ids = extractExplicitTechniqueIds(
        [alert.description, alert.text, alert.title, alert.message].filter(Boolean).join(' ')
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
    const meta = resolveTacticOnlyMeta(tacticOverride, attck);
    const quality = getQuality(0.88);
    return {
      primary: null,
      secondary: [],
      confidence: 0.88,
      quality: quality.level,
      qualityLabel: quality.label,
      method: 'explicit',
      techniqueName: meta.techniqueName,
      tacticId: meta.tacticId,
      tacticName: meta.tacticName,
      tacticNameEn: meta.tacticNameEn,
      killChainOrder: meta.killChainOrder
    };
  }
  const meta = resolveTechniqueMeta(techId, attck, tacticOverride);
  const quality = getQuality(0.96);
  return {
    primary: techId,
    secondary: techId.includes('.') ? [techId.split('.')[0]] : [],
    confidence: 0.96,
    quality: quality.level,
    qualityLabel: quality.label,
    method: 'explicit',
    techniqueName: meta.techniqueName,
    tacticId: meta.tacticId,
    tacticName: meta.tacticName,
    tacticNameEn: meta.tacticNameEn,
    killChainOrder: meta.killChainOrder
  };
}

`;

s = s.slice(0, start) + insert + s.slice(end);
fs.writeFileSync(file, s);
console.log('mapper.js patched');
