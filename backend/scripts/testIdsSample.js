const fs = require('fs');
const path = require('path');
const { loadAttckData, getDefaultAttckPath } = require('../src/attckParser');
const { mapAlertsBatch } = require('../src/mapper');
const { parseLooseAlertText, normalizeAlertList } = require('../src/alertNormalize');

const samplePath = path.join(__dirname, 'ids_sample.txt');
const raw = fs.readFileSync(samplePath, 'utf8');
const parsed = parseLooseAlertText(raw);
console.log('parsed count', parsed.length);
const alerts = normalizeAlertList(parsed);
const attck = loadAttckData(getDefaultAttckPath());
const mapped = mapAlertsBatch(alerts, attck);
mapped.forEach((m) => {
  console.log(
    [
      m.timestamp,
      m.srcIp,
      m.dstIp,
      m.mapping.primary,
      m.mapping.tacticId,
      m.mapping.method,
      m.mapping.confidence,
      (m.title || '').slice(0, 40)
    ].join(' | ')
  );
});
console.log('fallback count', mapped.filter((m) => m.mapping.method === 'fallback').length);
