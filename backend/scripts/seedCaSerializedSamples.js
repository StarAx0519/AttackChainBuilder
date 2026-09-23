/**
 * seedCaSerializedSamples.js
 * 将 data/ca_serialized_pc1.xlsx 每一行告警文本 upsert 进 samplealerts
 *
 * 用法：
 *   cd backend
 *   node scripts/seedCaSerializedSamples.js
 *   （init-db 也会自动调用）
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const { SampleAlert } = require('../src/models');

const MONGO_URI =
  process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/qy_attack_chain';

const DEFAULT_XLSX = path.join(
  __dirname,
  '..',
  '..',
  'data',
  'ca_serialized_pc1.xlsx'
);

function resolveXlsxPath() {
  const fromEnv = process.env.CA_SAMPLES_XLSX;
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;
  if (fs.existsSync(DEFAULT_XLSX)) return DEFAULT_XLSX;
  return null;
}

function extractFirstField(text, field) {
  const re = new RegExp(`'${field}':\\s*'((?:\\\\'|[^'])*)'`);
  const m = String(text || '').match(re);
  return m ? m[1].replace(/\\'/g, "'") : '';
}

function countAlertsInRow(text) {
  const s = String(text || '');
  const n = (s.match(/\{'id':/g) || []).length;
  if (n) return n;
  return (s.match(/\{\s*"id"\s*:/g) || []).length || 1;
}

function rowToSample(raw, index1Based) {
  const content = String(raw).trim();
  const firstDesc = extractFirstField(content, 'desc');
  const firstId = extractFirstField(content, 'id');
  const alertCount = countAlertsInRow(content);
  const shortDesc =
    firstDesc.length > 72 ? `${firstDesc.slice(0, 72)}…` : firstDesc;

  return {
    sampleKey: `ca-pc1-${String(index1Based).padStart(4, '0')}`,
    name: `CA样本 #${index1Based}${shortDesc ? ` · ${shortDesc}` : ''}`,
    description: `来自 ca_serialized_pc1.xlsx 第 ${index1Based} 行；约 ${alertCount} 条告警${
      firstId ? `；首条 id=${firstId}` : ''
    }`,
    format: 'python-list',
    content,
    sortOrder: 1000 + index1Based
  };
}

function readRowsFromXlsx(xlsxPath) {
  const wb = XLSX.readFile(xlsxPath, { raw: false, cellDates: false });
  const sheetName = wb.SheetNames[0];
  const sheet = wb.Sheets[sheetName];
  const matrix = XLSX.utils.sheet_to_json(sheet, {
    header: 1,
    defval: '',
    raw: false
  });

  const rows = [];
  for (const row of matrix) {
    if (!row || !row.length) continue;
    const cell = row[0];
    if (cell == null) continue;
    const text = String(cell).trim();
    if (!text) continue;
    // 跳过表头类单元格
    if (/^(alert|content|text|告警)/i.test(text) && text.length < 40) continue;
    rows.push(text);
  }
  return rows;
}

/**
 * @returns {Promise<{ upserted: number, totalRows: number, xlsxPath: string|null, skipped: boolean }>}
 */
async function seedCaSerializedSamples(options = {}) {
  const xlsxPath = options.xlsxPath || resolveXlsxPath();
  if (!xlsxPath) {
    console.warn(
      '[seedCaSerialized] 未找到 ca_serialized_pc1.xlsx，跳过（期望路径 data/ca_serialized_pc1.xlsx）'
    );
    return { upserted: 0, totalRows: 0, xlsxPath: null, skipped: true };
  }

  const texts = readRowsFromXlsx(xlsxPath);
  if (!texts.length) {
    console.warn('[seedCaSerialized] Excel 中无有效行:', xlsxPath);
    return { upserted: 0, totalRows: 0, xlsxPath, skipped: true };
  }

  const ops = texts.map((text, i) => {
    const doc = rowToSample(text, i + 1);
    return {
      updateOne: {
        filter: { sampleKey: doc.sampleKey },
        update: { $set: doc },
        upsert: true
      }
    };
  });

  const BATCH = 200;
  let upserted = 0;
  for (let i = 0; i < ops.length; i += BATCH) {
    const chunk = ops.slice(i, i + BATCH);
    const res = await SampleAlert.bulkWrite(chunk, { ordered: false });
    upserted += (res.upsertedCount || 0) + (res.modifiedCount || 0) + (res.matchedCount || 0);
  }

  console.log(
    `[seedCaSerialized] ${xlsxPath} → ${texts.length} 行已写入/更新 samplealerts`
  );
  return { upserted: texts.length, totalRows: texts.length, xlsxPath, skipped: false };
}

async function main() {
  await mongoose.connect(MONGO_URI);
  console.log('Connected:', MONGO_URI);
  await SampleAlert.createCollection().catch(() => {});
  await SampleAlert.collection.createIndex({ sampleKey: 1 }, { unique: true });
  await SampleAlert.collection.createIndex({ sortOrder: 1 });
  const result = await seedCaSerializedSamples();
  console.log(JSON.stringify(result, null, 2));
  await mongoose.disconnect();
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { seedCaSerializedSamples, resolveXlsxPath, readRowsFromXlsx };
