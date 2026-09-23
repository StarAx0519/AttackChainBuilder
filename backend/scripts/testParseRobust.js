/**
 * 快速校验：尾逗号等瑕疵不应改变解析条数
 * 运行：node scripts/testParseRobust.js
 */
const { parseLooseAlertText, repairJsonish } = require('../src/alertNormalize');
const { parseAlertsFromText } = require('../src/inputParse');
const { resolvePersistBatchId, classifyPersistKind } = require('../src/contentHash');

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exitCode = 1;
  } else {
    console.log('OK:', msg);
  }
}

const clean = '[{"title":"t1","attackType":"扫描"},{"title":"t2","attackType":"爆破"}]';
const trailing = '[{"title":"t1","attackType":"扫描"},{"title":"t2","attackType":"爆破"},]';
const trailingObj =
  '[{"title":"t1","attackType":"扫描",},{"title":"t2","attackType":"爆破",},]';
const withComment =
  '[\n  // sample\n  {"title":"t1","attackType":"扫描"},\n  {"title":"t2","attackType":"爆破",}\n]';
const smartQuotes = '[{"title":“t1”,“attackType”:“扫描”}]';

const a = parseAlertsFromText(clean);
const b = parseAlertsFromText(trailing);
const c = parseAlertsFromText(trailingObj);
const d = parseAlertsFromText(withComment);
const e = parseAlertsFromText(smartQuotes);

assert(a.length === 2, `clean length=${a.length}`);
assert(b.length === 2, `trailing array comma length=${b.length}`);
assert(c.length === 2, `trailing object commas length=${c.length}`);
assert(d.length === 2, `comments+trailing length=${d.length}`);
assert(e.length === 1, `smart quotes length=${e.length}`);
assert(a[0].title === b[0].title && a[1].title === b[1].title, 'clean vs trailing titles match');
assert(parseLooseAlertText(trailing).length === 2, 'loose trailing');
assert(repairJsonish(trailing).includes('}]') || repairJsonish(trailing).endsWith(']'), 'repair removes trailing');

assert(resolvePersistBatchId('all_new', 'S', [], 'NEW') === 'NEW', 'all_new uses new id');
assert(resolvePersistBatchId('partial', 'S', [{ batchId: 'OLD' }], 'NEW') === 'NEW', 'partial uses new id');
assert(
  resolvePersistBatchId('all_exist', 'S', [
    { batchId: 'A' },
    { batchId: 'A' },
    { batchId: 'B' }
  ], 'NEW') === 'A',
  'all_exist majority batch'
);
assert(classifyPersistKind(3, 0) === 'all_new', 'kind all_new');
assert(classifyPersistKind(3, 3) === 'all_exist', 'kind all_exist');
assert(classifyPersistKind(3, 1) === 'partial', 'kind partial');

if (!process.exitCode) console.log('\nAll parse/batchId checks passed.');
