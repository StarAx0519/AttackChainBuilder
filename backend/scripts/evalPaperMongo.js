const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { SampleAlert } = require('../src/models');
const { loadAttckData } = require('../src/attckParser');
const { parseAlertsFromText } = require('../src/inputParse');
const { mapAlertsBatch, extractExplicitTechniqueIds } = require('../src/mapper');
const {
  buildAttackChains,
  buildCoverageMatrix,
  computeStats
} = require('../src/chainBuilder');

const ROOT = path.join(__dirname, '..', '..');
const ATTCK_PATH = path.join(ROOT, 'data', 'ATTCK.json');
const OUT = path.join(ROOT, 'docs', 'icassp2027', 'results_mongo.json');
const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/qy_attack_chain';

function pct(n, d) {
  return d ? Number(((100 * n) / d).toFixed(1)) : 0;
}

function runOne(alerts, attck, mapOpts = {}, windowMs = 24 * 3600 * 1000) {
  const mapped = mapAlertsBatch(alerts, attck, mapOpts);
  const chains = buildAttackChains(mapped, { windowMs });
  const coverage = buildCoverageMatrix(mapped, attck.killChainOrder);
  const stats = computeStats(mapped, chains, coverage);
  const methods = { explicit: 0, rule: 0, heuristic: 0, fallback: 0, none: 0 };
  let eg = 0;
  let conf = 0;
  const techSet = new Set();
  const tacticSet = new Set();
  for (const a of mapped) {
    const m = a.mapping || {};
    methods[m.method || 'none'] = (methods[m.method || 'none'] || 0) + 1;
    if (['excellent', 'good'].includes(m.quality)) eg += 1;
    conf += m.confidence || 0;
    if (m.primary) techSet.add(String(m.primary).split('.')[0]);
    for (const t of m.tacticIds || (m.tacticId ? [m.tacticId] : [])) tacticSet.add(t);
  }
  const total = mapped.length;
  const nonFb = (methods.explicit || 0) + (methods.rule || 0) + (methods.heuristic || 0);
  const avgC =
    chains.length
      ? chains.reduce((s, c) => s + (c.complexityScore || 0), 0) / chains.length
      : 0;
  return {
    alerts: total,
    chains: chains.length,
    nonFallback: nonFb,
    excellentGood: eg,
    nonFallbackPct: pct(nonFb, total),
    proxyQualityPct: pct(eg, total),
    avgConfidence: total ? Number((conf / total).toFixed(3)) : 0,
    coveragePct: pct(coverage.coveredTactics, coverage.totalTactics),
    coveredTactics: coverage.coveredTactics,
    uniqueTechs: techSet.size,
    uniqueTactics: tacticSet.size,
    avgComplexity: Number(avgC.toFixed(1)),
    methods,
    methodPct: {
      explicit: pct(methods.explicit, total),
      rule: pct(methods.rule, total),
      heuristic: pct(methods.heuristic, total),
      fallback: pct((methods.fallback || 0) + (methods.none || 0), total)
    },
    mappingAccuracyPercent: stats.mappingAccuracyPercent,
    multiTacticAlerts: mapped.filter(
      (a) => (a.mapping?.tacticIds || []).length > 1
    ).length,
    mapped
  };
}

function parseSample(doc) {
  const fmt = doc.format || '';
  const content = doc.content;
  if (fmt === 'narrative' || (content && typeof content === 'object' && content.text)) {
    const obj =
      typeof content === 'string'
        ? (() => {
            try {
              return JSON.parse(content);
            } catch {
              return { title: doc.name, text: content };
            }
          })()
        : content;
    if (Array.isArray(obj)) return obj;
    return [obj];
  }
  if (typeof content === 'string') {
    try {
      return parseAlertsFromText(content);
    } catch {
      return [];
    }
  }
  if (Array.isArray(content)) return content;
  return [];
}

async function main() {
  const attck = loadAttckData(ATTCK_PATH);
  await mongoose.connect(MONGO);
  const docsAll = await SampleAlert.find({}).lean();
  // Paper experiment: only IDS python-list campaigns (exclude json demo + narrative)
  const docs = docsAll.filter(
    (d) =>
      d.format === 'python-list' ||
      String(d.sampleKey || '').startsWith('ca-pc1')
  );
  const byFormat = {};
  for (const d of docs) {
    const f = d.format || 'unknown';
    byFormat[f] = (byFormat[f] || 0) + 1;
  }

  const configs = {
    full: {},
    noRule: { enableRule: false },
    noHeuristic: { enableHeuristic: false },
    heuristicOnly: { enableExplicit: false, enableRule: false },
    fallbackOnly: {
      enableExplicit: false,
      enableRule: false,
      enableHeuristic: false
    },
    noExpand: { expandNarrative: false }
  };

  // Aggregate over all samplealerts documents (each doc = one campaign / narrative)
  const agg = {};
  for (const k of Object.keys(configs)) {
    agg[k] = {
      docs: 0,
      alerts: 0,
      nonFb: 0,
      eg: 0,
      conf: 0,
      chains: 0,
      complex: 0,
      complexN: 0,
      unionTac: new Set(),
      unionTech: new Set(),
      methods: { explicit: 0, rule: 0, heuristic: 0, fallback: 0, none: 0 },
      multiTactic: 0,
      perDocCoverage: [],
      failed: 0
    };
  }

  const windowAgg = {
    '2h': { chains: 0, multi: 0, n: 0 },
    '24h': { chains: 0, multi: 0, n: 0 },
    inf: { chains: 0, multi: 0, n: 0 }
  };

  let narrativeDocs = 0;
  let caDocs = 0;
  let otherDocs = 0;
  const narrativeDetail = [];

  for (const doc of docs) {
    let alerts;
    try {
      alerts = parseSample(doc);
    } catch {
      for (const a of Object.values(agg)) a.failed += 1;
      continue;
    }
    if (!alerts || !alerts.length) {
      for (const a of Object.values(agg)) a.failed += 1;
      continue;
    }

    const isNarr =
      doc.format === 'narrative' ||
      (alerts.length === 1 &&
        (alerts[0].text || '').length > 200 &&
        !alerts[0].attackType);
    if (isNarr) narrativeDocs += 1;
    else if (String(doc.sampleKey || '').startsWith('ca-pc1')) caDocs += 1;
    else otherDocs += 1;

    for (const [key, opts] of Object.entries(configs)) {
      const r = runOne(alerts, attck, opts);
      const a = agg[key];
      a.docs += 1;
      a.alerts += r.alerts;
      a.nonFb += r.nonFallback;
      a.eg += r.excellentGood;
      a.conf += r.avgConfidence * r.alerts;
      a.chains += r.chains;
      a.complex += r.avgComplexity * Math.max(1, r.chains);
      a.complexN += Math.max(1, r.chains);
      a.multiTactic += r.multiTacticAlerts;
      a.perDocCoverage.push(r.coveredTactics);
      for (const [m, c] of Object.entries(r.methods)) {
        a.methods[m] = (a.methods[m] || 0) + c;
      }
      for (const x of r.mapped) {
        if (x.mapping?.primary) a.unionTech.add(String(x.mapping.primary).split('.')[0]);
        for (const t of x.mapping?.tacticIds || []) a.unionTac.add(t);
      }
    }

    // window on full
    const mapped = mapAlertsBatch(alerts, attck, {});
    for (const [lab, ms] of [
      ['2h', 2 * 3600 * 1000],
      ['24h', 24 * 3600 * 1000],
      ['inf', 3650 * 24 * 3600 * 1000]
    ]) {
      const ch = buildAttackChains(mapped, { windowMs: ms });
      windowAgg[lab].n += 1;
      windowAgg[lab].chains += ch.length;
      if (ch.length > 1) windowAgg[lab].multi += 1;
    }

    if (isNarr || doc.format === 'narrative') {
      const on = runOne(alerts, attck, { expandNarrative: true });
      const off = runOne(alerts, attck, { expandNarrative: false });
      const text = alerts.map((a) => a.text || a.description || '').join(' ');
      const gold = extractExplicitTechniqueIds(text).map((t) => t.split('.')[0]);
      const goldU = [...new Set(gold)];
      const pred = [
        ...new Set(
          mapAlertsBatch(alerts, attck, { expandNarrative: true })
            .map((a) => (a.mapping?.primary || '').split('.')[0])
            .filter(Boolean)
        )
      ];
      const hit = goldU.filter((g) => pred.includes(g)).length;
      narrativeDetail.push({
        sampleKey: doc.sampleKey,
        name: doc.name,
        goldTechs: goldU,
        techRecall: goldU.length ? pct(hit, goldU.length) : null,
        expandOn: on,
        expandOff: off
      });
    }
  }

  function finalize(a) {
    return {
      docs: a.docs,
      alerts: a.alerts,
      nonFallbackPct: pct(a.nonFb, a.alerts),
      proxyQualityPct: pct(a.eg, a.alerts),
      avgConfidence: a.alerts ? Number((a.conf / a.alerts).toFixed(3)) : 0,
      avgChainsPerDoc: a.docs ? Number((a.chains / a.docs).toFixed(2)) : 0,
      avgComplexity: a.complexN ? Number((a.complex / a.complexN).toFixed(1)) : 0,
      unionTactics: a.unionTac.size,
      unionTechs: a.unionTech.size,
      unionCoveragePct: pct(a.unionTac.size, 14),
      meanDocCoverage: a.perDocCoverage.length
        ? Number(
            (
              a.perDocCoverage.reduce((s, x) => s + x, 0) / a.perDocCoverage.length
            ).toFixed(2)
          )
        : 0,
      multiTacticAlertPct: pct(a.multiTactic, a.alerts),
      methodPct: {
        explicit: pct(a.methods.explicit, a.alerts),
        rule: pct(a.methods.rule, a.alerts),
        heuristic: pct(a.methods.heuristic, a.alerts),
        fallback: pct((a.methods.fallback || 0) + (a.methods.none || 0), a.alerts)
      },
      failed: a.failed
    };
  }

  const out = {
    generatedAt: new Date().toISOString(),
    mongo: MONGO,
    samplealerts: {
      documents: docs.length,
      byFormat,
      caDocs,
      narrativeDocs,
      otherDocs
    },
    ablation: Object.fromEntries(
      Object.entries(agg).map(([k, v]) => [k, finalize(v)])
    ),
    window: Object.fromEntries(
      Object.entries(windowAgg).map(([k, v]) => [
        k,
        {
          avgChains: v.n ? Number((v.chains / v.n).toFixed(2)) : 0,
          multiChainPct: pct(v.multi, v.n)
        }
      ])
    ),
    narratives: narrativeDetail,
    metricRationale: {
      nonFallbackPct:
        'Shows hierarchical layers actually assign techniques vs L4 dump',
      methodMix:
        'Attributes gains to L1/L2/L3 — core claim of auditable hierarchy',
      layerAblationDelta: 'Quantifies necessity of rule vs heuristic layers',
      unionAndMeanCoverage:
        'Union = pack reach; mean doc coverage = typical campaign breadth',
      expandStepsAndCoverage:
        'Direct evidence for LLM-free narrative stepping',
      windowMultiChainPct:
        'Evidence for multi-activity separation under incomplete evidence',
      avgComplexity: 'Inspectable quantification of reconstructed activity',
      techRecallOnExplicitNarrative:
        'Grounded check when IDs are written in text'
    }
  };

  fs.writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(JSON.stringify({
    docs: docs.length,
    byFormat,
    full: out.ablation.full,
    noRule: out.ablation.noRule,
    noHeuristic: out.ablation.noHeuristic,
    fallbackOnly: out.ablation.fallbackOnly,
    noExpand: out.ablation.noExpand,
    window: out.window,
    narratives: narrativeDetail.map((n) => ({
      key: n.sampleKey,
      onSteps: n.expandOn.alerts,
      offSteps: n.expandOff.alerts,
      onCov: n.expandOn.coveredTactics,
      offCov: n.expandOff.coveredTactics,
      recall: n.techRecall
    }))
  }, null, 2));
  await mongoose.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
