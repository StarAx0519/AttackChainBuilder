const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');
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
const XLSX_PATH = path.join(ROOT, 'data', 'ca_serialized_pc1.xlsx');
const SAMPLE_PATH = path.join(ROOT, 'data', 'sample_alerts.json');
const APT_PATH = path.join(ROOT, 'data', 'aptexample.json');
const OUT_DIR = path.join(ROOT, 'docs', 'icassp2027');
const OUT_JSON = path.join(OUT_DIR, 'results.json');

const NIGHT_DRAGON = {
  title: '案例-夜龙 APT 攻击',
  text:
    '背景：夜龙 APT 攻击是 McAfee 在2011年2月份发现并命名的针对全球主要能源公司的攻击行为。该多步攻击的分析过程如下：第一步：研究目标。主要针对的是国际知名的能源公司。第二步：拿下第一目标主机，打开局面。黑客为了侵入内网，使用由外到内的策略。虽然内网往往不与internet有接触，但是对于每个公司的web服务器来说，它具有的一个特点就是：既与内网连接，又与外网连接。所以，黑客选中了这些公司的web服务器作为第一目标主机。对外网主机如Web服务器进行攻击，黑客采用的是SQL注入攻击，并顺利拿下了web服务器。第三步：通过横向移动。拿下具有高级权限的敏感主机黑客以被黑的Web服务器被作为跳板，对内网的其他服务器或PC进行扫描，使用弱口令对内网机器如AD服务器或开发人员电脑进行攻击，拿下敏感主机。被黑机器被植入恶意代码，并被安装远端控制工具（RAT）。第四步：构建虚拟隧道。并禁用掉被黑机器IE的代理设置，建立起直连的通道。第五步：卷货撤退   传回大量机敏文件（WORD、PPT、PDF等等），包括所有会议记录与组织人事架构图。'
};

function pct(n, d) {
  if (!d) return 0;
  return Number(((100 * n) / d).toFixed(1));
}

function summarizeMapped(mapped, chains, coverage) {
  const total = mapped.length;
  const byMethod = { explicit: 0, rule: 0, heuristic: 0, fallback: 0, none: 0 };
  let eg = 0;
  let confSum = 0;
  for (const a of mapped) {
    const m = a.mapping || {};
    const method = m.method || 'none';
    byMethod[method] = (byMethod[method] || 0) + 1;
    if (['excellent', 'good'].includes(m.quality)) eg += 1;
    confSum += m.confidence || 0;
  }
  const nonFb = total - (byMethod.fallback || 0) - (byMethod.none || 0);
  const stats = computeStats(mapped, chains, coverage);
  const avgComplex =
    chains && chains.length
      ? Number(
          (
            chains.reduce((s, c) => s + (c.complexityScore || 0), 0) / chains.length
          ).toFixed(1)
        )
      : 0;
  return {
    alerts: total,
    nonFallbackPct: pct(nonFb, total),
    proxyQualityPct: pct(eg, total),
    avgConfidence: total ? Number((confSum / total).toFixed(3)) : 0,
    coveragePct: coverage ? pct(coverage.coveredTactics, coverage.totalTactics) : 0,
    coveredTactics: coverage ? coverage.coveredTactics : 0,
    chains: (chains || []).length,
    avgComplexity: avgComplex,
    methodMix: byMethod,
    mappingAccuracyPercent: stats.mappingAccuracyPercent
  };
}

function runPipeline(alerts, attck, mapOpts = {}, windowMs = 24 * 3600 * 1000) {
  const mapped = mapAlertsBatch(alerts, attck, mapOpts);
  const chains = buildAttackChains(mapped, { windowMs });
  const coverage = buildCoverageMatrix(mapped, attck.killChainOrder);
  return { mapped, chains, coverage, summary: summarizeMapped(mapped, chains, coverage) };
}

function readXlsxCampaigns(limit = null) {
  const wb = XLSX.readFile(XLSX_PATH, { raw: false });
  const sheet = wb.Sheets[wb.SheetNames[0]];
  const matrix = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '', raw: false });
  const campaigns = [];
  for (const row of matrix) {
    if (!row || !row.length) continue;
    const cell = String(row[0] || '').trim();
    if (!cell || cell.length < 20) continue;
    campaigns.push(cell);
    if (limit && campaigns.length >= limit) break;
  }
  return campaigns;
}

function evaluateIdsCorpus(attck, campaigns) {
  const configs = {
    full: {},
    noRule: { enableRule: false },
    noHeuristic: { enableHeuristic: false },
    noExplicit: { enableExplicit: false },
    heuristicOnly: { enableExplicit: false, enableRule: false },
    fallbackOnly: {
      enableExplicit: false,
      enableRule: false,
      enableHeuristic: false
    }
  };

  const agg = {};
  for (const key of Object.keys(configs)) {
    agg[key] = {
      alerts: 0,
      nonFb: 0,
      eg: 0,
      confSum: 0,
      coveredSet: new Set(),
      chainCount: 0,
      complexSum: 0,
      complexN: 0,
      methods: { explicit: 0, rule: 0, heuristic: 0, fallback: 0, none: 0 }
    };
  }

  const windowStudy = { '2h': [], '24h': [], infinite: [] };
  let campaignIdx = 0;

  for (const text of campaigns) {
    let alerts;
    try {
      alerts = parseAlertsFromText(text);
    } catch (e) {
      continue;
    }
    if (!alerts || !alerts.length) continue;
    campaignIdx += 1;

    for (const [key, opts] of Object.entries(configs)) {
      const { mapped, chains, coverage } = runPipeline(alerts, attck, opts);
      const a = agg[key];
      a.alerts += mapped.length;
      for (const m of mapped) {
        const method = m.mapping?.method || 'none';
        a.methods[method] = (a.methods[method] || 0) + 1;
        if (method !== 'fallback' && method !== 'none') a.nonFb += 1;
        if (['excellent', 'good'].includes(m.mapping?.quality)) a.eg += 1;
        a.confSum += m.mapping?.confidence || 0;
      }
      for (const row of coverage.matrix || []) {
        if (row.covered) a.coveredSet.add(row.tacticId);
      }
      a.chainCount += chains.length;
      for (const c of chains) {
        a.complexSum += c.complexityScore || 0;
        a.complexN += 1;
      }
    }

    // window study on full mapping only
    const fullMapped = mapAlertsBatch(alerts, attck, {});
    for (const [label, ms] of [
      ['2h', 2 * 3600 * 1000],
      ['24h', 24 * 3600 * 1000],
      ['infinite', 3650 * 24 * 3600 * 1000]
    ]) {
      const chains = buildAttackChains(fullMapped, { windowMs: ms });
      windowStudy[label].push(chains.length);
    }
  }

  const table = {};
  for (const [key, a] of Object.entries(agg)) {
    table[key] = {
      campaigns: campaignIdx,
      alerts: a.alerts,
      nonFallbackPct: pct(a.nonFb, a.alerts),
      proxyQualityPct: pct(a.eg, a.alerts),
      avgConfidence: a.alerts ? Number((a.confSum / a.alerts).toFixed(3)) : 0,
      unionCoveragePct: pct(a.coveredSet.size, 14),
      unionCoveredTactics: a.coveredSet.size,
      avgChainsPerCampaign: campaignIdx
        ? Number((a.chainCount / campaignIdx).toFixed(2))
        : 0,
      avgComplexity: a.complexN
        ? Number((a.complexSum / a.complexN).toFixed(1))
        : 0,
      methodMixPct: {
        explicit: pct(a.methods.explicit, a.alerts),
        rule: pct(a.methods.rule, a.alerts),
        heuristic: pct(a.methods.heuristic, a.alerts),
        fallback: pct(a.methods.fallback + a.methods.none, a.alerts)
      }
    };
  }

  const windowSummary = {};
  for (const [k, arr] of Object.entries(windowStudy)) {
    const sum = arr.reduce((s, x) => s + x, 0);
    windowSummary[k] = {
      avgChains: arr.length ? Number((sum / arr.length).toFixed(2)) : 0,
      multiChainCampaigns: arr.filter((n) => n > 1).length,
      multiChainPct: pct(arr.filter((n) => n > 1).length, arr.length)
    };
  }

  return { campaigns: campaignIdx, ablation: table, windowStudy: windowSummary };
}

function evaluateStructured(attck) {
  const alerts = JSON.parse(fs.readFileSync(SAMPLE_PATH, 'utf8'));
  return runPipeline(alerts, attck, {}).summary;
}

function evaluateNarrative(attck) {
  const apt = JSON.parse(fs.readFileSync(APT_PATH, 'utf8'));
  const withIds = Array.isArray(apt) ? apt[0] : apt;
  const goldTechs = extractExplicitTechniqueIds(withIds.text || '');
  // normalize base technique (drop subtech)
  const goldBase = [...new Set(goldTechs.map((t) => t.split('.')[0]))];

  const expandOn = runPipeline([withIds], attck, { expandNarrative: true });
  const expandOff = runPipeline([withIds], attck, { expandNarrative: false });

  const predTechs = [
    ...new Set(
      expandOn.mapped
        .map((a) => (a.mapping?.primary || '').split('.')[0])
        .filter(Boolean)
    )
  ];
  const hit = goldBase.filter((g) => predTechs.includes(g)).length;
  const techRecall = goldBase.length ? pct(hit, goldBase.length) : 0;

  const nightOn = runPipeline([NIGHT_DRAGON], attck, { expandNarrative: true });
  const nightOff = runPipeline([NIGHT_DRAGON], attck, { expandNarrative: false });

  return {
    lazarus: {
      goldTechniques: goldBase,
      expandOn: {
        ...expandOn.summary,
        steps: expandOn.mapped.length,
        techRecallVsExplicitIds: techRecall,
        predictedPrimary: predTechs
      },
      expandOff: {
        ...expandOff.summary,
        steps: expandOff.mapped.length
      }
    },
    nightDragon: {
      expandOn: { ...nightOn.summary, steps: nightOn.mapped.length },
      expandOff: { ...nightOff.summary, steps: nightOff.mapped.length }
    }
  };
}

function main() {
  console.log('Loading ATT&CK…');
  const attck = loadAttckData(ATTCK_PATH);
  console.log(
    `tactics=${attck.killChainOrder.length} techniques=${Object.keys(attck.techniqueById || {}).length}`
  );

  console.log('Evaluating structured sample…');
  const structured = evaluateStructured(attck);

  console.log('Evaluating narratives…');
  const narrative = evaluateNarrative(attck);

  console.log('Reading IDS campaigns from xlsx…');
  const campaigns = readXlsxCampaigns(null);
  console.log(`campaigns=${campaigns.length}; running ablations (may take a minute)…`);
  const ids = evaluateIdsCorpus(attck, campaigns);

  const results = {
    generatedAt: new Date().toISOString(),
    attck: {
      tactics: attck.killChainOrder.length,
      techniques: Object.keys(attck.techniqueById || {}).length
    },
    structuredSample: structured,
    narrative,
    idsCorpus: ids
  };

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_JSON, JSON.stringify(results, null, 2), 'utf8');
  console.log('Wrote', OUT_JSON);
  console.log(JSON.stringify(ids.ablation.full, null, 2));
  console.log('window', ids.windowStudy);
  console.log('narrative', JSON.stringify(narrative, null, 2));
}

main();
