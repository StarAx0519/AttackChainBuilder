const { v4: uuidv4 } = require('uuid');

/**
 * 将已映射告警聚类为若干条攻击链路
 * @param {Array} mappedAlerts mapAlert 的结果数组
 * @param {{windowMs?:number, batchId?:string}} options 关联时间窗，默认 24 小时
 */
function buildAttackChains(mappedAlerts, options = {}) {
  const windowMs = options.windowMs || 24 * 60 * 60 * 1000; // 24h
  const batchId = options.batchId || null;
  // 有步骤号时按步骤顺序；否则按时间；无时间则保持原序
  const sorted = [...(mappedAlerts || [])].sort((a, b) => {
    if (a.stepIndex != null && b.stepIndex != null) return a.stepIndex - b.stepIndex;
    const ta = a.timestamp ? new Date(a.timestamp).getTime() : NaN;
    const tb = b.timestamp ? new Date(b.timestamp).getTime() : NaN;
    if (!Number.isNaN(ta) && !Number.isNaN(tb) && ta !== tb) return ta - tb;
    return 0;
  });

  if (sorted.length === 0) return [];

  const clusters = [];
  let current = [];

  for (const alert of sorted) {
    if (current.length === 0) {
      current.push(alert);
      continue;
    }
    const last = current[current.length - 1];
    const gap = new Date(alert.timestamp) - new Date(last.timestamp);
    const related =
      gap <= windowMs &&
      (sameEntity(alert, last) || gap <= 2 * 60 * 60 * 1000 || sameCampaignHint(alert, last));

    if (related) {
      current.push(alert);
    } else {
      clusters.push(current);
      current = [alert];
    }
  }
  if (current.length) clusters.push(current);

  return clusters.map((cluster, idx) =>
    summarizeChain(cluster, idx, batchId, clusters.length)
  );
}

function sameEntity(a, b) {
  if (a.host && b.host && a.host === b.host) return true;
  if (a.srcIp && b.srcIp && a.srcIp === b.srcIp) return true;
  if (a.dstIp && b.dstIp && a.dstIp === b.dstIp) return true;
  return false;
}

function sameCampaignHint(a, b) {
  const ta = (a.attackType || '').toLowerCase();
  const tb = (b.attackType || '').toLowerCase();
  if (!ta || !tb) return false;
  return ta === tb;
}

/** 生成唯一链路名称：攻击链路（batchId） */
function buildChainName(batchId, index, total) {
  const id = batchId || 'unknown';
  if (total > 1) return `攻击链路（${id}#${index + 1}）`;
  return `攻击链路（${id}）`;
}

/**
 * 汇总单条链路：阶段分组、时长、复杂度、时间线
 * 无明确时序差异时：不编造“持续 N 小时”，改为按攻击步骤展示
 */
function summarizeChain(alerts, index, batchId = null, total = 1) {
  const withTs = alerts.filter((a) => a.timestamp && !Number.isNaN(new Date(a.timestamp).getTime()));
  const distinctTs = new Set(withTs.map((a) => new Date(a.timestamp).getTime()));
  const stepBased =
    alerts.some((a) => a.stepLabel) ||
    alerts.some((a) => a.timePrecision === 'month') ||
    distinctTs.size <= 1;

  let start = null;
  let end = null;
  let durationMs = 0;
  let durationHuman = '无明确时序（按攻击步骤）';
  let timeMode = 'steps';

  if (!stepBased && withTs.length >= 2 && distinctTs.size > 1) {
    start = new Date(Math.min(...withTs.map((a) => new Date(a.timestamp).getTime())));
    end = new Date(Math.max(...withTs.map((a) => new Date(a.timestamp).getTime())));
    durationMs = Math.max(0, end - start);
    durationHuman = formatDuration(durationMs);
    timeMode = 'timeline';
  } else if (withTs.length) {
    start = new Date(withTs[0].timestamp);
    end = start;
    // 仅有年月等粗粒度日期时，展示文中日期，不写假时长
    const disp = alerts.find((a) => a.timeDisplay)?.timeDisplay;
    durationHuman = disp
      ? `事件时间约 ${disp}（无明确时序，按攻击步骤）`
      : '无明确时序（按攻击步骤）';
  }

  // Group by Kill Chain stage — 一条告警可归属多个战术阶段
  const stageMap = {};
  for (const a of alerts) {
    const m = a.mapping || {};
    const tids =
      Array.isArray(m.tacticIds) && m.tacticIds.length
        ? m.tacticIds
        : m.tacticId
          ? [m.tacticId]
          : ['UNKNOWN'];

    for (const key of tids) {
      const tacticMeta =
        (Array.isArray(m.tactics) && m.tactics.find((t) => t.id === key)) || null;
      const order =
        tacticMeta?.order ||
        (key === m.tacticId ? m.killChainOrder : null) ||
        99;
      if (!stageMap[key]) {
        stageMap[key] = {
          tacticId: key,
          tacticName: tacticMeta?.name || m.tacticName || '未知',
          tacticNameEn: tacticMeta?.nameEn || m.tacticNameEn || 'Unknown',
          order,
          alerts: []
        };
      }
      stageMap[key].alerts.push(a);
    }
  }

  const stages = Object.values(stageMap).sort((a, b) => a.order - b.order);
  const coveredTactics = stages.filter((s) => s.tacticId !== 'UNKNOWN').map((s) => s.tacticId);
  const techniques = [
    ...new Set(
      alerts.flatMap((a) => {
        const m = a.mapping || {};
        if (Array.isArray(m.techniques) && m.techniques.length) {
          return m.techniques.map((t) => t.id).filter(Boolean);
        }
        return [m.primary].filter(Boolean);
      })
    )
  ];

  const avgConfidence =
    alerts.reduce((s, a) => s + (a.mapping?.confidence || 0), 0) / alerts.length;

  const complexity = computeComplexity({
    alertCount: alerts.length,
    stageCount: coveredTactics.length,
    techniqueCount: techniques.length,
    durationMs: timeMode === 'timeline' ? durationMs : 0,
    avgConfidence
  });

  return {
    chainId: uuidv4(),
    name: buildChainName(batchId, index, total),
    batchId: batchId || undefined,
    alertCount: alerts.length,
    startTime: start ? start.toISOString() : null,
    endTime: end ? end.toISOString() : null,
    durationMs,
    durationHuman,
    timeMode,
    stages,
    coveredTactics,
    techniques,
    avgConfidence: Number(avgConfidence.toFixed(3)),
    complexityScore: complexity.score,
    complexityLevel: complexity.level,
    complexityDetail: complexity.detail,
    timeline: alerts.map((a, i) => ({
      stepLabel: a.stepLabel || `攻击步骤${i + 1}`,
      stepIndex: a.stepIndex || i + 1,
      timestamp: a.timestamp,
      timeDisplay: a.timeDisplay || null,
      timePrecision: a.timePrecision || null,
      title: a.title,
      attackType: a.attackType,
      technique: a.mapping?.primary,
      techniques: a.mapping?.techniques || null,
      techniqueName: a.mapping?.techniqueName,
      tacticId: a.mapping?.tacticId,
      tacticIds: a.mapping?.tacticIds || null,
      tacticName: a.mapping?.tacticName,
      confidence: a.mapping?.confidence,
      quality: a.mapping?.quality,
      description: a.description || null,
      host: a.host,
      srcIp: a.srcIp,
      dstIp: a.dstIp
    }))
  };
}

/**
 * 复杂度评分（0~100）：阶段广度 + 技术多样性 + 告警量 + 持续时间 + 置信度加成
 * high≥70 / medium≥40 / low
 */
function computeComplexity({ alertCount, stageCount, techniqueCount, durationMs, avgConfidence }) {
  // Weighted score 0-100
  const stageScore = Math.min(40, stageCount * (40 / 14));
  const techScore = Math.min(25, techniqueCount * 3);
  const volumeScore = Math.min(20, alertCount * 2);
  const durationHours = durationMs / 3600000;
  const durationScore = Math.min(10, durationHours * 0.5);
  const confBonus = avgConfidence * 5;
  const score = Math.round(
    Math.min(100, stageScore + techScore + volumeScore + durationScore + confBonus)
  );

  let level = 'low';
  if (score >= 70) level = 'high';
  else if (score >= 40) level = 'medium';

  return {
    score,
    level,
    detail: {
      stageScore: Number(stageScore.toFixed(1)),
      techScore: Number(techScore.toFixed(1)),
      volumeScore: Number(volumeScore.toFixed(1)),
      durationScore: Number(durationScore.toFixed(1)),
      confBonus: Number(confBonus.toFixed(1))
    }
  };
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}秒`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}分${sec % 60}秒`;
  const hour = Math.floor(min / 60);
  if (hour < 24) return `${hour}小时${min % 60}分`;
  const day = Math.floor(hour / 24);
  return `${day}天${hour % 24}小时`;
}

/**
 * ATT&CK tactic coverage matrix from mapped alerts / chains
 */
/**
 * 生成 14 战术覆盖矩阵（前端格子图数据源）
 */
function buildCoverageMatrix(mappedAlerts, killChainOrder) {
  const tacticStats = {};
  for (const t of killChainOrder) {
    tacticStats[t.id] = {
      tacticId: t.id,
      tacticName: t.name,
      tacticNameEn: t.nameEn,
      order: t.order,
      covered: false,
      alertCount: 0,
      techniques: {},
      avgConfidence: 0,
      confSum: 0
    };
  }

  for (const a of mappedAlerts || []) {
    const m = a.mapping || {};
    // 多战术：全部计入覆盖；兼容旧数据仅有 tacticId
    const tids =
      Array.isArray(m.tacticIds) && m.tacticIds.length
        ? m.tacticIds
        : m.tacticId
          ? [m.tacticId]
          : [];
    const techList =
      Array.isArray(m.techniques) && m.techniques.length
        ? m.techniques
        : m.primary
          ? [{ id: m.primary, name: m.techniqueName }]
          : [];

    for (const tid of tids) {
      if (!tid || !tacticStats[tid]) continue;
      const cell = tacticStats[tid];
      cell.covered = true;
      cell.alertCount += 1;
      cell.confSum += m.confidence || 0;
      for (const tech of techList) {
        if (!tech || !tech.id) continue;
        if (!cell.techniques[tech.id]) {
          cell.techniques[tech.id] = {
            id: tech.id,
            name: tech.name || tech.id,
            count: 0,
            maxConfidence: 0
          };
        }
        cell.techniques[tech.id].count += 1;
        cell.techniques[tech.id].maxConfidence = Math.max(
          cell.techniques[tech.id].maxConfidence,
          m.confidence || 0
        );
      }
    }
  }

  const rows = Object.values(tacticStats)
    .sort((a, b) => a.order - b.order)
    .map((r) => {
      const techniques = Object.values(r.techniques);
      return {
        tacticId: r.tacticId,
        tacticName: r.tacticName,
        tacticNameEn: r.tacticNameEn,
        order: r.order,
        covered: r.covered,
        alertCount: r.alertCount,
        avgConfidence: r.alertCount
          ? Number((r.confSum / r.alertCount).toFixed(3))
          : 0,
        techniques
      };
    });

  const coveredCount = rows.filter((r) => r.covered).length;
  const total = rows.length;

  return {
    totalTactics: total,
    coveredTactics: coveredCount,
    coverageRate: total ? Number((coveredCount / total).toFixed(4)) : 0,
    matrix: rows
  };
}

/**
 * 计算顶部四项统计
 * 映射准确率 ≈ excellent/good 质量占比（原型可解释口径）
 */
function computeStats(mappedAlerts, chains, coverage) {
  const total = mappedAlerts.length;
  const mapped = mappedAlerts.filter(
    (a) => a.mapping && a.mapping.method !== 'fallback'
  ).length;
  const excellentOrGood = mappedAlerts.filter(
    (a) => a.mapping && ['excellent', 'good'].includes(a.mapping.quality)
  ).length;
  const accuracy = total ? excellentOrGood / total : 0;
  const avgConfidence = total
    ? mappedAlerts.reduce((s, a) => s + (a.mapping?.confidence || 0), 0) / total
    : 0;

  return {
    mappedAlertCount: mapped,
    totalAlertCount: total,
    mappingAccuracy: Number(accuracy.toFixed(4)),
    mappingAccuracyPercent: `${(accuracy * 100).toFixed(1)}%`,
    avgConfidence: Number(avgConfidence.toFixed(3)),
    attackChainCount: (chains || []).length,
    tacticCoverage: coverage ? coverage.coverageRate : 0,
    tacticCoveragePercent: coverage
      ? `${(coverage.coverageRate * 100).toFixed(1)}%`
      : '0%',
    coveredTactics: coverage ? coverage.coveredTactics : 0,
    totalTactics: coverage ? coverage.totalTactics : 14
  };
}

module.exports = {
  buildAttackChains,
  buildCoverageMatrix,
  computeStats,
  formatDuration
};
