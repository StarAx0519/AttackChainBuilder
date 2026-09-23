/**
 * =============================================================================
 * routes.js — HTTP API 路由层
 * =============================================================================
 *
 * 【接口一览】
 *   GET  /health           健康检查 + 知识库规模 + mongo 是否可用
 *   GET  /attck/tactics    战术/技术字典（前端画空矩阵用）
 *   GET  /mapping/rules    导出攻击类型规则表
 *   POST /mapping/batch    批量映射（仅内存计算，不落库）
 *   POST /chains/build     基于已映射结果构建攻击链路（仅内存，不落库）
 *   POST /pipeline         映射 + 构建一步完成（仅内存，不落库）
 *   POST /persist          用户确认后手动入库（alerts | chains | stats 三表分立）
 *   GET  /stats            最近/指定批次统计
 *   GET  /stats/cumulative 库内累计：mappedalerts / attackchains 条数（顶部统计栏）
 *   GET  /chains           查询已落库链路
 *   GET  /samples          列表示例告警（samplealerts 集合）
 *   GET  /samples/:id      获取单条示例完整内容
 *
 * 【输入解析】
 *   multer 接收 multipart 文件；也支持 JSON body.text / body.alerts
 *   文本可为：JSON/NDJSON/CSV/TSV/XML/CEF/LEEF/KV/叙述型 {title,text} 等
 *   叙述型案例（含无 T/TA 编号的中文多步 APT）由 mapper/narrativeExpand 拆条
 *
 * 【Mongo 落库（手动确认）】
 *   映射/构链接口只返回 JSON，不写库。
 *   前端点「存入」后调用 POST /persist；成功/失败由接口明确返回。
 * =============================================================================
 */

const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { mapAlertsBatch } = require('./mapper');
const {
  buildAttackChains,
  buildCoverageMatrix,
  computeStats
} = require('./chainBuilder');
const { MappedAlert, AttackChain, SessionStats, SampleAlert } = require('./models');
const { normalizeAlertList } = require('./alertNormalize');
const {
  hashAlertsInput,
  hashMappedAlerts,
  hashChains,
  itemHashMappedAlert,
  itemHashChain,
  classifyPersistKind,
  resolvePersistBatchId,
  userPersistMessage,
  userPersistTitle
} = require('./contentHash');
const { parseAlertsFromText } = require('./inputParse');

/** Mongo 是否已连接（readyState: 1=connected） */
function isMongoReady() {
  return mongoose.connection.readyState === 1;
}
/** 上传文件只放内存 buffer，不写磁盘（原型够用） */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

/** 统一从请求体 / 上传文件中抽出告警数组 */
function parseAlertsInput(body, file) {
  let alerts = [];
  const bodyText = body && body.text != null ? String(body.text).trim() : '';

  // 文本优先：前端粘贴内容后若仍带上旧文件，应分析文本而非文件
  if (body.alerts) {
    if (typeof body.alerts === 'string') {
      alerts = parseAlertsFromText(body.alerts);
    } else if (Array.isArray(body.alerts)) {
      alerts = normalizeAlertList(body.alerts);
    }
  } else if (bodyText) {
    alerts = parseAlertsFromText(bodyText);
  } else if (file && file.buffer) {
    const text = file.buffer.toString('utf8').trim();
    alerts = parseAlertsFromText(text);
  }

  return alerts;
}

/**
 * 解析文本为告警列表（兼容旧调用）
 */
function parseTextToAlerts(text) {
  return parseAlertsFromText(text);
}

/**
 * 对照库内 itemHash，决定本批映射结果的 persistKind 与 batchId
 * all_exist → 复用原批次；否则 → 新 batchId
 */
async function classifyMappedBatch(mapped) {
  const prepared = (mapped || []).map((m) => {
    const itemHash = m.itemHash || itemHashMappedAlert(m);
    return { ...m, itemHash };
  });
  const itemHashes = [...new Set(prepared.map((d) => d.itemHash))];
  let existingDocs = [];
  if (isMongoReady() && itemHashes.length) {
    existingDocs = await MappedAlert.find({ itemHash: { $in: itemHashes } })
      .select('itemHash batchId')
      .lean();
  }
  const existingSet = new Set(existingDocs.map((d) => d.itemHash));
  const existedCount = itemHashes.filter((h) => existingSet.has(h)).length;
  const addedCount = itemHashes.length - existedCount;
  const persistKind = classifyPersistKind(itemHashes.length, existedCount);
  const freshId = uuidv4();
  const batchId = resolvePersistBatchId(persistKind, freshId, existingDocs, freshId);
  return {
    prepared,
    itemHashes,
    existingDocs,
    existedCount,
    addedCount,
    persistKind,
    batchId
  };
}

async function classifyChainsBatch(chains) {
  const prepared = (chains || []).map((c) => {
    const itemHash = c.itemHash || itemHashChain(c);
    return { ...c, itemHash };
  });
  const itemHashes = [...new Set(prepared.map((d) => d.itemHash))];
  let existingDocs = [];
  if (isMongoReady() && itemHashes.length) {
    existingDocs = await AttackChain.find({ itemHash: { $in: itemHashes } })
      .select('itemHash batchId')
      .lean();
  }
  const existingSet = new Set(existingDocs.map((d) => d.itemHash));
  const existedCount = itemHashes.filter((h) => existingSet.has(h)).length;
  const addedCount = itemHashes.length - existedCount;
  const persistKind = classifyPersistKind(itemHashes.length, existedCount);
  const freshId = uuidv4();
  const batchId = resolvePersistBatchId(persistKind, freshId, existingDocs, freshId);
  return {
    prepared,
    itemHashes,
    existingDocs,
    existedCount,
    addedCount,
    persistKind,
    batchId
  };
}

function createRouter(attck) {
  const router = express.Router();

  /** Health */
  router.get('/health', (req, res) => {
    res.json({
      ok: true,
      tactics: attck.tactics.length,
      techniques: attck.techniques.length,
      mongo: isMongoReady()
    });
  });

  /** ATT&CK reference */
  router.get('/attck/tactics', (req, res) => {
    res.json({ tactics: attck.killChainOrder, techniques: attck.techniques });
  });

  /** Mapping rules listing */
  router.get('/mapping/rules', (req, res) => {
    const { ATTACK_TYPE_RULES, QUALITY_LEVELS } = require('./mapper');
    res.json({ rules: ATTACK_TYPE_RULES, qualityLevels: QUALITY_LEVELS });
  });

  /** Batch map */
  router.post('/mapping/batch', upload.single('file'), async (req, res) => {
    try {
      const alerts = parseAlertsInput(req.body, req.file);
      if (!alerts.length) {
        return res.status(400).json({
          error: '未解析到告警数据，请上传 JSON/CSV 或在文本框中输入告警'
        });
      }

      const contentHash = hashAlertsInput(alerts);
      const mappedRaw = mapAlertsBatch(alerts, attck);
      const classified = await classifyMappedBatch(
        mappedRaw.map((m) => ({ ...m, contentHash }))
      );
      const batchId = classified.batchId;
      const mapped = classified.prepared.map((m) => ({
        ...m,
        batchId,
        contentHash
      }));
      const coverage = buildCoverageMatrix(mapped, attck.killChainOrder);
      const stats = computeStats(mapped, [], coverage);

      // 仅返回计算结果，不落库；入库请前端调用 POST /persist
      res.json({
        batchId,
        contentHash,
        mapped,
        stats,
        coverage,
        persistKind: classified.persistKind,
        existed: classified.existedCount,
        added: classified.addedCount,
        persisted: false
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  });

  /** Build attack chains from a batch (or provided mapped alerts) */
  router.post('/chains/build', async (req, res) => {
    try {
      let mapped = req.body.mapped || [];
      const batchId = req.body.batchId || uuidv4();

      if ((!mapped || !mapped.length) && req.body.batchId) {
        const docs = await MappedAlert.find({ batchId: req.body.batchId }).lean();
        mapped = docs;
      }

      if (!mapped.length) {
        return res.status(400).json({ error: '没有可用于构建链路的已映射告警' });
      }

      // Ensure mapping objects exist
      mapped = mapped.map((m) => {
        if (m.mapping) return m;
        return mapAlertsBatch([m], attck)[0];
      });

      const chains = buildAttackChains(mapped, {
        windowMs: req.body.windowMs || 24 * 60 * 60 * 1000,
        batchId
      });
      const contentHash =
        req.body.contentHash ||
        (mapped[0] && mapped[0].contentHash) ||
        null;
      const chainsOut = chains.map((c) => ({
        ...c,
        batchId,
        ...(contentHash ? { contentHash } : {})
      }));
      const coverage = buildCoverageMatrix(mapped, attck.killChainOrder);
      const stats = computeStats(mapped, chainsOut, coverage);

      // 仅返回计算结果，不落库
      res.json({
        batchId,
        contentHash,
        chains: chainsOut,
        stats,
        coverage,
        persisted: false
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  });

  /** Combined: map + build in one call */
  router.post('/pipeline', upload.single('file'), async (req, res) => {
    try {
      const alerts = parseAlertsInput(req.body, req.file);
      if (!alerts.length) {
        return res.status(400).json({ error: '未解析到告警数据' });
      }
      const contentHash = hashAlertsInput(alerts);
      const mappedRaw = mapAlertsBatch(alerts, attck);
      const classified = await classifyMappedBatch(
        mappedRaw.map((m) => ({ ...m, contentHash }))
      );
      const batchId = classified.batchId;
      const mapped = classified.prepared.map((m) => ({
        ...m,
        batchId,
        contentHash
      }));
      const chains = buildAttackChains(mapped, { batchId }).map((c) => ({
        ...c,
        contentHash,
        batchId
      }));
      const coverage = buildCoverageMatrix(mapped, attck.killChainOrder);
      const stats = computeStats(mapped, chains, coverage);

      // 仅返回计算结果，不落库
      res.json({
        batchId,
        contentHash,
        mapped,
        chains,
        stats,
        coverage,
        persistKind: classified.persistKind,
        existed: classified.existedCount,
        added: classified.addedCount,
        persisted: false
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * 手动入库（用户确认后调用）
   * body.mode: 'alerts' | 'chains' | 'stats'
   * batchId 策略：
   *   - all_exist（本次全部已在库，含子集）：复用原 batchId，不重复写入
   *   - partial / all_new：使用全新 batchId，允许重新写入
   */
  router.post('/persist', async (req, res) => {
    const mode = String(req.body.mode || '').toLowerCase();
    let batchId = req.body.batchId;
    const mapped = Array.isArray(req.body.mapped) ? req.body.mapped : [];
    const chains = Array.isArray(req.body.chains) ? req.body.chains : [];
    let stats = req.body.stats || null;
    let coverage = req.body.coverage || null;
    let contentHash =
      req.body.contentHash ||
      (mapped[0] && mapped[0].contentHash) ||
      (chains[0] && chains[0].contentHash) ||
      null;

    const steps = [];
    const saved = { alerts: 0, chains: 0, stats: false };

    const finish = (payload) => {
      const persistKind = payload.persistKind || 'all_new';
      const message =
        payload.message ||
        userPersistMessage(mode, persistKind, {
          total: payload.total,
          existed: payload.existed,
          added: payload.added
        });
      return res.json({
        ok: true,
        skipped: !!payload.skipped,
        persisted: !payload.skipped,
        title: userPersistTitle(persistKind),
        message,
        steps: [{ name: mode, status: 'done', message: payload.skipped ? '已跳过' : '已完成' }],
        mode,
        saved: payload.saved || saved,
        batchId: payload.batchId,
        contentHash: payload.contentHash || contentHash,
        persistKind,
        total: payload.total ?? 0,
        existed: payload.existed ?? 0,
        added: payload.added ?? 0
      });
    };

    try {
      if (!isMongoReady()) {
        return res.status(503).json({
          ok: false,
          error: 'MongoDB 未连接，无法入库。请启动本机/服务器 MongoDB 后重试。',
          steps,
          saved
        });
      }
      if (!batchId) {
        return res.status(400).json({
          ok: false,
          error: '缺少 batchId，请先完成映射或一键流水线',
          steps,
          saved
        });
      }
      if (!['alerts', 'chains', 'stats'].includes(mode)) {
        return res.status(400).json({
          ok: false,
          error: 'mode 须为 alerts / chains / stats',
          steps,
          saved
        });
      }

      if (mode === 'alerts') {
        if (!mapped.length) {
          return res.status(400).json({
            ok: false,
            error: '没有可入库的映射结果，请先执行批量映射',
            steps,
            saved
          });
        }
        if (!contentHash) contentHash = hashMappedAlerts(mapped);

        const classified = await classifyMappedBatch(
          mapped.map((m) => ({
            ...m,
            contentHash,
            timestamp: m.timestamp ? new Date(m.timestamp) : undefined
          }))
        );
        const { persistKind, existedCount, addedCount, itemHashes, prepared } = classified;
        const writeBatchId = classified.batchId;

        if (persistKind === 'all_exist') {
          return finish({
            skipped: true,
            batchId: writeBatchId,
            contentHash,
            persistKind,
            total: itemHashes.length,
            existed: existedCount,
            added: 0,
            saved
          });
        }

        // partial / all_new：写入新批次；重叠条目按 itemHash 覆盖，避免累计重复计数
        await MappedAlert.deleteMany({
          $or: [{ itemHash: { $in: itemHashes } }, { batchId: writeBatchId }]
        });
        await MappedAlert.insertMany(
          prepared.map((m) => ({
            ...m,
            batchId: writeBatchId,
            contentHash,
            itemHash: m.itemHash
          }))
        );
        saved.alerts = prepared.length;
        return finish({
          batchId: writeBatchId,
          contentHash,
          persistKind,
          total: itemHashes.length,
          existed: existedCount,
          added: addedCount,
          saved
        });
      }

      if (mode === 'chains') {
        if (!chains.length) {
          return res.status(400).json({
            ok: false,
            error: '没有可入库的攻击链路，请先构建攻击链路',
            steps,
            saved
          });
        }
        if (!contentHash) contentHash = hashChains(chains);

        // 链路入库跟会话 batchId：该批次尚未写入 attackchains 则可存
        // （不再用「映射告警已在库」来拦截，否则先存告警后再存链路会被误判跳过）
        const writeBatchId = batchId;
        const existingInBatch = await AttackChain.countDocuments({ batchId: writeBatchId });
        if (existingInBatch > 0) {
          return finish({
            skipped: true,
            batchId: writeBatchId,
            contentHash,
            persistKind: 'all_exist',
            total: chains.length,
            existed: existingInBatch,
            added: 0,
            saved
          });
        }

        const prepared = chains.map((c, i) => {
          const name =
            chains.length > 1
              ? `攻击链路（${writeBatchId}#${i + 1}）`
              : `攻击链路（${writeBatchId}）`;
          const itemHash = c.itemHash || itemHashChain({ ...c, name });
          return {
            ...c,
            name,
            itemHash,
            contentHash,
            batchId: writeBatchId,
            startTime: c.startTime ? new Date(c.startTime) : undefined,
            endTime: c.endTime ? new Date(c.endTime) : undefined
          };
        });

        await AttackChain.deleteMany({ batchId: writeBatchId });
        await AttackChain.insertMany(prepared);
        saved.chains = prepared.length;
        return finish({
          batchId: writeBatchId,
          contentHash,
          persistKind: 'all_new',
          total: prepared.length,
          existed: 0,
          added: prepared.length,
          saved
        });
      }

      // mode === 'stats'
      if (!coverage) {
        coverage = buildCoverageMatrix(
          mapped.length ? mapped : [],
          attck.killChainOrder
        );
      }
      if (!stats) {
        stats = computeStats(mapped, chains, coverage);
      }
      if (!stats) {
        return res.status(400).json({
          ok: false,
          error: '没有可入库的统计/覆盖数据，请先完成映射或构链',
          steps,
          saved
        });
      }
      if (!contentHash) {
        contentHash = mapped.length
          ? hashMappedAlerts(mapped)
          : chains.length
            ? hashChains(chains)
            : null;
      }

      // 统计入库跟会话 batchId：该批次尚无 sessionstats 则可存
      const writeBatchId = batchId;
      const existedStats = await SessionStats.findOne({ batchId: writeBatchId }).lean();
      if (existedStats) {
        return finish({
          skipped: true,
          batchId: writeBatchId,
          contentHash,
          persistKind: 'all_exist',
          total: 1,
          existed: 1,
          added: 0,
          saved
        });
      }

      await SessionStats.findOneAndUpdate(
        { batchId: writeBatchId },
        { batchId: writeBatchId, contentHash, stats, coverage },
        { upsert: true }
      );
      saved.stats = true;
      return finish({
        batchId: writeBatchId,
        contentHash,
        persistKind: 'all_new',
        total: 1,
        existed: 0,
        added: 1,
        saved
      });
    } catch (err) {
      console.error('[persist]', err);
      res.status(500).json({
        ok: false,
        error: err.message || '入库失败',
        steps,
        saved
      });
    }
  });

  /** Latest / by batch stats */
  router.get('/stats', async (req, res) => {
    try {
      const { batchId } = req.query;
      if (batchId) {
        const doc = await SessionStats.findOne({ batchId }).lean();
        if (doc) return res.json(doc);
      }
      const latest = await SessionStats.findOne().sort({ updatedAt: -1 }).lean();
      if (latest) return res.json(latest);

      // empty defaults
      res.json({
        stats: {
          mappedAlertCount: 0,
          totalAlertCount: 0,
          mappingAccuracy: 0,
          mappingAccuracyPercent: '0%',
          attackChainCount: 0,
          tacticCoverage: 0,
          tacticCoveragePercent: '0%',
          coveredTactics: 0,
          totalTactics: 14
        },
        coverage: buildCoverageMatrix([], attck.killChainOrder)
      });
    } catch (err) {
      res.json({
        stats: {
          mappedAlertCount: 0,
          totalAlertCount: 0,
          mappingAccuracy: 0,
          mappingAccuracyPercent: '0%',
          attackChainCount: 0,
          tacticCoverage: 0,
          tacticCoveragePercent: '0%',
          coveredTactics: 0,
          totalTactics: 14
        }
      });
    }
  });

  /**
   * 库内累计条数（顶部统计栏左侧数字）
   * 未连 Mongo 时返回 0，不抛错
   */
  router.get('/stats/cumulative', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.json({
          mappedAlertCount: 0,
          attackChainCount: 0,
          mongo: false
        });
      }
      const [mappedAlertCount, attackChainCount] = await Promise.all([
        MappedAlert.countDocuments({}),
        AttackChain.countDocuments({})
      ]);
      res.json({
        mappedAlertCount,
        attackChainCount,
        mongo: true
      });
    } catch (err) {
      res.json({
        mappedAlertCount: 0,
        attackChainCount: 0,
        mongo: false,
        error: err.message
      });
    }
  });

  router.get('/chains', async (req, res) => {
    try {
      const filter = req.query.batchId ? { batchId: req.query.batchId } : {};
      const chains = await AttackChain.find(filter).sort({ startTime: 1 }).lean();
      res.json({ chains });
    } catch (err) {
      res.json({ chains: [] });
    }
  });

  /**
   * 列表示例告警（演示用集合 samplealerts）
   * 列表不含超长 content，详情接口再取全文
   */
  router.get('/samples', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.status(503).json({
          error: 'MongoDB 未连接，无法读取示例告警',
          samples: []
        });
      }
      const docs = await SampleAlert.find({})
        .sort({ sortOrder: 1, createdAt: 1 })
        .select('sampleKey name description format sortOrder updatedAt')
        .lean();
      const samples = docs.map((d) => ({
        id: String(d._id),
        sampleKey: d.sampleKey,
        name: d.name,
        description: d.description || '',
        format: d.format || 'json',
        preview: String(d.description || '').slice(0, 280),
        updatedAt: d.updatedAt
      }));
      res.json({ samples, count: samples.length });
    } catch (err) {
      res.status(500).json({ error: err.message || '读取示例失败', samples: [] });
    }
  });

  router.get('/samples/:id', async (req, res) => {
    try {
      if (!isMongoReady()) {
        return res.status(503).json({ error: 'MongoDB 未连接，无法读取示例告警' });
      }
      const id = req.params.id;
      let doc = null;
      if (mongoose.isValidObjectId(id)) {
        doc = await SampleAlert.findById(id).lean();
      }
      if (!doc) {
        doc = await SampleAlert.findOne({ sampleKey: id }).lean();
      }
      if (!doc) {
        return res.status(404).json({ error: '未找到该示例告警' });
      }
      res.json({
        id: String(doc._id),
        sampleKey: doc.sampleKey,
        name: doc.name,
        description: doc.description || '',
        format: doc.format || 'json',
        content: doc.content
      });
    } catch (err) {
      res.status(500).json({ error: err.message || '读取示例失败' });
    }
  });

  return router;
}

module.exports = { createRouter, parseTextToAlerts };
