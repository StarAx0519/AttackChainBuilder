/**
 * =============================================================================
 * models.js — MongoDB 数据模型（Mongoose Schema）
 * =============================================================================
 *
 * 【MongoDB 在本项目存什么】
 *   不是存 ATTCK.json 知识库（知识库启动时读文件进内存）。
 *   只存「用户跑完一次映射/构链之后」的业务结果快照，便于刷新后回看、按 batchId 查询。
 *
 * 【四个集合】（库名默认 qy_attack_chain）
 *   mappedalerts  / MappedAlert   已映射告警
 *   attackchains  / AttackChain   攻击链路
 *   sessionstats  / SessionStats  批次统计 + 覆盖矩阵
 *   samplealerts  / SampleAlert   示例告警
 * =============================================================================
 */

const mongoose = require('mongoose');

/** 已映射告警文档结构 */
const MappedAlertSchema = new mongoose.Schema(
  {
    alertId: String,
    timestamp: Date,
    attackType: String,
    title: String,
    srcIp: String,
    dstIp: String,
    host: String,
    severity: String,
    mapping: {
      primary: String,
      secondary: [String],
      // 多技术 / 多战术展开（enrichMapping 产物）
      techniques: mongoose.Schema.Types.Mixed,
      tactics: mongoose.Schema.Types.Mixed,
      tacticIds: [String],
      confidence: Number,
      quality: String,
      qualityLabel: String,
      method: String,
      methodLabel: String,
      techniqueName: String,
      tacticId: String,
      tacticName: String,
      tacticNameEn: String,
      killChainOrder: Number
    },
    // 可选：步骤模式字段
    stepIndex: Number,
    stepLabel: String,
    timePrecision: String,
    timeDisplay: String,
    destNodeId: String,
    srcNodeId: String,
    device: String,
    description: String,
    original: mongoose.Schema.Types.Mixed,
    batchId: { type: String, index: true },
    /** 批次内容指纹 */
    contentHash: { type: String, index: true },
    /** 单条告警指纹：用于部分重叠时的覆盖/新增判定 */
    itemHash: { type: String, index: true }
  },
  { timestamps: true }
);

const AttackChainSchema = new mongoose.Schema(
  {
    chainId: { type: String, index: true },
    name: String,
    batchId: { type: String, index: true },
    contentHash: { type: String, index: true },
    itemHash: { type: String, index: true },
    alertCount: Number,
    startTime: Date,
    endTime: Date,
    durationMs: Number,
    durationHuman: String,
    timeMode: String,
    stages: mongoose.Schema.Types.Mixed,
    coveredTactics: [String],
    techniques: [String],
    avgConfidence: Number,
    complexityScore: Number,
    complexityLevel: String,
    complexityDetail: mongoose.Schema.Types.Mixed,
    timeline: mongoose.Schema.Types.Mixed
  },
  { timestamps: true }
);

const SessionStatsSchema = new mongoose.Schema(
  {
    batchId: { type: String, unique: true },
    contentHash: { type: String, index: true },
    stats: mongoose.Schema.Types.Mixed,
    coverage: mongoose.Schema.Types.Mixed
  },
  { timestamps: true }
);

/** 演示用示例告警（独立集合，不与 mappedalerts 混用） */
const SampleAlertSchema = new mongoose.Schema(
  {
    sampleKey: { type: String, unique: true, index: true },
    name: { type: String, required: true },
    description: String,
    format: { type: String, default: 'json' },
    /** 填入文本框的完整内容（JSON 字符串或叙述文本） */
    content: { type: String, required: true },
    sortOrder: { type: Number, default: 0 }
  },
  { timestamps: true, collection: 'samplealerts' }
);

module.exports = {
  MappedAlert: mongoose.model('MappedAlert', MappedAlertSchema),
  AttackChain: mongoose.model('AttackChain', AttackChainSchema),
  SessionStats: mongoose.model('SessionStats', SessionStatsSchema),
  SampleAlert: mongoose.model('SampleAlert', SampleAlertSchema)
};
