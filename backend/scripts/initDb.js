/**
 * =============================================================================
 * initDb.js — 初始化 MongoDB 库与索引，并种子写入示例告警集合
 * =============================================================================
 *
 * 用法（需先启动 mongod）：
 *   cd backend
 *   npm run init-db
 *
 * 会创建数据库 qy_attack_chain，以及集合：
 *   mappedalerts / attackchains / sessionstats / samplealerts
 * =============================================================================
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const {
  MappedAlert,
  AttackChain,
  SessionStats,
  SampleAlert
} = require('../src/models');
const { seedCaSerializedSamples } = require('./seedCaSerializedSamples');

const MONGO_URI =
  process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/qy_attack_chain';

const NIGHT_DRAGON_TEXT = JSON.stringify(
  {
    title: '案例-夜龙 APT 攻击',
    text:
      '背景：夜龙 APT 攻击是 McAfee 在2011年2月份发现并命名的针对全球主要能源公司的攻击行为。该多步攻击的分析过程如下：第一步：研究目标。主要针对的是国际知名的能源公司。第二步：拿下第一目标主机，打开局面。黑客为了侵入内网，使用由外到内的策略。虽然内网往往不与internet有接触，但是对于每个公司的web服务器来说，它具有的一个特点就是：既与内网连接，又与外网连接。所以，黑客选中了这些公司的web服务器作为第一目标主机。对外网主机如Web服务器进行攻击，黑客采用的是SQL注入攻击，并顺利拿下了web服务器。第三步：通过横向移动。拿下具有高级权限的敏感主机黑客以被黑的Web服务器被作为跳板，对内网的其他服务器或PC进行扫描，使用弱口令对内网机器如AD服务器或开发人员电脑进行攻击，拿下敏感主机。被黑机器被植入恶意代码，并被安装远端控制工具（RAT）。第四步：构建虚拟隧道。并禁用掉被黑机器IE的代理设置，建立起直连的通道。第五步：卷货撤退   传回大量机敏文件（WORD、PPT、PDF等等），包括所有会议记录与组织人事架构图。'
  },
  null,
  2
);

function loadSampleAlertsJson() {
  const candidates = [
    path.join(__dirname, '..', '..', 'data', 'sample_alerts.json'),
    path.join(__dirname, '..', '..', 'frontend', 'sample_alerts.json')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return fs.readFileSync(p, 'utf8');
    }
  }
  return '[]';
}

async function seedSampleAlerts() {
  const batchJson = loadSampleAlertsJson();
  const seeds = [
    {
      sampleKey: 'batch-json-demo',
      name: '多阶段结构化告警（JSON 数组）',
      description: '侦察→注入→横向→外泄等结构化样例，适合演示规则映射与链路构建',
      format: 'json',
      content: batchJson.trim(),
      sortOrder: 10
    },
    {
      sampleKey: 'night-dragon-narrative',
      name: '夜龙 APT 叙述案例',
      description: '无 T/TA 编号的中文多步攻击叙述，适合演示关键词启发拆条',
      format: 'narrative',
      content: NIGHT_DRAGON_TEXT,
      sortOrder: 20
    }
  ];

  for (const s of seeds) {
    await SampleAlert.findOneAndUpdate(
      { sampleKey: s.sampleKey },
      { $set: s },
      { upsert: true, new: true }
    );
  }
  return seeds.length;
}

async function main() {
  await mongoose.connect(MONGO_URI);
  console.log('Connected:', MONGO_URI);

  await MappedAlert.createCollection();
  await AttackChain.createCollection();
  await SessionStats.createCollection();
  await SampleAlert.createCollection();

  await MappedAlert.collection.createIndex({ batchId: 1 });
  await MappedAlert.collection.createIndex({ timestamp: 1 });
  await MappedAlert.collection.createIndex({ contentHash: 1 });
  await MappedAlert.collection.createIndex({ itemHash: 1 });
  await AttackChain.collection.createIndex({ batchId: 1 });
  await AttackChain.collection.createIndex({ chainId: 1 });
  await AttackChain.collection.createIndex({ contentHash: 1 });
  await AttackChain.collection.createIndex({ itemHash: 1 });
  await SessionStats.collection.createIndex({ contentHash: 1 });
  await SampleAlert.collection.createIndex({ sampleKey: 1 }, { unique: true });
  await SampleAlert.collection.createIndex({ sortOrder: 1 });

  const seeded = await seedSampleAlerts();
  const caSeed = await seedCaSerializedSamples();

  console.log('Database qy_attack_chain initialized.');
  console.log(
    'Collections: mappedalerts, attackchains, sessionstats, samplealerts'
  );
  console.log(`Built-in demo samples upserted: ${seeded}`);
  if (!caSeed.skipped) {
    console.log(`CA serialized samples upserted: ${caSeed.totalRows}`);
  } else {
    console.log('CA serialized samples: skipped (xlsx not found or empty)');
  }
  const totalSamples = await SampleAlert.countDocuments({});
  console.log(`samplealerts total documents: ${totalSamples}`);
  await mongoose.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
