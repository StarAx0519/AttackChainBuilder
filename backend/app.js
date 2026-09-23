/**
 * =============================================================================
 * app.js — 后端服务入口（Express + MongoDB）
 * =============================================================================
 * 1. 读取 ATTCK.json，构建战术/技术知识库
 * 2. 创建 Express HTTP 服务，挂载 /api 路由
 * 3. 尝试连接 MongoDB；连不上以“内存模式”跑
 * 4. 本机开发时同时托管 frontend 静态页面，实现“一个端口访问前后端”
 *
 * 浏览器 → http://localhost:3000/          （前端 HTML/CSS/JS）
 * 浏览器 → http://localhost:3000/api/...   （映射/链路等业务接口）
 *
 * 【环境变量】
 *   PORT        监听端口，默认 3000
 *   MONGO_URI   MongoDB 连接串
 *   ATTCK_PATH  ATTCK.json 绝对/相对路径
 * =============================================================================
 */

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

// 解析 ATT&CK 知识库、挂载业务路由
const { loadAttckData, getDefaultAttckPath } = require('./src/attckParser');
const { createRouter } = require('./src/routes');

const PORT = process.env.PORT || 3000;
const MONGO_URI =
  process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/qy_attack_chain';

// ---------- 1) 加载 ATT&CK 数据（系统启动硬依赖） ----------
const attckPath = process.env.ATTCK_PATH || getDefaultAttckPath();
if (!fs.existsSync(attckPath)) {
  console.error('[启动失败] 找不到 ATTCK.json，当前探测路径:', attckPath);
  console.error('请设置环境变量 ATTCK_PATH，或把文件放到 data/ATTCK.json');
  process.exit(1);
}

const attck = loadAttckData(attckPath);
console.log(
  `[ATT&CK] 已加载 ${attck.tactics.length} 个战术、${attck.techniques.length} 个技术 ← ${attckPath}`
);

// ---------- 2) 创建 Express 应用 ----------
const app = express();

// 允许跨域：本机用 live-server / 不同端口打开前端时需要
app.use(cors());

// 解析 JSON / 表单；告警批量文本可能较大，放宽到 8MB
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));

// 业务 API：/api/mapping/batch、/api/chains/build 等
app.use('/api', createRouter(attck));

// API 根说明（方便 curl 探测）
app.get('/api-info', (req, res) => {
  res.json({
    name: 'Attack Chain Builder API',
    version: '1.0.0',
    endpoints: [
      'GET  /api/health',
      'GET  /api/attck/tactics',
      'GET  /api/mapping/rules',
      'POST /api/mapping/batch',
      'POST /api/chains/build',
      'POST /api/pipeline',
      'POST /api/persist',
      'GET  /api/stats',
      'GET  /api/chains'
    ]
  });
});

// ---------- 3) 本机一体托管前端静态资源 ----------
// 优先顺序：仓库 frontend/ → /home/www/frontend（云服务器）
const frontendCandidates = [
  path.join(__dirname, '../frontend'),
  path.join(__dirname, 'frontend'),
  '/home/www/frontend'
];
const frontendDir = frontendCandidates.find((p) => fs.existsSync(path.join(p, 'index.html')));
if (frontendDir) {
  app.use(express.static(frontendDir));
  // 示例告警：既可从 frontend/sample_alerts.json，也可从 data/
  const samplePath = path.join(__dirname, '../data/sample_alerts.json');
  if (fs.existsSync(samplePath)) {
    app.get('/sample_alerts.json', (req, res) => res.sendFile(samplePath));
  }
  console.log('[Static] 前端目录:', frontendDir);
}

// ---------- 4) 启动：先连库，再监听端口 ----------
/**
 * 尝试监听端口；若被占用则依次尝试 PORT+1 ... PORT+9
 * 避免本机重复双击 start-local 时出现 EADDRINUSE 未捕获崩溃
 */
function listenWithFallback(port, mongoOk) {
  const base = Number(port) || 3000;
  const maxTry = 10;

  const tryListen = (offset) => {
    const p = base + offset;
    const server = app.listen(p, '0.0.0.0', () => {
      console.log('========================================');
      console.log(`[Server] Open in browser: http://127.0.0.1:${p}/`);
      console.log(`[Server] API health:      http://127.0.0.1:${p}/api/health`);
      console.log(`[Server] MongoDB:         ${mongoOk ? 'connected' : 'memory mode (OK for demo)'}`);
      if (p !== base) {
        console.log(`[Server] Note: port ${base} was busy, using ${p} instead`);
      }
      console.log('========================================');
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE' && offset + 1 < maxTry) {
        console.warn(`[Server] Port ${p} in use, trying ${p + 1}...`);
        tryListen(offset + 1);
      } else if (err.code === 'EADDRINUSE') {
        console.error(
          `[Server] Ports ${base}-${base + maxTry - 1} all busy. Close old node windows or set PORT=3080`
        );
        process.exit(1);
      } else {
        console.error('[Server] listen error:', err);
        process.exit(1);
      }
    });
  };

  tryListen(0);
}

async function start() {
  let mongoOk = false;
  try {
    // serverSelectionTimeoutMS：几秒连不上就放弃，避免本机无 Mongo 时卡住太久
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 5000
    });
    mongoOk = true;
    console.log('[MongoDB] connected:', MONGO_URI);
  } catch (err) {
    // 无数据库也能演示：映射结果只在本次 HTTP 响应中返回，不落库
    console.warn('[MongoDB] unavailable, memory mode (demo OK):', err.message);
  }

  listenWithFallback(PORT, mongoOk);
}

start();
