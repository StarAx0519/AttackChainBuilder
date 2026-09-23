#!/usr/bin/env bash
# =============================================================================
# deploy.sh — 云服务器上一键安装依赖、初始化库、后台启动 Node 服务
# 用法：cd /home/www/backend && bash deploy.sh
# 本机 Windows 请改用项目根目录 start-local.bat（不需要本脚本）
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

export PORT="${PORT:-3000}"
export MONGO_URI="${MONGO_URI:-mongodb://127.0.0.1:27017/qy_attack_chain}"

# Resolve ATTCK.json
if [[ -z "${ATTCK_PATH:-}" ]]; then
  if [[ -f "$ROOT/data/ATTCK.json" ]]; then
    export ATTCK_PATH="$ROOT/data/ATTCK.json"
  elif [[ -f "$ROOT/../data/ATTCK.json" ]]; then
    export ATTCK_PATH="$ROOT/../data/ATTCK.json"
  elif [[ -f "/home/www/data/ATTCK.json" ]]; then
    export ATTCK_PATH="/home/www/data/ATTCK.json"
  fi
fi

echo "==> Working dir: $ROOT"
echo "==> MongoDB: $MONGO_URI"
echo "==> ATTCK: ${ATTCK_PATH:-not set}"

# Ensure Node deps
if [[ ! -d node_modules ]]; then
  echo "==> Installing npm dependencies..."
  npm install --production
fi

# Init DB (best-effort)
echo "==> Initializing database..."
node scripts/initDb.js || echo "WARN: initDb failed (is mongod running?)"

# Stop previous instance if pid file exists
PID_FILE="$ROOT/app.pid"
if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [[ -n "${OLD_PID}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "==> Stopping previous process $OLD_PID"
    kill "$OLD_PID" || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi

mkdir -p "$ROOT/logs"
echo "==> Starting backend on port $PORT"
nohup node app.js >> "$ROOT/logs/app.log" 2>&1 &
echo $! > "$PID_FILE"
echo "==> Started PID $(cat "$PID_FILE")"
echo "==> Log: $ROOT/logs/app.log"
sleep 1
curl -s "http://127.0.0.1:${PORT}/api/health" || true
echo
echo "Done."
