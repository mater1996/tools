#!/usr/bin/env bash
# xray-sub-server 一键安装
# 用法: bash <(curl -fsSL https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
# 可选环境变量:
#   PORT=8081                 监听端口
#   NAME=JP-Reality           节点名(会同步替换模板里的引用)
#   SECRET=<随机串>            设置后启用多用户：每个 Xray client 一个独立 token
#   TEMPLATE=/path/template   Clash 模板(默认用仓库自带 template.yaml)
#   REPO_RAW=<镜像前缀+raw>    GitHub 直连慢时用镜像，如 https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server
set -euo pipefail

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server}"
DIR="${DIR:-/opt/xray-sub}"
PORT="${PORT:-8081}"
NAME="${NAME:-JP-Reality}"
CONF_DIR="${CONF_DIR:-/etc/xray/conf}"
XRAY_BIN="${XRAY_BIN:-/etc/xray/bin/xray}"
TEMPLATE="${TEMPLATE:-$DIR/template.yaml}"

command -v python3 >/dev/null 2>&1 || { echo "[x] 需要 python3"; exit 1; }
[ -d "$CONF_DIR" ] || { echo "[x] 找不到 Xray 配置目录: $CONF_DIR"; exit 1; }
[ -x "$XRAY_BIN" ] || { echo "[x] 找不到 xray 可执行文件: $XRAY_BIN"; exit 1; }

echo "[+] 下载脚本与模板 ..."
mkdir -p "$DIR"
curl -fsSL "$REPO_RAW/xray-sub-server.py" -o "$DIR/xray-sub-server.py"
chmod +x "$DIR/xray-sub-server.py"
if [ "$TEMPLATE" = "$DIR/template.yaml" ]; then
  curl -fsSL "$REPO_RAW/template.yaml" -o "$DIR/template.yaml" || echo "[!] 模板下载失败，将生成基础配置"
fi

# 复用已有 token/secret，避免重装后订阅地址失效
SVC=/etc/systemd/system/xray-sub.service
SECRET="${SECRET:-}"
TOKEN=""
if [ -f "$SVC" ]; then
  [ -z "$SECRET" ] && SECRET="$(grep -oE -- '--secret [^ ]+' "$SVC" | head -1 | awk '{print $2}')"
  TOKEN="$(grep -oE -- '--token [^ ]+' "$SVC" | head -1 | awk '{print $2}')"
fi
ARGS="--conf-dir $CONF_DIR --xray-bin $XRAY_BIN --port $PORT --name $NAME"
if [ -n "$SECRET" ]; then
  ARGS="$ARGS --secret $SECRET"
else
  [ -n "$TOKEN" ] || TOKEN="$(openssl rand -hex 16)"
  ARGS="$ARGS --token $TOKEN"
fi
[ -f "$TEMPLATE" ] && ARGS="$ARGS --template $TEMPLATE"

echo "[+] 写入 systemd 服务 ..."
cat > /etc/systemd/system/xray-sub.service <<EOF
[Unit]
Description=Xray Subscription Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 $DIR/xray-sub-server.py $ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray-sub >/dev/null 2>&1
systemctl restart xray-sub   # 重装时确保新代码/新模板生效
sleep 1
if ! systemctl is-active --quiet xray-sub; then
  echo "[x] 启动失败，用 journalctl -u xray-sub -n 30 查看"
  exit 1
fi

IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
echo
echo "✅ 安装完成"
if [ -n "$SECRET" ]; then
  echo "   多用户模式：查看每人订阅链接执行"
  echo "   python3 $DIR/xray-sub-server.py list --conf-dir $CONF_DIR --xray-bin $XRAY_BIN --secret $SECRET --port $PORT --server ${IP:-<公网IP>}"
else
  echo "   订阅地址: http://${IP:-<你的公网IP>}:$PORT/sub?token=$TOKEN"
fi
echo "   放行端口: 安全组加 TCP $PORT"
echo "   改 Xray 配置后，客户端下次拉订阅自动更新，无需重启本服务"
