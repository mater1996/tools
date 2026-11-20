#!/usr/bin/env bash
# xray-sub-server 安装（仅安装，不启动）
# 用法: bash <(curl -fsSL https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
# 安装后用 `xray-sub init` 注册 systemd、启动并生成订阅链接
set -euo pipefail

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server}"
DIR="${DIR:-/opt/xray-sub}"

command -v python3 >/dev/null 2>&1 || { echo "[x] 需要 python3"; exit 1; }

# 依次尝试：自定义源 -> GitHub 直连 -> 常见镜像
fetch_to() {  # $1=相对路径  $2=输出文件
  local rel="$1" out="$2" base
  for base in "$REPO_RAW" \
      "https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server" \
      "https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server" \
      "https://gh-proxy.com/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server" \
      "https://ghproxy.net/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server"; do
    if curl -fsSL --connect-timeout 10 --max-time 90 "$base/$rel" -o "$out" 2>/dev/null && [ -s "$out" ]; then
      echo "    来源: $base"
      return 0
    fi
  done
  return 1
}

echo "[+] 下载脚本与模板 ..."
mkdir -p "$DIR"
if ! fetch_to "xray-sub-server.py" "$DIR/xray-sub-server.py"; then
  echo "[x] 下载 xray-sub-server.py 失败：GitHub 直连和镜像都不通"
  echo "    可指定镜像重试：REPO_RAW=https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server"
  exit 1
fi
chmod +x "$DIR/xray-sub-server.py"
fetch_to "template.yaml" "$DIR/template.yaml" || echo "[!] 模板下载失败，将生成基础配置"

echo "[+] 生成全局命令 /usr/local/bin/xray-sub ..."
cat > /usr/local/bin/xray-sub <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 $DIR/xray-sub-server.py "\$@"
EOF
chmod +x /usr/local/bin/xray-sub

echo
echo "✅ 已安装（未启动）。全局命令: xray-sub"
echo "   注册并启动:    xray-sub init"
echo "   之后查看链接:  xray-sub list   # 每个 Xray 用户一条"
