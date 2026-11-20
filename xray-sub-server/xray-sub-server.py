#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xray-sub-server
读取 Xray 的 Reality 配置(/etc/xray/conf/*.json)，生成 Clash/mihomo 订阅，
并通过内置 HTTP(S) 服务提供。无需 nginx。

特点:
  - 每次请求热重载配置：改了服务端节点，客户端下次拉订阅自动更新
  - 自动由 privateKey 计算 publicKey(调用 xray x25519，带缓存)
  - 可选套用已有 Clash 模板(保留你的策略组/规则)，只替换 proxies 段
  - Token 认证 + 可选 HTTPS(自签证书)

用法:
  python3 xray-sub-server.py --token 'YOUR_TOKEN' --port 8081 \
      --conf-dir /etc/xray/conf --xray-bin /etc/xray/bin/xray \
      --template /etc/xray/clash-template.yaml

订阅地址:
  http://<服务器IP>:8081/<token>.yaml
"""
import argparse
import glob
import json
import os
import socket
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

APP = None  # 全局，供 handler 访问
_pub_cache = {}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def detect_public_ip():
    """取本机出口 IPv4（本机公网 IP 直接绑网卡时结果即公网 IP）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def pubkey_from_priv(xray_bin, priv):
    if not priv:
        return ""
    if priv in _pub_cache:
        return _pub_cache[priv]
    pub = ""
    try:
        out = subprocess.run([xray_bin, "x25519", "-i", priv],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            low = line.lower()
            if "public" in low or "password" in low:
                pub = line.split(":", 1)[1].strip() if ":" in line else line.strip()
                break
    except Exception as e:
        log(f"[warn] x25519 计算失败: {e}")
    _pub_cache[priv] = pub
    return pub


def load_nodes(conf_dir, xray_bin, base_name="JP-Reality"):
    nodes = []
    for f in sorted(glob.glob(os.path.join(conf_dir, "*.json"))):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:
            log(f"[warn] 跳过 {f}: {e}")
            continue
        for ib in d.get("inbounds", []) or []:
            if ib.get("protocol") != "vless":
                continue
            ss = ib.get("streamSettings") or {}
            if ss.get("security") != "reality":
                continue
            rs = ss.get("realitySettings") or {}
            clients = ((ib.get("settings") or {}).get("clients")) or []
            if not clients:
                continue
            c = clients[0]
            port = ib.get("listen_port") or ib.get("port")
            target = rs.get("dest") or rs.get("target") or ""
            sns = rs.get("serverNames") or []
            sni = next((s for s in sns if s), "") or (target.split(":")[0] if target else "")
            sid = (rs.get("shortIds") or [""])[0]
            pub = pubkey_from_priv(xray_bin, rs.get("privateKey") or "")
            if not (c.get("id") and pub and sni and port):
                log(f"[warn] {os.path.basename(f)}: 节点字段不完整，跳过")
                continue
            idx = len(nodes) + 1
            nodes.append({
                "name": base_name if idx == 1 else f"{base_name}-{idx}",
                "port": int(port),
                "uuid": c.get("id"),
                "flow": c.get("flow") or "xtls-rprx-vision",
                "sni": sni,
                "pub": pub,
                "sid": sid,
            })
    return nodes


def gen_proxies_lines(nodes, server):
    lines = []
    for n in nodes:
        lines += [
            f'  - name: "{n["name"]}"',
            '    type: vless',
            f'    server: {server}',
            f'    port: {n["port"]}',
            f'    uuid: {n["uuid"]}',
            '    network: tcp',
            '    udp: true',
            '    tls: true',
            f'    flow: {n["flow"]}',
            f'    servername: {n["sni"]}',
            '    client-fingerprint: chrome',
            '    reality-opts:',
            f'      public-key: {n["pub"]}',
            f'      short-id: "{n["sid"]}"',
        ]
    return lines


def gen_profile(nodes, server):
    y = [
        "mixed-port: 7890", "allow-lan: false", "mode: rule",
        "log-level: warning", "ipv6: false", "",
        "dns:", "  enable: true", "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16", "  nameserver:",
        "    - 1.1.1.1", "    - 8.8.8.8", "", "proxies:",
    ]
    y += gen_proxies_lines(nodes, server)
    y += ["", "proxy-groups:", '  - name: "PROXY"', "    type: select", "    proxies:"]
    y += [f'      - "{n["name"]}"' for n in nodes]
    y += ["      - DIRECT", "", "rules:", "  - GEOIP,CN,DIRECT", "  - MATCH,PROXY"]
    return "\n".join(y) + "\n"


def inject_template(template_text, nodes, server, base_name="JP-Reality"):
    """把模板里顶层 `proxies:` 段整体替换为新节点，其余(策略组/规则)原样保留。
    自定义节点名时，模板里对 `JP-Reality` 的引用同步替换，避免策略组断链。"""
    proxies = gen_proxies_lines(nodes, server)
    lines = template_text.splitlines()
    out, i, injected = [], 0, False
    while i < len(lines):
        line = lines[i]
        if not injected and line.strip() == "proxies:" and not line.startswith(" "):
            out.append("proxies:")
            out.extend(proxies)
            i += 1
            # 跳过旧的 proxies 段：缩进行、顶格列表项(- )、空行，直到下一个顶层键
            while i < len(lines):
                t = lines[i]
                if t.strip() == "" or t.startswith(" ") or t.startswith("- "):
                    i += 1
                else:
                    break
            injected = True
            continue
        out.append(line)
        i += 1
    if not injected:
        out += ["", "proxies:"] + proxies
    result = "\n".join(out) + "\n"
    if base_name != "JP-Reality":
        result = result.replace("JP-Reality", base_name)
    return result


class App:
    def __init__(self, args):
        self.args = args
        self.template = ""
        if args.template and os.path.exists(args.template):
            self.template = open(args.template, encoding="utf-8").read()
            log(f"[+] 使用模板: {args.template}")
        self.server = args.server or detect_public_ip()
        if not self.server:
            log("[warn] 无法自动探测公网 IP，请用 --server 指定")

    def render(self):
        nodes = load_nodes(self.args.conf_dir, self.args.xray_bin, self.args.name)
        if not nodes:
            raise RuntimeError("未从 Xray 配置中找到可用的 Reality 节点")
        if self.template:
            return inject_template(self.template, nodes, self.server, self.args.name)
        return gen_profile(nodes, self.server)


class Handler(BaseHTTPRequestHandler):
    server_version = "xray-sub/1.0"

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/")
        q = parse_qs(u.query)
        token = APP.args.token
        qtok = (q.get("token") or [""])[0]
        bearer = self.headers.get("Authorization", "")
        ok = (
            qtok == token
            or bearer == f"Bearer {token}"
            or path in (f"/{token}.yaml", f"/sub/{token}", f"/clash/{token}")
        )
        if not ok:
            self.send_error(404, "not found")
            return
        try:
            body = APP.render().encode("utf-8")
        except Exception as e:
            log(f"[error] {e}")
            self.send_error(503, str(e))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Profile-Update-Interval", "12")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        log(f"[ok] {self.address_string()} -> subscription ({len(body)} bytes)")

    def log_message(self, fmt, *args):
        pass  # 已自定义日志


def main():
    global APP
    ap = argparse.ArgumentParser(description="Xray Reality -> Clash 订阅服务器(无需 nginx)")
    ap.add_argument("--conf-dir", default="/etc/xray/conf", help="Xray 配置目录")
    ap.add_argument("--xray-bin", default="xray", help="xray 可执行文件路径")
    ap.add_argument("--token", required=True, help="订阅访问 token(放在 URL 里)")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--server", default="", help="订阅里的服务器地址，留空自动探测")
    ap.add_argument("--name", default="JP-Reality", help="节点名(模板里对 JP-Reality 的引用会同步替换)")
    ap.add_argument("--template", default="", help="可选：Clash 模板 yaml，保留其策略组/规则")
    ap.add_argument("--tls-cert", default="", help="可选：HTTPS 证书")
    ap.add_argument("--tls-key", default="", help="可选：HTTPS 私钥")
    args = ap.parse_args()

    APP = App(args)
    # 启动即校验一次，尽早暴露配置问题
    try:
        sample = APP.render()
        log(f"[+] 启动校验通过，订阅大小 {len(sample)} 字节")
    except Exception as e:
        log(f"[x] 启动校验失败: {e}")
        sys.exit(1)

    httpd = ThreadingHTTPServer((args.listen, args.port), Handler)
    scheme = "http"
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    log(f"[+] 订阅服务已启动: {scheme}://{APP.server}:{args.port}/sub?token={args.token}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("[+] 已停止")


if __name__ == "__main__":
    main()
