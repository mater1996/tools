#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xray-sub-server  v1.2.0
读取 Xray 的 Reality 配置，生成 Clash/mihomo 订阅，内置 HTTP(S) 服务提供。

子命令:
  serve     启动订阅服务(默认)
  list      列出订阅链接(多用户时可列出每个用户各自的链接)
  update    从 GitHub 拉取最新程序与模板并重启 systemd 服务
  version   版本

两种模式:
  单用户  --token <全局token>            一个 token 拉全部节点
  多用户  --secret <随机密钥>            每个 Xray client 一个独立 token(HMAC 派生)

多用户 token = HMAC-SHA256(secret, email/id)[:32]，删掉该 client 后 token 自动失效(404)。
"""
import argparse
import glob
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.2.0"
DEFAULT_REPO = "https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server"
SVC_PATH = "/etc/systemd/system/xray-sub.service"
APP = None
_pub_cache = {}


def log(m):
    print(m, file=sys.stderr, flush=True)


def service_defaults():
    """从已注册的 systemd 服务里读取参数，供 list/serve 免参数复用。"""
    d = {}
    if not os.path.exists(SVC_PATH):
        return d
    try:
        for line in open(SVC_PATH, encoding="utf-8", errors="ignore"):
            if line.startswith("ExecStart="):
                toks = line.split()
                for i, t in enumerate(toks[:-1]):
                    if t.startswith("--"):
                        d[t[2:]] = toks[i + 1]
                break
    except Exception:
        pass
    return d


def fill_defaults(args):
    d = service_defaults()
    for k, v in d.items():
        attr = k.replace("-", "_")
        if not hasattr(args, attr):
            continue
        cur = getattr(args, attr)
        if k == "port":
            if cur in (None, 8081):
                try:
                    setattr(args, "port", int(v))
                except Exception:
                    pass
        elif cur in (None, ""):
            setattr(args, attr, v)


def detect_public_ip():
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


def load_nodes(conf_dir, xray_bin, base_name):
    """返回所有 vless-reality client 组成的节点列表(每个 client 一项)。"""
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
            port = ib.get("listen_port") or ib.get("port")
            target = rs.get("dest") or rs.get("target") or ""
            sns = rs.get("serverNames") or []
            sni = next((s for s in sns if s), "") or (target.split(":")[0] if target else "")
            sid = (rs.get("shortIds") or [""])[0]
            pub = pubkey_from_priv(xray_bin, rs.get("privateKey") or "")
            if not (pub and sni and port):
                log(f"[warn] {os.path.basename(f)}: 节点字段不完整，跳过")
                continue
            for c in clients:
                if not c.get("id"):
                    continue
                nodes.append({
                    "email": c.get("email") or c["id"],
                    "uuid": c["id"],
                    "flow": c.get("flow") or "xtls-rprx-vision",
                    "port": int(port),
                    "sni": sni,
                    "pub": pub,
                    "sid": sid,
                })
    for i, n in enumerate(nodes):
        n["name"] = base_name if i == 0 else f"{base_name}-{i + 1}"
    return nodes


def token_for(secret, email):
    return hmac.new(secret.encode(), str(email).encode(), hashlib.sha256).hexdigest()[:32]


def group_by_email(nodes):
    d = {}
    for n in nodes:
        d.setdefault(n["email"], []).append(n)
    return d


def select_nodes(nodes, secret, token, base_name):
    """按 secret+token 选出该用户的节点；单用户(secret 为空)返回全部。"""
    if not secret:
        sel = nodes
    else:
        sel = None
        for email, ns in group_by_email(nodes).items():
            if hmac.compare_digest(token_for(secret, email), token or ""):
                sel = ns
                break
        if sel is None:
            return None
    # 重新命名：每个订阅里都从 base_name 开始
    out = []
    for i, n in enumerate(sel):
        nn = dict(n)
        nn["name"] = base_name if i == 0 else f"{base_name}-{i + 1}"
        out.append(nn)
    return out


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


def inject_template(template_text, nodes, server, base_name="JP-Reality", group_name=""):
    proxies = gen_proxies_lines(nodes, server)
    lines = template_text.splitlines()
    out, i, injected = [], 0, False
    while i < len(lines):
        line = lines[i]
        if not injected and line.strip() == "proxies:" and not line.startswith(" "):
            out.append("proxies:")
            out.extend(proxies)
            i += 1
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
    if group_name and group_name != "XQ-Network":
        result = result.replace("XQ-Network", group_name)
    return result


class App:
    def __init__(self, args):
        self.args = args
        self.template = ""
        if args.template and os.path.exists(args.template):
            self.template = open(args.template, encoding="utf-8").read()
            log(f"[+] 使用模板: {args.template}")
        self.profile_title = ""
        if self.template:
            m = re.search(r'^profile-title:\s*["\']?(.+?)["\']?\s*$', self.template, re.M)
            if m:
                self.profile_title = m.group(1).strip()
        self.server = args.server or detect_public_ip()
        if not self.server:
            log("[warn] 无法自动探测公网 IP，请用 --server 指定")

    @property
    def multi(self):
        return bool(getattr(self.args, "secret", ""))

    def render(self, token):
        nodes = load_nodes(self.args.conf_dir, self.args.xray_bin, self.args.name)
        if not nodes:
            raise RuntimeError("未从 Xray 配置中找到可用的 Reality 节点")
        sel = select_nodes(nodes, getattr(self.args, "secret", ""), token, self.args.name)
        if sel is None:
            return None
        if self.template:
            return inject_template(self.template, sel, self.server, self.args.name, getattr(self.args, "group_name", ""))
        return gen_profile(sel, self.server)


def extract_token(handler, path):
    u = urlparse(handler.path)
    q = parse_qs(u.query)
    if q.get("token"):
        return q["token"][0]
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    p = u.path.strip("/")
    if p.endswith(".yaml"):
        p = p[:-5]
    if p.startswith("sub/"):
        p = p[4:]
    if p.startswith("clash/"):
        p = p[6:]
    return p


class Handler(BaseHTTPRequestHandler):
    server_version = "xray-sub/1.2"

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/")
        token = extract_token(self, p)
        if not APP.multi and not hmac.compare_digest(token or "", APP.args.token or ""):
            self.send_error(404, "not found")
            return
        try:
            body = APP.render(token)
        except Exception as e:
            log(f"[error] {e}")
            self.send_error(503, str(e))
            return
        if body is None:
            self.send_error(404, "invalid token")
            return
        data = body.encode("utf-8")
        name_hint = APP.profile_title or getattr(APP.args, "group_name", "") or APP.args.name or "xray-sub"
        if not all(ord(c) < 128 for c in name_hint):   # 响应头只放 ASCII
            name_hint = "xray-sub"
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Profile-Title", name_hint)
        self.send_header("Profile-Update-Interval", "12")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        log(f"[ok] {self.address_string()} -> subscription ({len(data)} bytes)")

    def log_message(self, fmt, *args):
        pass


def common_args(p):
    p.add_argument("--conf-dir", default="/etc/xray/conf")
    p.add_argument("--xray-bin", default="/etc/xray/bin/xray")
    p.add_argument("--name", default="JP-Reality")
    p.add_argument("--group-name", default="", help="替换模板里的策略组名 XQ-Network")
    p.add_argument("--template", default="")
    p.add_argument("--server", default="")


def url_base(args):
    scheme = "https" if getattr(args, "tls_cert", "") else "http"
    ip = args.server or detect_public_ip() or "<公网IP>"
    return f"{scheme}://{ip}:{getattr(args, 'port', 8081)}"


def cmd_serve(args):
    global APP
    fill_defaults(args)
    if not args.secret and not args.token:
        args.secret = secrets.token_hex(16)
        log("[i] 未指定凭据，自动生成临时 secret（建议用 xray-sub init 持久化）")
    APP = App(args)
    try:
        if args.secret:
            emails = list(group_by_email(load_nodes(args.conf_dir, args.xray_bin, args.name)))
            if not emails:
                log("[x] 没有找到任何用户")
                sys.exit(1)
            sample = APP.render(token_for(args.secret, emails[0]))
        else:
            sample = APP.render(args.token or "")
        if sample is None:
            log("[x] 启动校验失败: token 不匹配")
            sys.exit(1)
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
    log(f"[+] 订阅服务已启动: {url_base(args)}/sub?token=<token>")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("[+] 已停止")


def cmd_list(args):
    fill_defaults(args)
    nodes = load_nodes(args.conf_dir, args.xray_bin, args.name)
    if not nodes:
        log("[x] 没有找到可用节点")
        sys.exit(1)
    base = url_base(args)
    if args.secret:
        for email in sorted(group_by_email(nodes)):
            print(f"{email}\t{base}/sub?token={token_for(args.secret, email)}")
    else:
        if not args.token:
            log("[x] 单用户模式需要 --token")
            sys.exit(1)
        print(f"all\t{base}/sub?token={args.token}")


def cmd_init(args):
    if os.geteuid() != 0:
        log("[x] init 需要 root 权限")
        sys.exit(1)
    if not os.path.isdir(args.conf_dir):
        log(f"[x] 配置目录不存在: {args.conf_dir}")
        sys.exit(1)
    if not (os.path.isfile(args.xray_bin) and os.access(args.xray_bin, os.X_OK)):
        log(f"[x] 找不到可执行的 xray: {args.xray_bin}")
        sys.exit(1)

    # 复用已有凭据，避免重复 init 后订阅地址变化
    d = service_defaults()
    secret = args.secret or d.get("secret", "")
    token = args.token or d.get("token", "")
    if not token and not secret:
        secret = secrets.token_hex(16)   # 默认多用户：按 Xray client 分发 token

    tmpl = args.template or os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.yaml")
    if not os.path.exists(tmpl):
        tmpl = ""

    exe = sys.executable or "/usr/bin/python3"
    script = os.path.abspath(__file__)
    parts = [exe, script, "serve",
             "--conf-dir", args.conf_dir, "--xray-bin", args.xray_bin,
             "--port", str(args.port), "--name", args.name]
    if args.server:
        parts += ["--server", args.server]
    if getattr(args, "group_name", ""):
        parts += ["--group-name", args.group_name]
    if tmpl:
        parts += ["--template", tmpl]
    if secret:
        parts += ["--secret", secret]
    else:
        parts += ["--token", token]

    unit = ("[Unit]\nDescription=Xray Subscription Server\nAfter=network.target\n\n"
            "[Service]\n"
            f"ExecStart={' '.join(parts)}\n"
            "Restart=always\nRestartSec=3\n\n"
            "[Install]\nWantedBy=multi-user.target\n")
    with open(SVC_PATH, "w", encoding="utf-8") as f:
        f.write(unit)
    log(f"[+] 已写入 {SVC_PATH}")
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "--now", "xray-sub"])
    time.sleep(1)
    if subprocess.run(["systemctl", "is-active", "--quiet", "xray-sub"]).returncode != 0:
        log("[x] 启动失败，用 journalctl -u xray-sub -n 30 查看")
        sys.exit(1)
    log("[+] 服务已启动")

    args.secret = secret
    args.token = token
    args.server = args.server or detect_public_ip()
    log("[+] 订阅链接：")
    cmd_list(args)


def _reality_files(conf_dir):
    out = []
    for f in sorted(glob.glob(os.path.join(conf_dir, "*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for ib in d.get("inbounds", []) or []:
            if ib.get("protocol") == "vless" and (ib.get("streamSettings") or {}).get("security") == "reality":
                out.append(f)
                break
    return out


def cmd_add_user(args):
    if os.geteuid() != 0:
        log("[x] add-user 需要 root")
        sys.exit(1)
    if not args.email:
        log("[x] 需要 --email")
        sys.exit(1)
    files = _reality_files(args.conf_dir)
    if not files:
        log("[x] 没找到 vless-reality 配置")
        sys.exit(1)
    f = args.file or files[0]
    d = json.load(open(f, encoding="utf-8"))
    added = False
    for ib in d.get("inbounds", []) or []:
        if ib.get("protocol") != "vless":
            continue
        cl = ib.setdefault("settings", {}).setdefault("clients", [])
        if any(c.get("email") == args.email for c in cl):
            log(f"[x] 用户已存在: {args.email}")
            sys.exit(1)
        uuid = subprocess.run([args.xray_bin, "uuid"], capture_output=True, text=True).stdout.strip()
        cl.append({"id": uuid, "flow": "xtls-rprx-vision", "email": args.email})
        added = True
        break
    if not added:
        log("[x] 配置里没有可写的 vless inbound")
        sys.exit(1)
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=4)
    log(f"[+] 已添加 {args.email} -> {f}")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")
    secret = args.secret or service_defaults().get("secret", "")
    args.server = args.server or detect_public_ip()
    if secret:
        print(f"{args.email}\t{url_base(args)}/sub?token={token_for(secret, args.email)}")
    else:
        log("[i] 未找到 secret，用 xray-sub list 查看链接")


def cmd_del_user(args):
    if os.geteuid() != 0:
        log("[x] del-user 需要 root")
        sys.exit(1)
    if not args.email:
        log("[x] 需要 --email")
        sys.exit(1)
    files = _reality_files(args.conf_dir)
    if not files:
        log("[x] 没找到 vless-reality 配置")
        sys.exit(1)
    f = args.file or files[0]
    d = json.load(open(f, encoding="utf-8"))
    removed = False
    for ib in d.get("inbounds", []) or []:
        if ib.get("protocol") != "vless":
            continue
        cl = (ib.get("settings") or {}).get("clients") or []
        new = [c for c in cl if c.get("email") != args.email]
        if len(new) != len(cl):
            ib["settings"]["clients"] = new
            removed = True
            break
    if not removed:
        log(f"[x] 没找到用户: {args.email}")
        sys.exit(1)
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=4)
    log(f"[+] 已删除 {args.email}（其订阅 token 立即失效）")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")


def cmd_update(args):
    import urllib.request
    os.makedirs(args.dir, exist_ok=True)
    for fn in ("xray-sub-server.py", "template.yaml"):
        url = f"{args.repo_raw}/{fn}"
        dst = os.path.join(args.dir, fn)
        log(f"[+] 下载 {url}")
        urllib.request.urlretrieve(url, dst + ".new")
        os.replace(dst + ".new", dst)
        log(f"[+] 已更新 {dst}")
    if not getattr(args, "no_restart", False):
        r = subprocess.run(["systemctl", "restart", args.service])
        log(f"[+] systemctl restart {args.service} -> rc={r.returncode}")
    else:
        log("[i] 未自动重启；执行 systemctl restart " + args.service + " 生效")


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("serve", "init", "list", "add-user", "del-user", "update", "version", "-h", "--help"):
        sys.argv.insert(1, "serve")  # 兼容旧的无子命令用法

    ap = argparse.ArgumentParser(prog="xray-sub-server", description="Xray Reality -> Clash 订阅服务")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("serve", help="启动订阅服务")
    common_args(sp)
    sp.add_argument("--token"); sp.add_argument("--secret")
    sp.add_argument("--listen", default="0.0.0.0"); sp.add_argument("--port", type=int, default=8081)
    sp.add_argument("--tls-cert", default=""); sp.add_argument("--tls-key", default="")
    sp.set_defaults(func=cmd_serve)

    ip = sub.add_parser("init", help="注册 systemd、启动并打印订阅链接")
    common_args(ip)
    ip.add_argument("--token"); ip.add_argument("--secret"); ip.add_argument("--port", type=int, default=8081)
    ip.set_defaults(func=cmd_init)

    au = sub.add_parser("add-user", help="在 Xray 配置里新增用户并打印其订阅链接")
    common_args(au)
    au.add_argument("--email", required=True)
    au.add_argument("--file", default="")
    au.add_argument("--secret", default="")
    au.add_argument("--port", type=int, default=8081)
    au.add_argument("--no-restart", action="store_true")
    au.set_defaults(func=cmd_add_user)

    du = sub.add_parser("del-user", help="删除用户（其 token 立即失效）")
    common_args(du)
    du.add_argument("--email", required=True)
    du.add_argument("--file", default="")
    du.add_argument("--no-restart", action="store_true")
    du.set_defaults(func=cmd_del_user)

    lp = sub.add_parser("list", help="列出订阅链接")
    common_args(lp)
    lp.add_argument("--token"); lp.add_argument("--secret"); lp.add_argument("--port", type=int, default=8081)
    lp.set_defaults(func=cmd_list)

    up = sub.add_parser("update", help="拉取最新程序与模板并重启")
    up.add_argument("--repo-raw", default=DEFAULT_REPO)
    up.add_argument("--dir", default="/opt/xray-sub")
    up.add_argument("--service", default="xray-sub")
    up.add_argument("--no-restart", action="store_true")
    up.set_defaults(func=cmd_update)

    vp = sub.add_parser("version", help="显示版本")
    vp.set_defaults(func=lambda a: print(f"xray-sub-server {VERSION}"))

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
