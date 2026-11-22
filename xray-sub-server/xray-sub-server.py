#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xray-sub-server  v1.5.6
按 Xray 用户分发订阅。每个用户可拥有多个订阅链接；
链接首次被拉取时绑定来源 IP，之后只允许该 IP 刷新（防分享）。

数据文件 users.json:
{
  "email": {
    "quota_gb": 100, "expire": 1797...,
    "links": [ {"token": "....", "ip": "1.2.3.4", "created": 1797...} ]
  }
}

子命令:
  serve      启动订阅服务
  init       注册 systemd、启动并打印链接
  list       列出每个用户的链接与绑定 IP
  add-user   新增 Xray 用户并生成首个链接
  add-link   给已有用户追加一个链接(多设备)
  unlink     解绑某链接的 IP(换网络时用)
  set-user   设置额度/到期
  del-user   删除用户
  update     更新程序与模板并重启
  version    版本
"""
import argparse
import glob
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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

VERSION = "1.5.6"
DEFAULT_REPO = "https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server"
SVC_PATH = "/etc/systemd/system/xray-sub.service"
USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
APP = None
_pub_cache = {}


def log(m):
    print(m, file=sys.stderr, flush=True)


# ---------------- 用户数据 ----------------
def load_users():
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(d):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


def find_link(users, token):
    """按 token 找到 (email, link_dict)。"""
    for email, u in users.items():
        for ln in u.get("links", []) or []:
            if hmac.compare_digest(str(ln.get("token", "")), token or ""):
                return email, ln
    return None, None


def new_link():
    return {"token": secrets.token_hex(16), "ip": "", "created": int(time.time())}


def get_user(users, email):
    return users.setdefault(email, {"quota_gb": 0, "expire": 0, "links": []})


# ---------------- systemd 参数 ----------------
def service_defaults():
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


# ---------------- Xray 配置解析 ----------------
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


def _conf_files(conf_dir):
    return sorted(glob.glob(os.path.join(conf_dir, "*.json")))


def _parse_conf(f):
    """解析一个配置文件，返回 (路径, 完整字典, {vless:[入站], hysteria:[入站]})。

    只认 vless+reality 和 hysteria 两类入站，其他协议忽略。
    """
    try:
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return None
    groups = {"vless": [], "hysteria": []}
    for ib in d.get("inbounds") or []:
        proto = ib.get("protocol")
        ss = ib.get("streamSettings") or {}
        if proto == "vless" and ss.get("security") == "reality":
            groups["vless"].append(ib)
        elif proto == "hysteria":
            groups["hysteria"].append(ib)
    return (f, d, groups) if (groups["vless"] or groups["hysteria"]) else None


def _reality_inbounds(f):
    """兼容旧接口：只返回 vless+reality 入站。"""
    parsed = _parse_conf(f)
    if not parsed or not parsed[2]["vless"]:
        return None
    return (parsed[1], parsed[2]["vless"])


def _reality_files(conf_dir):
    return [f for f in _conf_files(conf_dir) if _reality_inbounds(f)]


def load_nodes(conf_dir, xray_bin, base_name="Materonix-JP"):
    """读取所有配置，返回节点列表。每个节点带 proto 字段（vless / hysteria2）。"""
    nodes = []
    for f in _conf_files(conf_dir):
        parsed = _parse_conf(f)
        if not parsed:
            continue
        _, _, groups = parsed

        # ---- vless + reality ----
        for ib in groups["vless"]:
            ss = ib.get("streamSettings") or {}
            rs = ss.get("realitySettings") or {}
            clients = ((ib.get("settings") or {}).get("clients")) or []
            port = ib.get("listen_port") or ib.get("port")
            target = rs.get("dest") or rs.get("target") or ""
            sns = rs.get("serverNames") or []
            sni = next((s for s in sns if s), "") or (target.split(":")[0] if target else "")
            sid = (rs.get("shortIds") or [""])[0]
            pub = pubkey_from_priv(xray_bin, rs.get("privateKey") or "")
            if not (pub and sni and port):
                log(f"[warn] {os.path.basename(f)}: reality 字段不完整，跳过")
                continue
            for c in clients:
                if not c.get("id"):
                    continue
                nodes.append({
                    "proto": "vless",
                    "email": c.get("email") or c["id"],
                    "uuid": c["id"],
                    "flow": c.get("flow") or "xtls-rprx-vision",
                    "port": int(port), "sni": sni, "pub": pub, "sid": sid,
                })

        # ---- hysteria2 ----
        for ib in groups["hysteria"]:
            ss = ib.get("streamSettings") or {}
            settings = ib.get("settings") or {}
            users = settings.get("users") or []
            hs = ss.get("hysteriaSettings") or {}
            global_auth = hs.get("auth") or ""
            port = ib.get("listen_port") or ib.get("port")
            tls = ss.get("tlsSettings") or {}
            sni = tls.get("serverName") or ""
            if not port:
                log(f"[warn] {os.path.basename(f)}: hysteria 缺少端口，跳过")
                continue
            if not users:
                if global_auth:
                    log(f"[warn] {os.path.basename(f)}: hysteria 用全局 auth 而非 users[]，"
                        f"无法按用户分发（运行 xray-sub sync 生成 users）")
                continue
            for u in users:
                auth = u.get("auth") or ""
                email = u.get("email") or ""
                if not (auth and email):
                    continue
                nodes.append({
                    "proto": "hysteria2",
                    "email": email,
                    "auth": auth,
                    "port": int(port),
                    "sni": sni,
                })

    # 命名：vless 用 base_name（多个则 -2/-3），hy2 用 base_name-Hy2（多个则 -2/-3）
    counters = {"vless": 0, "hysteria2": 0}
    for n in nodes:
        proto = n["proto"]
        idx = counters[proto]
        counters[proto] += 1
        if proto == "hysteria2":
            n["name"] = f"{base_name}-Hy2" if idx == 0 else f"{base_name}-Hy2-{idx + 1}"
        else:
            n["name"] = base_name if idx == 0 else f"{base_name}-{idx + 1}"
    return nodes


def group_by_email(nodes):
    d = {}
    for n in nodes:
        d.setdefault(n["email"], []).append(n)
    return d


# ---------------- 订阅生成 ----------------
def gen_proxies_lines(nodes, server):
    lines = []
    for n in nodes:
        if n.get("proto") == "hysteria2":
            lines += [
                f'  - name: "{n["name"]}"',
                '    type: hysteria2',
                f'    server: {server}',
                f'    port: {n["port"]}',
                f'    password: "{n["auth"]}"',
                '    udp: true',
            ]
            # 233boy 生成的 hy2 用自签证书且不带 serverName，
            # 所以 skip-cert-verify 必须无条件输出，否则客户端握手直接失败（表现为超时）
            sni = n.get("sni") or "www.bing.com"
            lines.append(f'    sni: {sni}')
            lines.append('    skip-cert-verify: true')
            continue
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
            '      support-x25519mlkem768: true',
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


def inject_template(template_text, nodes, server, base_name="Materonix-JP", group_name=""):
    """把节点写入模板的 proxies 段，并把策略组里对占位名的引用换成实际节点名。

    模板里的策略组用 `- JP-Reality` 作为占位（脱敏后的固定写法），
    实际渲染时替换为当前用户的所有节点，hy2 排在 vless 之前（fallback 优先走 hy2）。
    """
    proxies = gen_proxies_lines(nodes, server)
    node_names = [n["name"] for n in nodes]

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

    # 重写策略组里的占位引用：任何 `- JP-Reality` 行展开成实际节点列表
    pat = re.compile(r'^(\s*)- JP-Reality\s*$')
    rewritten = []
    for ln in out:
        m = pat.match(ln)
        if m:
            indent = m.group(1)
            for nm in node_names:
                rewritten.append(f"{indent}- {nm}")
        else:
            rewritten.append(ln)

    result = "\n".join(rewritten) + "\n"
    if group_name and group_name != "Materonix":
        result = result.replace("Materonix", group_name)
    return result


# ---------------- 用量 ----------------
_stats_cache = {"ts": 0.0, "data": {}}


def query_user_stats(xray_bin, api_addr="127.0.0.1:10085", ttl=60):
    now = time.time()
    if now - _stats_cache["ts"] < ttl:
        return _stats_cache["data"]
    data = {}
    try:
        out = subprocess.run(
            [xray_bin, "api", "statsquery", f"--server={api_addr}", "-pattern", "user"],
            capture_output=True, text=True, timeout=5).stdout
        j = json.loads(out or "{}")
        for s in j.get("stat", []) or []:
            name = s.get("name", "")
            try:
                val = int(str(s.get("value", "0")))
            except Exception:
                val = 0
            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user":
                email, kind = parts[1], parts[3]
                d = data.setdefault(email, {"up": 0, "down": 0})
                if kind == "uplink":
                    d["up"] += val
                elif kind == "downlink":
                    d["down"] += val
    except Exception as e:
        log(f"[warn] stats 查询失败: {e}")
    _stats_cache["ts"] = now
    _stats_cache["data"] = data
    return data


# ---------------- App / Handler ----------------
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

    def render_email(self, email):
        nodes = load_nodes(self.args.conf_dir, self.args.xray_bin, self.args.name)
        g = group_by_email(nodes)
        if email not in g:
            return None
        # load_nodes 已按协议分好名字（JP-Reality / JP-Reality-Hy2），这里直接沿用
        sel = [dict(n) for n in g[email]]
        if self.template:
            return inject_template(self.template, sel, self.server, self.args.name,
                                   getattr(self.args, "group_name", ""))
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
    for pre in ("sub/", "clash/"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p


def client_ip(handler):
    xff = handler.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return handler.client_address[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "xray-sub/1.4"

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/")
        token = extract_token(self, p)
        users = load_users()
        email, ln = find_link(users, token)
        if not email:
            self.send_error(404, "invalid token")
            return
        exp = int((users.get(email, {}) or {}).get("expire", 0) or 0)
        if exp and exp < time.time():
            self.send_error(403, "subscription expired")
            return
        ln["last_seen"] = int(time.time())
        ln["hits"] = int(ln.get("hits", 0)) + 1
        save_users(users)
        try:
            body = APP.render_email(email)
        except Exception as e:
            log(f"[error] {e}")
            self.send_error(503, str(e))
            return
        if body is None:
            self.send_error(404, "user not found in xray")
            return
        data = body.encode("utf-8")
        name_hint = APP.profile_title or getattr(APP.args, "group_name", "") or APP.args.name or "xray-sub"
        fname = name_hint[:-5] if name_hint.endswith(".yaml") else name_hint
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(fname, safe=""))
        self.send_header("Profile-Update-Interval", "12")
        self.send_header("Cache-Control", "no-store")
        info = self.userinfo(email)
        if info:
            self.send_header("Subscription-Userinfo", info)
        self.end_headers()
        self.wfile.write(data)
        log(f"[ok] {self.address_string()} -> {email} ({len(data)} bytes)")

    def userinfo(self, email):
        a = APP.args
        try:
            stats = query_user_stats(a.xray_bin, getattr(a, "stats_api", "127.0.0.1:10085"))
        except Exception:
            stats = {}
        st = stats.get(email, {"up": 0, "down": 0})
        parts = [f"upload={st['up']}", f"download={st['down']}"]
        users = load_users()
        meta = users.get("_meta", {}) or {}
        u = users.get(email, {}) or {}
        quota = float(u.get("quota_gb", 0) or 0)
        total = float(meta.get("total_gb", 0) or 0)
        if total > 0 and meta.get("owner") == email:
            # 所有者拿「总量 - 其他人已分配」的剩余
            others = sum(float(x.get("quota_gb", 0) or 0)
                         for e, x in users.items() if e not in ("_meta", email))
            quota = max(0.0, total - others)
        if quota > 0:
            parts.append(f"total={int(quota * 1024 ** 3)}")
        exp = int(u.get("expire", 0) or 0)
        if exp > 0:
            parts.append(f"expire={exp}")
        return "; ".join(parts)

    def log_message(self, fmt, *args):
        pass


# ---------------- CLI ----------------
def common_args(p):
    p.add_argument("--conf-dir", default="/etc/xray/conf")
    p.add_argument("--xray-bin", default="/etc/xray/bin/xray")
    p.add_argument("--name", default="Materonix-JP",
                   help="节点名前缀。vless 用 <name>，hy2 用 <name>-Hy2；不要和策略组名相同")
    p.add_argument("--group-name", default="", help="替换模板里的策略组名 XQ-Network")
    p.add_argument("--template", default="")
    p.add_argument("--server", default="")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--stats-api", default="127.0.0.1:10085")


def url_base(args):
    scheme = "https" if getattr(args, "tls_cert", "") else "http"
    ip = args.server or detect_public_ip() or "<公网IP>"
    return f"{scheme}://{ip}:{getattr(args, 'port', 8081)}"


def sub_url(args, token):
    return f"{url_base(args)}/sub?token={token}"


def cmd_serve(args):
    global APP
    fill_defaults(args)
    APP = App(args)
    users = load_users()
    emails = [e for e in users if e != "_meta" and users[e].get("links")]
    if not emails:
        log("[x] users.json 里没有任何用户链接，先 xray-sub add-user")
        sys.exit(1)
    httpd = ThreadingHTTPServer((args.listen, args.port), Handler)
    scheme = "http"
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    log(f"[+] 订阅服务已启动: {url_base(args)}/sub?token=<token>  ({len(emails)} 个用户)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("[+] 已停止")


def cmd_init(args):
    if os.geteuid() != 0:
        log("[x] init 需要 root")
        sys.exit(1)
    d = service_defaults()
    tmpl = args.template or os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.yaml")
    if not os.path.exists(tmpl):
        tmpl = ""
    exe = sys.executable or "/usr/bin/python3"
    script = os.path.abspath(__file__)
    parts = [exe, script, "serve", "--conf-dir", args.conf_dir, "--xray-bin", args.xray_bin,
             "--port", str(args.port), "--name", args.name]
    if args.server:
        parts += ["--server", args.server]
    if args.group_name:
        parts += ["--group-name", args.group_name]
    if tmpl:
        parts += ["--template", tmpl]
    if getattr(args, "stats_api", "") and args.stats_api != "127.0.0.1:10085":
        parts += ["--stats-api", args.stats_api]
    unit = ("[Unit]\nDescription=Xray Subscription Server\nAfter=network.target\n\n"
            "[Service]\n" f"ExecStart={' '.join(parts)}\n" "Restart=always\nRestartSec=3\n\n"
            "[Install]\nWantedBy=multi-user.target\n")
    with open(SVC_PATH, "w", encoding="utf-8") as f:
        f.write(unit)
    log(f"[+] 已写入 {SVC_PATH}")
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "--now", "xray-sub"])
    time.sleep(1)
    if subprocess.run(["systemctl", "is-active", "--quiet", "xray-sub"]).returncode != 0:
        log("[x] 启动失败，journalctl -u xray-sub -n 30 查看")
        sys.exit(1)
    log("[+] 服务已启动")
    args.server = args.server or detect_public_ip()
    cmd_status(args)


def _gb(b):
    return f"{float(b) / (1024 ** 3):.2f}"


def _mb(b):
    return f"{float(b) / (1024 ** 2):.2f}"


def cmd_status(args):
    fill_defaults(args)
    users = load_users()
    meta = users.get("_meta", {}) or {}
    total = float(meta.get("total_gb", 0) or 0) * 1024 ** 3
    owner = meta.get("owner", "")
    try:
        stats = query_user_stats(args.xray_bin, getattr(args, "stats_api", "127.0.0.1:10085"))
    except Exception:
        stats = {}
    try:
        xray_emails = set(group_by_email(load_nodes(args.conf_dir, args.xray_bin, args.name)))
    except Exception:
        xray_emails = set()
    umeta = {e: v for e, v in users.items() if e != "_meta"}
    all_emails = sorted(xray_emails | set(umeta))
    used_total = sum(stats.get(e, {}).get("up", 0) + stats.get(e, {}).get("down", 0) for e in all_emails)
    if total:
        print(f"全局: 已用 {_mb(used_total)} MB / {_gb(total)} GB | 剩余 {_gb(max(0, total - used_total))} GB")
    else:
        print(f"全局: 已用 {_mb(used_total)} MB (总量未设置)")
    print("-" * 56)
    if not all_emails:
        print("(没有用户)")
        return
    for email in all_emails:
        u = umeta.get(email, {})
        st = stats.get(email, {"up": 0, "down": 0})
        used = st.get("up", 0) + st.get("down", 0)
        quota = float(u.get("quota_gb", 0) or 0) * 1024 ** 3
        if total and owner == email:
            others = sum(float(x.get("quota_gb", 0) or 0) for e, x in umeta.items() if e != email) * 1024 ** 3
            quota = max(0.0, total - others)
        qstr = f"{_gb(quota)} GB" if quota else "无限制"
        tag = "" if email in xray_emails else "  [账号已不在Xray]"
        print(f"{email}{tag}  已用 {_mb(used)} MB / 额度 {qstr}")
        links = u.get("links", []) or []
        if links:
            now = time.time()
            for ln in links:
                seen = int(ln.get("last_seen", 0) or 0)
                if seen:
                    mins = int((now - seen) / 60)
                    ago = f"{mins}分钟前" if mins < 60 else f"{mins // 60}小时前"
                    tail = f"最近拉取: {ago}"
                else:
                    tail = "未拉取"
                print(f"    {sub_url(args, ln['token'])}  ({tail})")
        else:
            print(f"    (未纳管，运行: xray-sub add-sub --email {email})")


def _write_link(args, email, ln):
    print(f"{email}\t{sub_url(args, ln['token'])}")


def cmd_add_user(args):
    if os.geteuid() != 0:
        log("[x] add-user 需要 root")
        sys.exit(1)
    if not (_reality_files(args.conf_dir) or _parse_conf_files_any(args.conf_dir)):
        log("[x] 没找到 vless-reality 或 hysteria 配置")
        sys.exit(1)

    users = load_users()
    if args.email in users and users[args.email].get("vless_id"):
        log(f"[x] 用户已存在: {args.email}")
        sys.exit(1)

    u = get_user(users, args.email)
    u["vless_id"] = _gen_uuid(args.xray_bin)
    u["hy2_auth"] = _gen_auth()
    if args.quota_gb:
        u["quota_gb"] = args.quota_gb
    if args.expire_days:
        u["expire"] = int(time.time()) + args.expire_days * 86400
    if args.expire:
        try:
            u["expire"] = int(args.expire)
        except Exception:
            pass
    ln = new_link()
    u.setdefault("links", []).append(ln)
    save_users(users)

    vless_n, hy2_n, files = sync_conf_files(args.conf_dir, args.xray_bin, users)
    log(f"[+] 已添加 {args.email} -> {', '.join(files) or '无配置'}")
    log(f"    vless clients: {vless_n} | hysteria users: {hy2_n}")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")
    args.server = args.server or detect_public_ip()
    _write_link(args, args.email, ln)


def _parse_conf_files_any(conf_dir):
    """只要有 vless 或 hysteria 入站就算有配置。"""
    for f in _conf_files(conf_dir):
        if _parse_conf(f):
            return [f]
    return []


MAX_LINKS = 5


def cmd_add_link(args):
    users = load_users()
    u = get_user(users, args.email)
    links = u.setdefault("links", [])
    if len(links) >= MAX_LINKS:
        log(f"[x] {args.email} 已有 {len(links)} 个链接（上限 {MAX_LINKS}），先 del-sub 删一个")
        sys.exit(1)
    ln = new_link()
    links.append(ln)
    save_users(users)
    args.server = args.server or detect_public_ip()
    _write_link(args, args.email, ln)


def cmd_del_link(args):
    users = load_users()
    email, ln = find_link(users, args.token)
    if not email:
        log("[x] token 不存在")
        sys.exit(1)
    users[email]["links"].remove(ln)
    save_users(users)
    log(f"[+] 已删除 {email} 的链接 {args.token[:8]}...")


def cmd_set_user(args):
    users = load_users()
    u = get_user(users, args.email)
    if args.quota_gb is not None:
        u["quota_gb"] = args.quota_gb
    if args.expire_days:
        u["expire"] = int(time.time()) + args.expire_days * 86400
    if args.expire:
        try:
            u["expire"] = int(args.expire)
        except Exception:
            log("[x] --expire 需为 Unix 时间戳")
            sys.exit(1)
    if args.clear:
        u["quota_gb"] = 0
        u["expire"] = 0
    save_users(users)
    log(f"[+] {args.email}: quota={u.get('quota_gb')}GB expire={u.get('expire')}")


def cmd_set_total(args):
    users = load_users()
    meta = users.setdefault("_meta", {})
    if args.total_gb is not None:
        meta["total_gb"] = args.total_gb
    if args.owner:
        meta["owner"] = args.owner
    save_users(users)
    log(f"[+] 总量池: total={meta.get('total_gb')}GB owner={meta.get('owner')}")


def cmd_del_user(args):
    if os.geteuid() != 0:
        log("[x] del-user 需要 root")
        sys.exit(1)
    users = load_users()
    if args.email not in users:
        log(f"[x] 没找到用户: {args.email}")
        sys.exit(1)
    del users[args.email]
    save_users(users)

    vless_n, hy2_n, files = sync_conf_files(args.conf_dir, args.xray_bin, users)
    log(f"[+] 已删除 {args.email}，其所有链接立即失效")
    log(f"    已从 {', '.join(files) or '无配置'} 移除 | "
        f"vless clients: {vless_n} | hysteria users: {hy2_n}")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")


def cmd_expire(args):
    """停用已过期用户：从 users.json 保留记录但不再写入配置，节点立即连不上。"""
    if os.geteuid() != 0:
        log("[x] expire 需要 root")
        sys.exit(1)
    users = load_users()
    now = time.time()
    expired = [e for e, u in users.items()
               if e != "_meta" and int(u.get("expire", 0) or 0) and int(u.get("expire", 0)) < now]
    if not expired:
        log("[i] 没有过期用户")
        return
    vless_n, hy2_n, files = sync_conf_files(args.conf_dir, args.xray_bin, users)
    log(f"[+] 已停用过期用户: {', '.join(expired)}（节点已断）")
    log(f"    剩余有效 | vless clients: {vless_n} | hysteria users: {hy2_n}")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")


def _load_cfg(f):
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)


def _save_cfg(f, d):
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=4)


# ---------------- 用户同步（users.json -> vless clients + hy2 users）------
def _gen_uuid(xray_bin):
    try:
        u = subprocess.run([xray_bin, "uuid"], capture_output=True, text=True, timeout=5).stdout.strip()
        if u:
            return u
    except Exception:
        pass
    return str(uuid.uuid4())


def _gen_auth():
    """Hy2 的 auth 可以是任意字符串，用 32 位随机 hex。"""
    return secrets.token_hex(16)


def ensure_credentials(users, xray_bin):
    """给每个用户补齐 vless_id / hy2_auth。已有值保持不变，保证订阅不失效。"""
    changed = False
    for email, u in users.items():
        if email == "_meta":
            continue
        if not u.get("vless_id"):
            u["vless_id"] = _gen_uuid(xray_bin)
            changed = True
        if not u.get("hy2_auth"):
            u["hy2_auth"] = _gen_auth()
            changed = True
    return changed


def _active_users(users):
    """未过期的用户。"""
    now = time.time()
    out = {}
    for email, u in users.items():
        if email == "_meta":
            continue
        exp = int(u.get("expire", 0) or 0)
        if exp and exp < now:
            continue
        out[email] = u
    return out


def sync_conf_files(conf_dir, xray_bin, users):
    """把 users.json 的用户写进所有 vless-reality 和 hysteria 入站。

    返回 (vless 写入数, hy2 写入数, 涉及的文件列表)。
    配置文件由本工具独占管理：clients[] / users[] 会被完全重写为当前有效用户。
    """
    active = _active_users(users)
    vless_n = hy2_n = 0
    touched = []
    for f in _conf_files(conf_dir):
        parsed = _parse_conf(f)
        if not parsed:
            continue
        _, d, groups = parsed
        dirty = False

        for ib in groups["vless"]:
            cl = []
            for email, u in active.items():
                if not u.get("vless_id"):
                    continue
                cl.append({
                    "id": u["vless_id"],
                    "flow": "xtls-rprx-vision",
                    "email": email,
                    "level": 0,
                })
            ib.setdefault("settings", {})["clients"] = cl
            vless_n += len(cl)
            dirty = True

        for ib in groups["hysteria"]:
            ul = []
            for email, u in active.items():
                if not u.get("hy2_auth"):
                    continue
                ul.append({"auth": u["hy2_auth"], "level": 0, "email": email})
            ib.setdefault("settings", {})["users"] = ul
            # users[] 存在时 hysteriaSettings.auth 会被覆盖，清掉避免误导
            hs = (ib.get("streamSettings") or {}).get("hysteriaSettings")
            if isinstance(hs, dict) and "auth" in hs:
                hs.pop("auth", None)
            hy2_n += len(ul)
            dirty = True

        if dirty:
            _save_cfg(f, d)
            touched.append(os.path.basename(f))
    return vless_n, hy2_n, touched


def cmd_sync(args):
    """把 users.json 同步到 Xray 配置（vless clients + hy2 users）。"""
    if os.geteuid() != 0:
        log("[x] sync 需要 root")
        sys.exit(1)
    users = load_users()
    real = {e: v for e, v in users.items() if e != "_meta"}
    if not real:
        log("[x] users.json 里没有用户")
        sys.exit(1)
    if ensure_credentials(users, args.xray_bin):
        save_users(users)
        log("[+] 已为缺失的用户生成 vless_id / hy2_auth")
    vless_n, hy2_n, files = sync_conf_files(args.conf_dir, args.xray_bin, users)
    if not files:
        log("[x] 没找到 vless-reality 或 hysteria 配置")
        sys.exit(1)
    log(f"[+] 已同步到 {', '.join(files)}")
    log(f"    vless clients: {vless_n} 条 | hysteria users: {hy2_n} 条")
    if not args.no_restart:
        r = subprocess.run(["systemctl", "restart", "xray"])
        if r.returncode == 0:
            log("[+] 已重启 xray")
        else:
            log("[!] xray 重启失败，检查 systemctl status xray")
    else:
        log("[i] 未重启；执行 systemctl restart xray 生效")


def cmd_import(args):
    """从现有 Xray 配置导入用户到 users.json（首次接管时用，不改配置文件）。"""
    users = load_users()
    found = {}
    for f in _conf_files(args.conf_dir):
        parsed = _parse_conf(f)
        if not parsed:
            continue
        _, _, groups = parsed
        for ib in groups["vless"]:
            for c in ((ib.get("settings") or {}).get("clients") or []):
                email, uid = c.get("email"), c.get("id")
                if email and uid:
                    found.setdefault(email, {})["vless_id"] = uid
        for ib in groups["hysteria"]:
            for u in ((ib.get("settings") or {}).get("users") or []):
                email, auth = u.get("email"), u.get("auth")
                if email and auth:
                    found.setdefault(email, {})["hy2_auth"] = auth
    if not found:
        log("[i] 现有配置里没有可导入的用户")
        return
    added = updated = 0
    for email, cred in found.items():
        u = get_user(users, email)
        for k, v in cred.items():
            if u.get(k) != v:
                u[k] = v
                updated += 1
        if not u.get("links"):
            added += 1
    save_users(users)
    log(f"[+] 导入 {len(found)} 个用户（{added} 个新建，{updated} 个凭据更新）")
    log("    users.json 已保存；配置文件未改动")
    log("    如需补齐缺失凭据并统一格式，运行: xray-sub sync")


def cmd_rename(args):
    """修改节点名前缀：更新 users 之外的全部相关处（systemd 参数 + 模板占位）。

    节点名不进 users.json，只由 serve 的 --name 决定，所以改 systemd 即可。
    """
    if os.geteuid() != 0:
        log("[x] rename 需要 root")
        sys.exit(1)
    if not os.path.exists(SVC_PATH):
        log(f"[x] 未找到 {SVC_PATH}，先运行 xray-sub init")
        sys.exit(1)

    old = new = None
    lines = open(SVC_PATH, encoding="utf-8").read().splitlines()
    out = []
    for ln in lines:
        if ln.startswith("ExecStart=") and "--name" in ln:
            toks = ln.split()
            for i, t in enumerate(toks):
                if t == "--name" and i + 1 < len(toks):
                    old = toks[i + 1]
                    toks[i + 1] = args.new_name
                    break
            ln = " ".join(toks)
        out.append(ln)

    if old is None:
        log("[x] ExecStart 里没有 --name 参数，无法改名")
        sys.exit(1)
    if old == args.new_name:
        log(f"[i] 已经是 {args.new_name}，无需修改")
        return

    with open(SVC_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    log(f"[+] {SVC_PATH}: --name {old} -> {args.new_name}")

    subprocess.run(["systemctl", "daemon-reload"])
    r = subprocess.run(["systemctl", "restart", "xray-sub"])
    if r.returncode != 0:
        log("[!] 重启失败，检查 systemctl status xray-sub")
        sys.exit(1)
    log("[+] 已重启 xray-sub")
    log(f"    订阅里的节点名将变为：{args.new_name} / {args.new_name}-Hy2")
    log("    客户端更新订阅即可看到新名字（token 不变）")


def _fetch_url(url, timeout=30):
    """下载 URL，带 cache-bust 参数绕过 raw.githubusercontent.com 的 CDN 缓存。

    raw CDN 会按 URL 缓存数分钟到数小时，光加 Cache-Control 请求头没用，
    必须改查询串才能拿到最新内容。
    """
    import urllib.request
    sep = "&" if "?" in url else "?"
    bust = f"{url}{sep}_t={int(time.time())}"
    req = urllib.request.Request(bust, headers={
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
        "User-Agent": "xray-sub",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def cmd_update(args):
    os.makedirs(args.dir, exist_ok=True)
    for fn in ("xray-sub-server.py", "template.yaml"):
        url = f"{args.repo_raw}/{fn}"
        dst = os.path.join(args.dir, fn)
        log(f"[+] 下载 {url}")
        data = _fetch_url(url)
        if not data:
            log(f"[x] {fn} 下载为空，跳过")
            continue
        # 校验下载到的是 Python 脚本（防止 CDN 返回错误页）
        if fn.endswith(".py") and b"def main()" not in data:
            log(f"[x] {fn} 内容异常（不是完整脚本），放弃覆盖")
            sys.exit(1)
        with open(dst + ".new", "wb") as fh:
            fh.write(data)
        os.replace(dst + ".new", dst)
        log(f"[+] 已更新 {dst}（{len(data)} 字节）")

    # 打印更新后的版本，便于确认是否真的拿到新版
    try:
        with open(os.path.join(args.dir, "xray-sub-server.py"), encoding="utf-8") as fh:
            m = re.search(r'^VERSION = "([^"]+)"', fh.read(), re.M)
        if m:
            log(f"[+] 当前版本: {m.group(1)}")
    except Exception:
        pass

    if not getattr(args, "no_restart", False):
        r = subprocess.run(["systemctl", "restart", args.service])
        log(f"[+] systemctl restart {args.service} -> rc={r.returncode}")
    else:
        log("[i] 未自动重启；执行 systemctl restart " + args.service + " 生效")


def main():
    names = ("serve", "init", "status", "list", "add-user", "add-sub", "add-link", "del-sub", "del-link", "set-user",
             "set-total", "del-user", "expire", "sync", "import", "rename", "update", "version", "-h", "--help")
    if len(sys.argv) > 1 and sys.argv[1] not in names:
        sys.argv.insert(1, "serve")

    ap = argparse.ArgumentParser(prog="xray-sub-server", description="按 Xray 用户分发 Clash 订阅")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("serve"); common_args(sp)
    sp.add_argument("--listen", default="0.0.0.0")
    sp.add_argument("--tls-cert", default=""); sp.add_argument("--tls-key", default="")
    sp.set_defaults(func=cmd_serve)

    ip = sub.add_parser("init"); common_args(ip); ip.set_defaults(func=cmd_init)

    lp = sub.add_parser("status", aliases=["list"], help="查看全局/用户流量与订阅")
    common_args(lp); lp.set_defaults(func=cmd_status)

    au = sub.add_parser("add-user"); common_args(au)
    au.add_argument("--email", required=True); au.add_argument("--file", default="")
    au.add_argument("--no-restart", action="store_true")
    au.add_argument("--quota-gb", type=float, default=0); au.add_argument("--expire-days", type=int, default=0)
    au.add_argument("--expire", default="")
    au.set_defaults(func=cmd_add_user)

    al = sub.add_parser("add-sub", aliases=["add-link"], help="给账号新增一条订阅链接"); common_args(al); al.add_argument("--email", required=True)
    al.set_defaults(func=cmd_add_link)

    dl = sub.add_parser("del-sub", aliases=["del-link"], help="删除一条订阅链接"); dl.add_argument("--token", required=True)
    dl.set_defaults(func=cmd_del_link)

    su = sub.add_parser("set-user"); su.add_argument("--email", required=True)
    su.add_argument("--quota-gb", type=float, default=None); su.add_argument("--expire-days", type=int, default=0)
    su.add_argument("--expire", default=""); su.add_argument("--clear", action="store_true")
    su.set_defaults(func=cmd_set_user)

    stt = sub.add_parser("set-total", help="设置整机总量池与所有者")
    stt.add_argument("--total-gb", type=float, default=None)
    stt.add_argument("--owner", default="")
    stt.set_defaults(func=cmd_set_total)

    du = sub.add_parser("del-user"); common_args(du); du.add_argument("--email", required=True)
    du.add_argument("--file", default=""); du.add_argument("--no-restart", action="store_true")
    du.set_defaults(func=cmd_del_user)

    ex = sub.add_parser("expire", help="停用已过期用户（从 Xray 删除 client）")
    common_args(ex)
    ex.add_argument("--file", default="")
    ex.set_defaults(func=cmd_expire)

    sy = sub.add_parser("sync", help="把 users.json 同步到 vless clients 和 hy2 users")
    common_args(sy)
    sy.add_argument("--no-restart", action="store_true")
    sy.set_defaults(func=cmd_sync)

    im = sub.add_parser("import", help="从现有 Xray 配置导入用户到 users.json（首次接管时用）")
    common_args(im)
    im.set_defaults(func=cmd_import)

    rn = sub.add_parser("rename", help="修改节点名前缀（更新 systemd 并重启）")
    rn.add_argument("new_name", help="新的节点名前缀，如 Materonix-JP")
    rn.set_defaults(func=cmd_rename)

    up = sub.add_parser("update"); up.add_argument("--repo-raw", default=DEFAULT_REPO)
    up.add_argument("--dir", default="/opt/xray-sub"); up.add_argument("--service", default="xray-sub")
    up.add_argument("--no-restart", action="store_true")
    up.set_defaults(func=cmd_update)

    vp = sub.add_parser("version"); vp.set_defaults(func=lambda a: print(f"xray-sub-server {VERSION}"))

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help(); return
    args.func(args)


if __name__ == "__main__":
    main()
