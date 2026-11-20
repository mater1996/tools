#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xray-sub-server  v1.4.0
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

VERSION = "1.4.0"
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


def _reality_inbounds(f):
    try:
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return None
    out = [ib for ib in (d.get("inbounds") or [])
           if ib.get("protocol") == "vless" and (ib.get("streamSettings") or {}).get("security") == "reality"]
    return (d, out) if out else None


def _reality_files(conf_dir):
    return [f for f in sorted(glob.glob(os.path.join(conf_dir, "*.json"))) if _reality_inbounds(f)]


def load_nodes(conf_dir, xray_bin, base_name):
    nodes = []
    for f in _reality_files(conf_dir):
        parsed = _reality_inbounds(f)
        if not parsed:
            continue
        d, inbounds = parsed
        for ib in inbounds:
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
                log(f"[warn] {os.path.basename(f)}: 字段不完整，跳过")
                continue
            for c in clients:
                if not c.get("id"):
                    continue
                nodes.append({
                    "email": c.get("email") or c["id"],
                    "uuid": c["id"],
                    "flow": c.get("flow") or "xtls-rprx-vision",
                    "port": int(port), "sni": sni, "pub": pub, "sid": sid,
                })
    for i, n in enumerate(nodes):
        n["name"] = base_name if i == 0 else f"{base_name}-{i + 1}"
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
        sel = []
        for i, n in enumerate(g[email]):
            nn = dict(n)
            nn["name"] = self.args.name if i == 0 else f"{self.args.name}-{i + 1}"
            sel.append(nn)
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
    p.add_argument("--name", default="JP-Reality")
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
    cmd_list(args)


def cmd_list(args):
    fill_defaults(args)
    users = load_users()
    umeta = {e: v for e, v in users.items() if e != "_meta"}
    try:
        xray_emails = set(group_by_email(load_nodes(args.conf_dir, args.xray_bin, args.name)))
    except Exception:
        xray_emails = set()
    all_emails = sorted(xray_emails | set(umeta))
    if not all_emails:
        log("[i] Xray 和 users.json 里都没有用户")
        return
    for email in all_emails:
        u = umeta.get(email, {})
        links = u.get("links", []) or []
        quota = u.get("quota_gb", 0) or 0
        if links:
            for ln in links:
                print(f"{email}\t{sub_url(args, ln['token'])}\tquota={quota}GB")
        else:
            tag = "" if email in xray_emails else " [不在Xray]"
            print(f"{email}\t(未纳管{tag}，运行: xray-sub add-sub --email {email})")


def _write_link(args, email, ln):
    print(f"{email}\t{sub_url(args, ln['token'])}")


def cmd_add_user(args):
    if os.geteuid() != 0:
        log("[x] add-user 需要 root")
        sys.exit(1)
    files = _reality_files(args.conf_dir)
    if not files:
        log("[x] 没找到 vless-reality 配置")
        sys.exit(1)
    f = args.file or files[0]
    d = _load_cfg(f)
    for ib in d.get("inbounds", []) or []:
        if ib.get("protocol") != "vless":
            continue
        cl = ib.setdefault("settings", {}).setdefault("clients", [])
        if any(c.get("email") == args.email for c in cl):
            log(f"[x] 用户已存在: {args.email}")
            sys.exit(1)
        uuid = subprocess.run([args.xray_bin, "uuid"], capture_output=True, text=True).stdout.strip()
        cl.append({"id": uuid, "flow": "xtls-rprx-vision", "email": args.email, "level": 0})
        break
    _save_cfg(f, d)
    log(f"[+] 已添加 {args.email} -> {f}")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")
    users = load_users()
    u = get_user(users, args.email)
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
    args.server = args.server or detect_public_ip()
    _write_link(args, args.email, ln)


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
    files = _reality_files(args.conf_dir)
    if not files:
        log("[x] 没找到 vless-reality 配置")
        sys.exit(1)
    f = args.file or files[0]
    d = _load_cfg(f)
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
    _save_cfg(f, d)
    users = load_users()
    if args.email in users:
        del users[args.email]
        save_users(users)
    log(f"[+] 已删除 {args.email}，其所有链接立即失效")
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "xray"])
        log("[+] 已重启 xray")


def _load_cfg(f):
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)


def _save_cfg(f, d):
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=4)


def cmd_update(args):
    import urllib.request
    os.makedirs(args.dir, exist_ok=True)
    for fn in ("xray-sub-server.py", "template.yaml"):
        url = f"{args.repo_raw}/{fn}"
        dst = os.path.join(args.dir, fn)
        log(f"[+] 下载 {url}")
        req = urllib.request.Request(
            url, headers={"Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "xray-sub"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        with open(dst + ".new", "wb") as fh:
            fh.write(data)
        os.replace(dst + ".new", dst)
        log(f"[+] 已更新 {dst}")
    if not getattr(args, "no_restart", False):
        r = subprocess.run(["systemctl", "restart", args.service])
        log(f"[+] systemctl restart {args.service} -> rc={r.returncode}")
    else:
        log("[i] 未自动重启；执行 systemctl restart " + args.service + " 生效")


def main():
    names = ("serve", "init", "list", "add-user", "add-sub", "add-link", "del-sub", "del-link", "set-user",
             "set-total", "del-user", "update", "version", "-h", "--help")
    if len(sys.argv) > 1 and sys.argv[1] not in names:
        sys.argv.insert(1, "serve")

    ap = argparse.ArgumentParser(prog="xray-sub-server", description="按 Xray 用户分发 Clash 订阅")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("serve"); common_args(sp)
    sp.add_argument("--listen", default="0.0.0.0")
    sp.add_argument("--tls-cert", default=""); sp.add_argument("--tls-key", default="")
    sp.set_defaults(func=cmd_serve)

    ip = sub.add_parser("init"); common_args(ip); ip.set_defaults(func=cmd_init)

    lp = sub.add_parser("list"); common_args(lp); lp.set_defaults(func=cmd_list)

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
