# xray-sub-server

读取 Xray 配置（`/etc/xray/conf/*.json`），生成 Clash / mihomo 订阅，并通过**内置 HTTP(S) 服务**提供——不需要 nginx。

支持 **VLESS-REALITY** 和 **Hysteria2** 两种入站，同一用户可同时拿到两条线路的节点。

## 特性

- **热重载**：每次请求重新读 Xray 配置，改服务端节点客户端下次拉订阅自动更新
- **自动算公钥**：由 `privateKey` 调 `xray x25519` 推 `publicKey`
- **可套模板**：用自带 `template.yaml`（已脱敏），保留策略组/分流规则，只替换 `proxies`
- **多用户**：每个 Xray client 一个独立 token（HMAC 派生，删用户自动失效）
- **双协议**：`users.json` 是唯一真源，`sync` 同时写入 vless `clients[]` 和 hy2 `users[]`
- token 校验支持 `?token=`、`Authorization: Bearer <token>`、路径 `/<token>.yaml`

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

**只装工具，不启动。** 安装只做三件事：下载 `xray-sub-server.py` + `template.yaml`、生成全局命令 `xray-sub`。

GitHub 慢时 install.sh 会自动回退镜像；也可手动指定：

```bash
REPO_RAW=https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

## 初始化（注册 + 启动 + 出链接）

> **部署 Hysteria2 前必须先放行 UDP 端口。** 云厂商安全组默认只开 TCP，
> UDP 8443（或你选的端口）不放行的话，服务端 `ss -ulnp` 能看到监听、
> xray 日志也正常，但客户端一律超时——这个坑很难从服务端日志看出来。

```bash
xray-sub init
```

`init` 会：写好 systemd（开机自启）→ 启动服务 → **打印每个用户的订阅链接**。

- 单用户：自动生成随机 token；
- 多用户：`xray-sub init --secret $(openssl rand -hex 16)`，每人一个独立 token。

重复执行 `init` 会**复用已有 token/secret**，订阅地址不变。

## 命令

| 命令 | 作用 |
|---|---|
| `xray-sub init` | 注册 systemd、启动、打印订阅链接 |
| `xray-sub list` | 查看订阅链接（自动从已注册服务读参数） |
| `xray-sub serve` | 前台启动（调试用） |
| `xray-sub sync` | **把 users.json 同步到 vless clients + hy2 users** |
| `xray-sub import` | 从现有 Xray 配置导入用户到 users.json（首次接管） |
| `xray-sub rename <新名>` | 修改节点名前缀（更新 systemd 并重启，token 不变） |
| `xray-sub add-user` | 新增用户（自动生成 vless_id + hy2_auth 并同步） |
| `xray-sub del-user` | 删除用户（从两个入站一并移除） |
| `xray-sub expire` | 停用过期用户 |
| `xray-sub update` | 拉取最新程序与模板并重启服务 |
| `xray-sub version` | 版本 |

## 双协议：users.json 是唯一真源

每个用户在 `users.json` 里保存两套凭据：

```json
{
  "alice@example.com": {
    "vless_id": "550e8400-e29b-41d4-a716-446655440000",
    "hy2_auth": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "quota_gb": 100,
    "expire": 1797999999,
    "links": [{"token": "...", "ip": "1.2.3.4"}]
  }
}
```

`xray-sub sync` 会把它写进两个地方：

```json
// vless 入站
"clients": [{"id": "<vless_id>", "flow": "xtls-rprx-vision", "email": "...", "level": 0}]

// hysteria 入站
"users": [{"auth": "<hy2_auth>", "level": 0, "email": "..."}]
```

**密码各自独立随机**：`vless_id` 是 UUID，`hy2_auth` 是 32 位 hex。两者不需要相同，因为它们是两个独立入站的独立凭据。

同时 `sync` 会**清掉 `hysteriaSettings.auth`**——Xray 在存在 `users[]` 时会忽略它，留着只会误导。

### 订阅里的节点命名

```
Materonix-JP       ← vless（--name）
Materonix-JP-Hy2   ← hysteria2（--name + -Hy2）
```

Hy2 节点会插到所有策略组的**主节点之前**。模板里 `fallback` 组按顺序选第一个可用的，所以默认走 Hy2、Reality 兜底。

**节点名不能和策略组名相同。** 模板的主策略组叫 `Materonix`，节点叫 `Materonix-JP`，两者不同名——否则规则里的 `- Materonix` 会解析到节点而不是组，分流失效。

### 改节点名

节点名由 `serve` 的 `--name` 参数决定（写在 systemd 的 ExecStart 里），不在 `users.json` 中。改法：

```bash
xray-sub rename Materonix-JP
```

会自动改 systemd、daemon-reload、重启服务。**token 和用户凭据都不变**，客户端更新订阅即可看到新名字。

不要用 `xray-sub init` 改名——`init` 会用当前默认值重写整个 unit，把 `--server`、`--group-name` 等手工参数一并覆盖。

### 流量统计

两个入站都带 `email`，Xray 统一记到 `user>>>email>>>traffic>>>uplink/downlink`。现有的配额和统计逻辑不用改。

## 排障：Hy2 节点超时

按顺序排除，每步都能独立定位问题：

| 检查 | 命令 | 说明 |
|---|---|---|
| **① 安全组/防火墙放行 UDP** | 云控制台 → 安全组 → 入方向 | **最常见原因**。UDP 默认不放行，服务端一切正常但客户端全超时 |
| ② 服务端在监听 | `ss -ulnp \| grep 8443` | 有 `xray` 记录才算监听 |
| ③ 入站已加载 | `journalctl -u xray \| grep -i hysteria` | 应出现 `appended inbound with tag` |
| ④ 订阅含 skip-cert-verify | `curl -s "<订阅URL>" \| grep -A9 Hy2` | 自签证书缺这行 = 握手失败 |
| ⑤ 服务端收到包 | `journalctl -u xray -f \| grep -i hysteria`，然后客户端连一次 | 完全无日志 = 包没到（回到第 ① 步） |

**区分两种失败**：

- `Timeout`（超时）→ 包没到，或握手无响应 → 查安全组
- `An error occurred in the delay test`（协议错误）→ 包到了但握手失败 → 查证书、密码、版本

## 首次接管现有配置

如果 Xray 配置是 233boy 脚本生成的，先导入再同步：

```bash
xray-sub import    # 读现有配置，把 UUID/auth 存进 users.json（不改配置文件）
xray-sub sync      # 补齐缺失凭据，重写两个入站的用户列表
```

`import` 只读不写配置，所以现有用户的 UUID 不会变，订阅继续有效。

**注意**：接管后这两个配置文件由 `xray-sub` 独占管理。再用 `xray add` / `xray change` 改它们会被覆盖。

## 单用户

```bash
xray-sub init
xray-sub list
```

订阅：`http://<IP>:8081/sub?token=<token>`

## 多用户

Xray 的 `clients[]` 里每个用户建议带 `email`（没有则用 `id`）：

```bash
xray-sub init --secret <随机串>
xray-sub list
```

- token = `HMAC-SHA256(secret, email)[:32]`，**稳定不变**
- 每个用户的订阅**只含自己的节点**
- **删掉该 client 后，其 token 自动失效（404）**
- 加用户：Xray 配置里加一个 client，客户端下次拉订阅就有，无需改工具

## 更新

```bash
xray-sub update
```

或重跑 `install.sh` 后再 `xray-sub init`（复用凭据，地址不变）。

## 参数（init / serve / list 通用）

| 参数 | 默认 | 说明 |
|---|---|---|
| `--conf-dir` | `/etc/xray/conf` | Xray 配置目录 |
| `--xray-bin` | `/etc/xray/bin/xray` | xray 可执行文件 |
| `--token` | — | 单用户全局 token |
| `--secret` | — | 多用户密钥（启用多用户） |
| `--port` | `8081` | 监听端口 |
| `--server` | 自动探测 | 订阅里节点地址 |
| `--name` | `Materonix-JP` | 节点名前缀。vless 用 `<name>`，hy2 用 `<name>-Hy2`。**不要和策略组名相同** |
| `--template` | 自带 template.yaml | Clash 模板 YAML |

`serve` 另支持 `--listen`、`--tls-cert`、`--tls-key`。

## 额外节点（ws / Cloudflare 隧道等）

工具只解析 Reality 和 Hy2 入站。如果还有别的接入方式（例如 Cloudflare Tunnel 后面的
`vless + ws` 节点），把它写进 `/etc/xray-sub/extra-proxies.yaml`，会被原样追加到订阅的
`proxies` 段，并自动加入所有策略组。

文件内容是标准的 Clash 条目，注意缩进两格：

```yaml
  - name: "Materonix-CF"
    type: vless
    server: node.example.com
    port: 443
    uuid: <与 Reality 节点相同的 UUID>
    network: ws
    tls: true
    servername: node.example.com
    ws-opts:
      path: /ws
      headers:
        Host: node.example.com
```

- 文件不存在则行为与之前完全一致，不影响现有部署
- 以 `#` 开头的行会被忽略，可用于注释
- 可用环境变量 `XRAY_SUB_EXTRA` 覆盖路径
- 改完直接 `systemctl restart xray-sub`，不用改代码；加更多节点也一样

## 安全

- **token/secret 就是凭据**，务必用长随机串
- 默认 **HTTP 明文**，公网使用建议加 HTTPS 或安全组限制来源 IP
- 服务以 root 运行，脚本无第三方依赖，便于审计
