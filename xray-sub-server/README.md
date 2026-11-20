# xray-sub-server

读取 Xray 的 Reality 配置（`/etc/xray/conf/*.json`），生成 Clash / mihomo 订阅，并通过**内置 HTTP(S) 服务**提供——不需要 nginx。

## 特性

- **热重载**：每次请求重新读 Xray 配置，改服务端节点客户端下次拉订阅自动更新
- **自动算公钥**：由 `privateKey` 调 `xray x25519` 推 `publicKey`
- **可套模板**：用自带 `template.yaml`（已脱敏），保留策略组/分流规则，只替换 `proxies`
- **多用户**：每个 Xray client 一个独立 token（HMAC 派生，删用户自动失效）
- token 校验支持 `?token=`、`Authorization: Bearer`、路径 `/<token>.yaml`

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
| `xray-sub update` | 拉取最新程序与模板并重启服务 |
| `xray-sub version` | 版本 |

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
| `--name` | `JP-Reality` | 节点名，改它时模板里 `JP-Reality` 引用同步替换 |
| `--template` | 自带 template.yaml | Clash 模板 YAML |

`serve` 另支持 `--listen`、`--tls-cert`、`--tls-key`。

## 安全

- **token/secret 就是凭据**，务必用长随机串
- 默认 **HTTP 明文**，公网使用建议加 HTTPS 或安全组限制来源 IP
- 服务以 root 运行，脚本无第三方依赖，便于审计
