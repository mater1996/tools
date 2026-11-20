# xray-sub-server

读取 Xray 的 Reality 配置（`/etc/xray/conf/*.json`），生成 Clash / mihomo 订阅，并通过**内置 HTTP(S) 服务**提供——不需要 nginx。

## 特性

- **热重载**：每次请求重新读 Xray 配置，改服务端节点客户端下次拉订阅自动更新
- **自动算公钥**：由 `privateKey` 调 `xray x25519` 推 `publicKey`
- **可套模板**：用自带 `template.yaml`（已脱敏），保留策略组/分流规则，只替换 `proxies`
- **多用户**：每个 Xray client 一个独立 token（HMAC 派生，删用户自动失效）
- **CLI**：`serve / list / update / version`
- token 校验支持 `?token=`、`Authorization: Bearer`、路径 `/<token>.yaml`

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

GitHub 慢用镜像：

```bash
REPO_RAW=https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

多用户安装：

```bash
SECRET=$(openssl rand -hex 16) ...install.sh   # 设置 SECRET 环境变量即启用多用户
```

## CLI

安装后会生成全局命令 **`xray-sub`**（不用再敲 python 路径）：

```bash
xray-sub list      # 查看订阅链接（多用户列出每人）
xray-sub update    # 更新程序与模板并重启
xray-sub version   # 版本
xray-sub serve     # 前台启动（一般由 systemd 托管，无需手动）
```

`xray-sub` 只是对同一份 Python 程序的包装。

| 命令 | 作用 |
|---|---|
| `serve` | 启动订阅服务（默认） |
| `list` | 列出订阅链接（多用户时列出每人各自的链接） |
| `update` | 从仓库拉取最新程序与模板，并重启 systemd 服务 |
| `version` | 版本 |

### 单用户

```bash
python3 xray-sub-server.py serve \
  --conf-dir /etc/xray/conf --xray-bin /etc/xray/bin/xray \
  --token YOURTOKEN --port 8081 --template /opt/xray-sub/template.yaml
```

订阅：`http://<IP>:8081/sub?token=YOURTOKEN`

### 多用户

Xray 的 `clients[]` 里每个用户建议带 `email`（没有则用 `id`）：

```bash
python3 xray-sub-server.py serve --conf-dir /etc/xray/conf \
  --xray-bin /etc/xray/bin/xray --secret YOURSECRET --port 8081

# 查看每个人的订阅链接
python3 xray-sub-server.py list --conf-dir /etc/xray/conf \
  --xray-bin /etc/xray/bin/xray --secret YOURSECRET --server <IP> --port 8081
```

- token = `HMAC-SHA256(secret, email)[:32]`，**稳定不变**
- 每个用户的订阅**只含自己的节点**
- **删掉该 client 后，其 token 自动失效（404）**
- 加用户：Xray 配置里加一个 client 即可，无需改本工具

### 更新

```bash
python3 /opt/xray-sub/xray-sub-server.py update            # 拉最新程序+模板并重启
python3 /opt/xray-sub/xray-sub-server.py update --no-restart
```

重跑 `install.sh` 也可以更新，且会**复用已有 token/secret**，订阅地址不变。

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--conf-dir` | `/etc/xray/conf` | Xray 配置目录 |
| `--xray-bin` | `xray` | xray 可执行文件 |
| `--token` | — | 单用户全局 token |
| `--secret` | — | 多用户密钥（启用多用户） |
| `--listen` / `--port` | `0.0.0.0` / `8081` | 监听地址/端口 |
| `--server` | 自动探测 | 订阅里节点地址 |
| `--name` | `JP-Reality` | 节点名，改它时模板里 `JP-Reality` 引用同步替换 |
| `--template` | 无 | Clash 模板 YAML |
| `--tls-cert` / `--tls-key` | 无 | 启用 HTTPS |

## 安全

- **token/secret 就是凭据**，务必用长随机串
- 默认 **HTTP 明文**，公网使用建议加 HTTPS 或安全组限制来源 IP
- 服务以 root 运行，脚本无第三方依赖，便于审计
