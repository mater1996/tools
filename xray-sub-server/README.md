# tools

个人工具集合，每个工具一个子目录，互不干扰。

---

## xray-sub-server

读取 Xray 的 Reality 配置（`/etc/xray/conf/*.json`），生成 Clash / mihomo 订阅，并通过**内置 HTTP(S) 服务**提供——不需要 nginx。

- **热重载**：每次请求重新读 Xray 配置，改了服务端节点，客户端下次拉订阅自动更新，不用重导 YAML
- **自动算公钥**：由服务端 `privateKey` 调 `xray x25519` 推出 `publicKey`
- **可套模板**：用自带的 `template.yaml`（已脱敏），保留策略组与分流规则，只替换 `proxies`
- **Token 认证** + 可选 HTTPS

### 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

GitHub 慢时用镜像：

```bash
REPO_RAW=https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/mater1996/tools/main/xray-sub-server/install.sh)
```

装完会打印订阅地址：

```
http://<公网IP>:8081/<token>.yaml
```

把它填进 Clash Verge → 配置 → 新建 → 远程即可。

### 文件

| 文件 | 作用 |
|---|---|
| `xray-sub-server.py` | 主程序（Python3 单文件，无第三方依赖） |
| `install.sh` | 一键安装（写 systemd、生成 token） |
| `template.yaml` | 脱敏 Clash 模板，运行时会用真实节点替换 `proxies` 段 |

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--conf-dir` | `/etc/xray/conf` | Xray 配置目录 |
| `--xray-bin` | `xray` | xray 可执行文件 |
| `--token` | 必填 | 订阅访问 token，放在 URL 里 |
| `--listen` / `--port` | `0.0.0.0` / `8081` | 监听地址/端口 |
| `--server` | 自动探测 | 订阅里节点的服务器地址 |
| `--name` | `JP-Reality` | 节点名，改它时模板里 `JP-Reality` 的引用会同步替换 |
| `--template` | 无 | Clash 模板 YAML |
| `--tls-cert` / `--tls-key` | 无 | 启用 HTTPS |

### 安全

- **token 就是凭据**，务必用长随机串（install.sh 默认生成 32 位）
- 默认 **HTTP 明文**，公网使用建议加 HTTPS（`--tls-cert/--tls-key`）或安全组限制来源 IP
- 服务以 root 运行，脚本本身无第三方依赖，便于审计
