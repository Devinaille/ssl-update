# ssl-update

> 把 acme.sh 续期的证书自动推送到雷池 WAF（CE）和阿里云 ESA 的命令行工具。
> 支持插件式扩展，写一个 Go 包就能加新的推送目标。

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-TBD-yellow)]()

---

## 目录

- [项目介绍](#项目介绍)
- [核心特性](#核心特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [配置文件详解](#配置文件详解)
- [命令参考](#命令参考)
- [接入 acme.sh](#接入-acmesh)
- [日志管理](#日志管理)
- [退出码](#退出码)
- [故障排查](#故障排查)
- [添加新推送目标](#添加新推送目标)
- [安全建议](#安全建议)
- [运维操作](#运维操作)
- [常见问题](#常见问题)

---

## 项目介绍

`ssl-update` 是 acme.sh 的下游自动化工具。**acme.sh 负责证书签发和续期，本工具负责把新证书推送到各个目标服务**。

适用场景：
- 你已经在用 acme.sh 签发证书
- 需要把同一张证书自动同步到多个不同服务（CDN、WAF、内部 LB 等）
- 希望"加新目标"时**不用改核心代码**

典型时序：

```
acme.sh 续期 cert → 写 cert/key 到磁盘
                 → 触发 --reloadcmd
                       → ssl-update run
                             → 读 cert/key + 状态
                             → 并发推送到所有 destination
                             → 写回状态（cert_id）
```

---

## 核心特性

| 特性 | 说明 |
|------|------|
| 🔌 **插件式** | 每个推送目标实现 `destination.Destination` 接口，init() 自注册到全局 registry |
| 📌 **有状态** | 记录上次推送成功的 cert id；续期时按 id 覆盖，不创建重复条目 |
| ⚖️ **per-destination 失败策略** | `required: true` 失败 → 整体 exit 1；`required: false` 失败 → 仅告警 |
| 🪶 **零外部依赖** | 不引入阿里云官方 SDK（手写 v3 签名 ~100 行）；只有 cobra + yaml.v3 + mapstructure |
| 🐧 **Linux 专一** | 没有 Windows / macOS 兼容代码，文件路径都是 Linux 风格 |
| 🧪 **可测试** | 单元测试 + httptest mock，不依赖真机就能跑全套 |
| 📜 **spec 驱动** | 设计与计划文档化在 `docs/superpowers/` 下 |

---

## 系统要求

| 项目 | 要求 |
|------|------|
| OS | Linux（amd64 / arm64）|
| Go（仅构建时） | 1.22+ |
| 运行依赖 | 仅 libc |
| 网络 | 出站 HTTPS 到 WAF / 阿里云 |
| 权限 | 普通用户即可；日志写 `/var/log` 需要 `adm` 组或 root |

---

## 快速开始

### 1. 安装

**从源码构建**：

```bash
git clone <repo> ssl-update
cd ssl-update
go build -o ssl-update ./cmd/ssl-update
sudo install -m 0755 ssl-update /usr/local/bin/ssl-update
```

**或下载预编译二进制**（如果发布页有）：

```bash
sudo install -m 0755 ssl-update-linux-amd64 /usr/local/bin/ssl-update
```

### 2. 准备目录

```bash
sudo install -d -m 0700 /etc/ssl-update
sudo install -d -m 0755 -o root -g adm /var/log/ssl-update
sudo install -m 0644 /dev/null /var/log/ssl-update/ssl-update.log
```

### 3. 写配置

```bash
sudo cp config.example.yaml /etc/ssl-update/config.yaml
sudo chmod 600 /etc/ssl-update/config.yaml
$EDITOR /etc/ssl-update/config.yaml   # 填真实凭据
```

### 4. 装 logrotate（强烈推荐）

```bash
sudo cp contrib/logrotate/ssl-update /etc/logrotate.d/
```

### 5. 验证连通性

```bash
ssl-update --config /etc/ssl-update/config.yaml validate
```

看到 `[OK]   prod-safeline (safeline)` 和 `[OK]   prod-esa (aliyun_esa)` 就 OK。

### 6. 接到 acme.sh

如果是已有 acme.sh 任务：

```bash
vi ~/.acme.sh/\*.a.com/\*.a.com.conf
# 末尾加一行：
Le_ReloadCmd='/usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run'
```

立即验证：

```bash
~/.acme.sh/acme.sh --renew -d "*.a.com" --force
tail -f /var/log/ssl-update/ssl-update.log
```

---

## 配置文件详解

完整示例见 `config.example.yaml`。这里挑重点讲。

### 顶层结构

```yaml
cert:           # 证书来源（env 自动 fallback）
state:          # 状态文件
log:            # 日志
concurrency: 5  # 并发上限
destinations:   # 推送目标列表
  - ...
```

### 证书来源

| 字段 | 含义 | 留空时 |
|------|------|--------|
| `cert.cert_path` | 完整链 PEM 路径 | 读 `$LE_CERT_PATH` |
| `cert.key_path`  | 私钥 PEM 路径 | 读 `$LE_KEY_PATH` |
| `cert.domain`    | 主域名（CN）| 读 `$Le_DomainMain` |

acme.sh 的 `--reloadcmd` 触发时会自动注入这三个环境变量，**配置里不填即可**。手动调用或调试时填绝对路径。

### 状态文件

默认 `~/.local/share/ssl-update/state.json`，**记录每个 (destination, cert_name) 上次推送的 cert id**。续期时通过这个 id 调覆盖接口，避免在服务侧累积重复证书条目。

```json
{
  "version": 1,
  "deployments": {
    "prod-safeline:wildcard-a-com": {
      "dest_name": "prod-safeline",
      "cert_name": "wildcard-a-com",
      "cert_id": "3",
      "last_deployed_at": "2026-08-15T10:30:00Z",
      "last_cert_fingerprint": "sha256:abc..."
    }
  }
}
```

**关键命名空间**：`<dest_name>:<cert_name>`。多个证书共享同一 destination 时不会互相覆盖。

### 日志

```yaml
log:
  level: info         # debug | info | warn | error
  format: text        # text | json
  file: /var/log/ssl-update/ssl-update.log   # 留空 → stdout
```

- **生产**：写本地文件，配合 logrotate
- **集中式日志平台**：用 `format: json`，外接 filebeat / promtail
- **journald**：把 `file` 留空，外层 `Le_ReloadCmd` 用 `systemd-cat` 包一层（见下文）

### Destination 项

```yaml
- name: prod-safeline       # 工具内引用名（必须唯一）
  type: safeline            # registry 中的 type name
  required: true            # 失败时是否让整体 exit 1
  config:                   # 该 destination 自己的配置（map）
    api_url: https://10.0.0.5:9443
    api_token: xxxxx
    cert_name: ""           # 留空 = 自动 sanitize
    verify_tls: true
```

#### 雷池 WAF（safeline）

| 字段 | 必填 | 说明 |
|------|------|------|
| `api_url` | ✅ | WAF 控制台地址，默认端口 9443 |
| `api_token` | ✅ | 在 WAF 控制台"个人中心 → OPEN API"生成 |
| `cert_name` | | 留空 = 主域名 sanitize 后（`*.a.com` → `wildcard-a-com`） |
| `verify_tls` | | 自签证书设 `false` |

#### 阿里云 ESA（aliyun_esa）

| 字段 | 必填 | 说明 |
|------|------|------|
| `access_key_id` | ✅ | 阿里云 AccessKey ID |
| `access_key_secret` | ✅ | 阿里云 AccessKey Secret |
| `region` | | `cn-hangzhou`（中国站） / `ap-southeast-1`（国际站） |
| `site_id` | ✅ | ESA 站点 ID，运行 `ssl-update list-sites --name <dest>` 获取 |
| `cert_name` | | 同上 |
| `endpoint` | | 默认从 `region` 推导成 `esa.<region>.aliyuncs.com`。VPC 内网或自定义代理场景下手动覆盖 |

### cert_name 自动 sanitize 规则

`Le_DomainMain` 或 `cert.domain` 的值会按以下规则生成 cert_name：

| 输入 | 输出 |
|------|------|
| `*.a.com` | `wildcard-a-com` |
| `a.com` | `a-com` |
| `www.a.com` | `www-a-com` |

**规则**：去掉 `*.` 前缀拼 `wildcard-`、`.` 换 `-`、不归一化大小写。

> 各服务对 cert_name 字符集有限制（ESA 明确禁 `*`），sanitize 保证产物永远符合要求。

---

## 命令参考

### 全局 flags

| Flag | 简写 | 说明 |
|------|------|------|
| `--config` | `-c` | 配置文件路径（默认 `/etc/ssl-update/config.yaml`） |
| `--log-level` | | 覆盖 config 里的 log level |
| `--log-format` | | 覆盖 config 里的 log format |

### `ssl-update run` — 主路径

```bash
ssl-update run [flags]
```

| Flag | 说明 |
|------|------|
| `--only <name>` | 只推送到指定 destination（可重复） |
| `--dry-run` | 打印会发什么请求，不实际推送 |
| `--skip-state` | 不读不写 state.json |
| `--timeout 5m` | 整体超时 |

**退出码**：见 [退出码](#退出码) 一节。

### `ssl-update validate` — 连通性检查

```bash
ssl-update validate [flags]
```

跑所有 destination 的 `Validate()`（不实际推送 cert）。改完 config 后必跑一遍。

### `ssl-update show-state` — 看推送历史

```bash
ssl-update show-state [--json]
```

表格模式默认，`--json` 输出原始 JSON。

### `ssl-update list-sites` — 查 ESA site_id（v0.1.2+）

```bash
ssl-update list-sites --name prod-esa
```

只对 `aliyun_esa` destination 有效：调用 ESA `ListSites` API 并把 `SiteId` 列表打印出来。**首次配置时必跑一次**，因为控制台没地方查 SiteId 这个数字 ID。

### `ssl-update version` — 版本信息

```bash
ssl-update version
```

输出 `ssl-update X.Y.Z` + 已注册 destination 类型列表。

---

## 接入 acme.sh

acme.sh 的 `--reloadcmd` 在每次成功签发/续期后**自动**触发。把 ssl-update 设进去就行。

### 情形 A：首次装证书

```bash
acme.sh --install-cert -d "*.a.com" \
  --reloadcmd "/usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run"
```

### 情形 B：已有 acme.sh 任务（推荐做法）

**不要**重新跑 `--install-cert`（会把 cert 重写到别的路径）。直接编辑任务配置：

```bash
vi ~/.acme.sh/\*.a.com/\*.a.com.conf
# 在文件末尾追加：
Le_ReloadCmd='/usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run'
```

`~/.acme.sh/<domain>/<domain>.conf` 是 acme.sh 给每个域名的任务配置。它会在每次续期后重读 `Le_ReloadCmd`。**改完即生效，无需重启任何东西**，下个续期周期就触发。

### 立即验证

```bash
# 强制续期（即使没到期也跑）
~/.acme.sh/acme.sh --renew -d "*.a.com" --force

# 看日志
tail -f /var/log/ssl-update/ssl-update.log
```

> 注意：续期命令是 `--renew --force`（强制重新签发），不是 `--renew` 本身。

### 接入 journald（可选）

如果想把 reloadcmd 输出接 journald（适合没装 logrotate 的环境）：

```bash
Le_ReloadCmd='/usr/bin/systemd-cat -t ssl-update /usr/local/bin/ssl-update --config /etc/ssl-update/config.yaml run'
journalctl -t ssl-update -f
```

---

## 日志管理

### 默认：本地文件

写 `/var/log/ssl-update/ssl-update.log`，text 格式。配合 `contrib/logrotate/ssl-update` 自动 rotate：

```bash
sudo cp contrib/logrotate/ssl-update /etc/logrotate.d/
```

rotate 策略：每天 rotate，保留 30 天，压缩，缺失不报错。

### 改用 stdout（备选）

config 里 `log.file: ""`，外层加 redirect：

```bash
Le_ReloadCmd='/usr/local/bin/ssl-update ... 2>&1 | tee -a /var/log/ssl-update.log'
```

或进 journald（见上一节）。

### 集中式日志平台

把 `format: json`，外接 filebeat / promtail / 阿里云 SLS。

### 调试

临时看更详细输出：

```bash
ssl-update --log-level debug --log-format text run --dry-run
```

---

## 退出码

| 码 | 含义 | acme.sh 看到会怎样 |
|----|------|---------------------|
| `0` | 全部成功（或只有 `required: false` 失败） | 正常 |
| `1` | 至少一个 `required: true` destination 失败 | reloadcmd 失败，但 cert 续期状态不变 |
| `2` | 启动期失败：config 错 / cert 文件读不到 / 未知 destination type | reloadcmd 失败 |

**acme.sh 角度看**：cert 已经写到 `~/.acme.sh/<domain>/` 了，ssl-update 失败不影响续期。但下次需要排查。

---

## 故障排查

### Q: 跑 `run` 后看到 "deploy failed: ErrCertNotFound http 404"

state.json 里记录的 `cert_id` 在服务侧已经不存在了。**先查原因**：

```bash
# 看 WAF 控制台证书列表，确认旧 cert 还在不在
# 看 state.json 里记录的 cert_id
cat /var/log/ssl-update/ssl-update.log | grep "hint_id="
```

修复：

```bash
# 方案 1：删 state.json 让它重新创建（极端但能恢复）
rm ~/.local/share/ssl-update/state.json

# 方案 2：手动改 state.json 把那个 destination 条目删了
# 留 dest_name:cert_name 这条 entry 就行
```

### Q: 看到 "InvalidParameter.SiteId" ESA 错误

`site_id` 错了或账号不对。用我们自己的子命令查：

```bash
ssl-update list-sites --name prod-esa
# 输出：
#   SITE_ID    SITE_NAME      STATUS  ACCESS_TYPE  COVERAGE  PLAN
#   12345      example.com    active  NS           domestic  pro
#   67890      test.com       pending CNAME        global    free
#
# 找到正确的 site_id 后改 config.yaml
```

### Q: "no required module provides package gopkg.in/yaml.v3"

第一次构建时缺依赖。重新：

```bash
go mod tidy
go mod download
```

### Q: 怎么强制重推一次（不靠 acme.sh 触发）

```bash
# 跑 validate 先确认连通
ssl-update --config /etc/ssl-update/config.yaml validate

# 再跑 run
ssl-update --config /etc/ssl-update/config.yaml run

# 强制不读 state（走 create 而不是 update 路径），清空 state 即可
rm ~/.local/share/ssl-update/state.json
ssl-update --config /etc/ssl-update/config.yaml run
```

### Q: acme.sh 续期后日志没新内容

acme.sh 默认 cron 在凌晨随机时间跑续期，**不是每次**都触发 reloadcmd——只在 cert 真的换了才触发。

强制试一次：

```bash
~/.acme.sh/acme.sh --renew -d "*.a.com" --force
tail -f /var/log/ssl-update/ssl-update.log
```

### Q: 想看一次 run 实际发了什么 HTTP 请求

```bash
# 跑 dry-run 看会推什么 destination
ssl-update --config /etc/ssl-update/config.yaml run --dry-run

# debug 日志级别（注意：debug 级别会输出完整 cert 内容，注意日志安全）
ssl-update --config /etc/ssl-update/config.yaml --log-level debug run --dry-run
```

---

## 添加新推送目标

### 步骤

1. **写 Go 包** `internal/destination/<your-type>/`
2. **实现 `destination.Destination` 接口**（4 个方法）
3. **在 `init()` 注册**
4. **main.go 加一行 blank import**
5. **写测试 + 写 config.example.yaml 的新段落**
6. 重新 build

### 模板

```go
// internal/destination/myprovider/myprovider.go
package myprovider

import (
    "context"

    "github.com/mitchellh/mapstructure"

    "ssl-update/internal/cert"
    "ssl-update/internal/destination"
)

const TypeName = "myprovider"

func init() {
    destination.Register(TypeName, New)
}

type Config struct {
    // your fields, with mapstructure tags
    Endpoint string `mapstructure:"endpoint"`
    Token    string `mapstructure:"token"`
}

type MyProvider struct {
    name string
    cfg  Config
}

func New(name string, raw map[string]any) (destination.Destination, error) {
    var c Config
    if err := mapstructure.Decode(raw, &c); err != nil {
        return nil, fmt.Errorf("%w: myprovider: %v", destination.ErrInvalidConfig, err)
    }
    // validate c
    return &MyProvider{name: name, cfg: c}, nil
}

func (m *MyProvider) Name() string { return m.name }

func (m *MyProvider) CertName(b cert.CertBundle) string {
    // return the cert name this destination will use
}

func (m *MyProvider) Deploy(ctx context.Context, b cert.CertBundle, certIDHint string) (destination.DeployResult, error) {
    // your push logic. If certIDHint != "", try to update the existing one;
    // otherwise create new. Return DeployResult with the new/existing CertID.
}

func (m *MyProvider) Validate(ctx context.Context) error {
    // connectivity check, no cert push
}
```

```go
// cmd/ssl-update/main.go
import (
    _ "ssl-update/internal/destination/myprovider"  // 新增
    _ "ssl-update/internal/destination/safeline"
    _ "ssl-update/internal/destination/aliyun_esa"
)
```

之后 config 里加：

```yaml
destinations:
  - name: my-instance
    type: myprovider   # 这里就用上了
    required: false
    config:
      endpoint: "..."
      token: "..."
```

---

## 安全建议

### 凭据保护

- 配置文件 `chmod 600`，属主 root
- **不要**把真实凭据 commit 到 git（`.gitignore` 已排除 `config.yaml`，但 `config.*.yaml` 也会挡——别去掉）
- AccessKey 在阿里云控制台**只勾选 ESA 权限**，别给全权
- 雷池 token 同理：只勾需要的模块
- 轮换：AccessKey 90 天一换；WAF token 半年一换

### cert/key 不落盘到非必要位置

- 本工具**不**把 cert 写到中间文件，**直接内存传给 destination**
- 但 `--log-level debug` 会把 cert 内容打到日志里——**生产环境别用 debug**
- logrotate 别忘了配，否则 `/var/log/ssl-update/` 可能装下整本证书库

### 不要在公网 host 上跑

- 本工具会向 WAF 和 ESA 发起 HTTPS 请求，**没监听任何端口**
- 但 state.json 含 cert id 和 cert 指纹（不是 cert 本身），仍然算敏感信息
- state.json 建议放在 root-only 的目录（`~/.local/share/ssl-update/` 默认是）

---

## 运维操作

### 升级

```bash
# 1. 备份 state.json
cp -a ~/.local/share/ssl-update/state.json{,.bak}

# 2. 替换二进制
sudo install -m 0755 ssl-update /usr/local/bin/ssl-update

# 3. 验证
ssl-update version
ssl-update validate
```

state.json 含 schema `version` 字段，未来不兼容时会有迁移路径。

### 卸载

```bash
# 1. 移除 reloadcmd
vi ~/.acme.sh/<domain>/<domain>.conf
# 删除 Le_ReloadCmd=... 那行

# 2. 移除二进制和目录
sudo rm /usr/local/bin/ssl-update
sudo rm -rf /etc/ssl-update
sudo rm -rf /var/log/ssl-update
sudo rm -f /etc/logrotate.d/ssl-update

# 3. 保留 state.json（cert_id 历史有用）或删
rm -rf ~/.local/share/ssl-update
```

### 备份

只需备份 `state.json`（< 1KB）。可以加进现有的配置备份流程。

### 监控

v1 **没有**内建 metrics。监控建议：

| 信号 | 怎么采集 |
|------|----------|
| 续期是否成功 | `acme.sh` cron 退出码 + cert 过期时间检查 |
| ssl-update 推送是否成功 | loggrep `[ERROR]` 或 exit code (systemd Exec condition) |
| 证书有效期 | `ssl-update run` 退出 0 + 解析日志里的 `expires` 字段 |
| WAF/ESA 实际生效 | 外部健康检查，访问受证书保护的 URL 测 TLS 握手 |

> 未来计划：加 `--json` 的状态输出 + Prometheus textfile exporter（见 `docs/superpowers/specs/...-design.md` §16）。

---

## 常见问题

**Q: 一个 cert 能推给多个 destination 吗？**

A: 可以，destinations 列表里写多条，concurrency 控制并发上限。同一张 cert 会并发推到所有。

**Q: 多张 cert 共用一个 destination 怎么办？**

A: state.json 的 key 是 `<dest_name>:<cert_name>`，每个 cert_name 独立记录 cert_id，互不干扰。比如 acme.sh 同时签了 `*.a.com` 和 `*.b.com`，在 ESA 里就是两个独立 cert 条目（除非你手工合并）。

**Q: 我换了 destination 的 cert_name 配置怎么办？**

A: 老 entry 还会在 state.json 里留着，忽略即可。要清理手动 `rm` 或 `cat state.json | jq 'keys'` 看。

**Q: 支持 Windows 吗？**

A: 不支持。设计上就是 Linux only。Windows 的路径分隔符、TLS 库、acme.sh 行为都不同。**强需求请用 WSL2 或 Docker**。

**Q: 不想用 acme.sh，能用别的 ACME 客户端吗？**

A: 可以，只要那个客户端支持 `reloadcmd` 或类似的"续期后回调"机制（certbot 的 `--deploy-hook` 之类）。把它调起来指向 `ssl-update run --config ...` 就行。

**Q: safeline / aliyun_esa 之外还能加什么 destination？**

A: 任何能调 HTTPS API 推送证书的服务都行。常见候选：

- 阿里云传统 CDN / DCDN（注意：用 acme.sh 自带的 `--deploy-hook aliyun`，比写新 destination 简单）
- 腾讯云 EdgeOne
- AWS CloudFront
- Cloudflare
- 内部 nginx / haproxy（写文件 + `nginx -s reload`）
- 自家控制台

具体怎么实现见 [添加新推送目标](#添加新推送目标) 一节。

---

## 路线图

- v0.1 (current)：safeline CE + aliyun_esa，文件日志，per-destination 失败策略
- v0.2（计划）：凭据外置（env / file）、webhook 通知、重试、Prometheus 指标
- v1.0（计划）：stable API、CHANGELOG、Homebrew tap

---

## 许可证

TBD。
