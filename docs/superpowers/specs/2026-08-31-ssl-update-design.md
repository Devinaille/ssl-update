# ssl-update 设计文档

**状态**：草案 v1
**日期**：2026-08-31
**作者**：Mavis (协助)、Master (决策)
**目标平台**：Linux only（amd64 / arm64）

---

## 1. 背景与目标

### 1.1 问题

acme.sh 续期证书后，需要把新证书自动推送到：

1. **雷池 WAF（社区版 CE）** — 本地自托管的反向代理/WAF
2. **阿里云 ESA（边缘安全加速）** — 阿里云的 CDN/WAF/边缘服务

acme.sh 自带的 `--deploy-hook` 体系已经能处理很多服务，但 Safeline CE 和 Aliyun ESA 没有现成 hook，且我们希望：

- 把多个 destination 集中管理，**一份配置搞定所有推送**
- 后续能方便地加新 destination（如传统 CDN / 其他 WAF / 内部 LB）
- 与 acme.sh 的 reloadcmd 流程无缝集成

### 1.2 目标

写一个 Go 工具 `ssl-update`：

- 读取 acme.sh 续期后的 cert/key
- 推送到一个或多个 destination（每个 destination 通过实现统一接口接入）
- 记录"上次推送的 cert id"以便续期覆盖
- 出错时按 per-destination 的 `required` 标志决定是否整体失败

### 1.3 非目标（v1 不做）

- 证书签发本身（acme.sh 已负责）
- 站点/域名与 cert 的绑定关系管理（约定：服务侧已完成初次绑定，本工具只负责更新证书内容）
- Windows / macOS 兼容
- 自动重试 / 告警通知 / 监控
- 多个 acme.sh 账号并行管理

---

## 2. 整体架构

### 2.1 核心理念

核心（runner / config / state）只依赖一个 `Destination` 接口；具体 destination 实现（safeline / aliyun_esa）通过包级 `init()` 自注册到全局 registry。**加新 destination = 写新 Go 包 + 在 main.go 显式 import，无需改核心代码。**

### 2.2 模块依赖图

```
                ┌─────────────────┐
                │ cmd/ssl-update  │  CLI 入口
                └────────┬────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   ┌────────┐       ┌────────┐      ┌────────┐
   │  cli   │       │ config │      │ state  │
   └────┬───┘       └────┬───┘      └────┬───┘
        └───────┬────────┴────────┬───────┘
                ▼                 ▼
          ┌─────────┐      ┌──────────────┐
          │ runner  │─────▶│ destination  │  ← 接口 + registry
          └────┬────┘      └──────────────┘
               │                  ▲
               │                  │ init() 注册
               │            ┌─────┴──────┐
               └───────────▶│ safeline   │
                            │ aliyun_esa │
                            └────────────┘
```

### 2.3 目录布局

```
ssl-update/
├── go.mod
├── go.sum
├── README.md
├── config.example.yaml
├── cmd/
│   └── ssl-update/
│       └── main.go              # 入口；显式 import 各 destination 包
├── internal/
│   ├── cli/
│   │   ├── root.go              # cobra 根命令
│   │   ├── run.go               # ssl-update run
│   │   ├── validate.go          # ssl-update validate
│   │   ├── show_state.go        # ssl-update show-state
│   │   └── version.go           # ssl-update version
│   ├── config/
│   │   ├── config.go            # YAML schema 定义
│   │   └── config_test.go
│   ├── cert/
│   │   ├── cert.go              # PEM 解析、sanitize name
│   │   └── cert_test.go
│   ├── state/
│   │   ├── state.go             # state.json 读写
│   │   └── state_test.go
│   ├── runner/
│   │   ├── runner.go            # 编排
│   │   └── runner_test.go
│   └── destination/
│       ├── destination.go       # interface
│       ├── registry.go          # Register / Create / ListTypes
│       ├── safeline/
│       │   ├── safeline.go
│       │   └── safeline_test.go
│       └── aliyun_esa/
│           ├── aliyun_esa.go
│           └── aliyun_esa_test.go
└── docs/
    └── superpowers/
        └── specs/
            └── 2026-08-31-ssl-update-design.md
```

---

## 3. 与 acme.sh 的集成

### 3.1 触发方式：`--reloadcmd`

acme.sh 的 `--reloadcmd` 在每次成功签发/续期证书后自动执行。一次性配置，长期生效。

```bash
# 一次性配置（首次安装证书时）
acme.sh --install-cert -d "*.a.com" \
  --reloadcmd "/usr/local/bin/ssl-update run --config /etc/ssl-update/config.yaml"

# 之后每次续期成功，acme.sh 会自动调这条命令
```

### 3.2 acme.sh 注入的环境变量

ssl-update 从以下环境变量读 cert/key 路径与域名：

| 变量 | 含义 |
|------|------|
| `LE_CERT_PATH` | 完整证书链文件路径（PEM） |
| `LE_KEY_PATH` | 私钥文件路径（PEM） |
| `LE_RENEWED_DOMAINS` | 续期的域名列表，逗号分隔 |
| `Le_DomainMain` | 主域名（CN） |

**回退**：如果环境变量为空（如手动跑 `validate`），则从 config 的 `cert.cert_path / key_path / domain` 字段读。

**`NotAfter` 字段来源**：acme.sh 不直接提供，**从 cert PEM 文件里解析**（`crypto/x509.ParseCertificate` 取 `NotAfter`）。CertBundle 的 `Domains / MainDomain` 从环境变量取。

---

## 4. CLI 设计

### 4.1 子命令总览

```bash
ssl-update <command> [flags]
```

| 子命令 | 用途 |
|--------|------|
| `run` | 主路径。读 cert、推送到所有 enabled destinations（acme.sh reloadcmd 调的就是这个） |
| `validate` | 检查 config 语法、各 destination 连通性、cert 路径可读性（不实际推送） |
| `show-state` | 打印 state.json 内容（上次推送的 cert id、时间、指纹） |
| `version` | 输出版本、Go runtime、内置 destination 类型列表 |

### 4.2 通用 flags

| Flag | 简写 | 说明 |
|------|------|------|
| `--config` | `-c` | 配置文件路径（默认 `/etc/ssl-update/config.yaml`） |
| `--log-level` | | `debug` / `info` / `warn` / `error`（覆盖 config 里的设置） |
| `--log-format` | | `text` / `json` |

### 4.3 `run` 子命令的额外 flags

| Flag | 说明 |
|------|------|
| `--only <dest_name>` | 只推送到指定 destination（可重复，调试用） |
| `--dry-run` | 不实际推送，只打印会发什么请求 |
| `--skip-state` | 不读写 state.json（force 覆盖场景用） |

### 4.4 使用示例

```bash
# 1. acme.sh reloadcmd 调它
ssl-update run --config /etc/ssl-update/config.yaml

# 2. 改完 config 后检查
ssl-update validate --config /etc/ssl-update/config.yaml

# 3. 单推一个 destination（调试）
ssl-update run --only prod-safeline

# 4. 看状态
ssl-update show-state

# 5. 模拟跑
ssl-update run --dry-run
```

---

## 5. 配置 Schema（YAML）

完整示例见 `config.example.yaml`。以下是字段说明。

### 5.1 顶层字段

```yaml
cert:               # cert 来源（env 自动回退到这里）
  cert_path: ""     # 留空 = 从 LE_CERT_PATH 读
  key_path: ""      # 留空 = 从 LE_KEY_PATH 读
  domain: ""        # 留空 = 从 Le_DomainMain 读

state:
  path: ~/.local/share/ssl-update/state.json   # 状态文件路径

log:
  level: info         # debug / info / warn / error
  format: text        # text / json

concurrency: 5        # 并发推送到 destinations 的上限

destinations: [...]   # 目标列表
```

### 5.2 Destination 项字段

```yaml
- name: prod-safeline       # 本工具内的引用名，唯一
  type: safeline            # registry 中的 type name
  required: true            # 失败时是否让整体 run 失败
  config:                   # 该 destination 自己的配置（map，destination 包自己解析）
    api_url: https://10.0.0.5:9443
    api_token: xxxxx
    cert_name: ""           # 留空 = 自动从主域名 sanitize
    verify_tls: true
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | ✅ | 引用名（用于 `--only` 过滤、日志、state 索引） |
| `type` | ✅ | destination type（`safeline` / `aliyun_esa` / 未来新增的） |
| `required` | ❌ | 失败是否让整体 abort。默认 `false` |
| `config` | ✅ | 该 type 自己的配置，透传给 destination 包的 Factory |

### 5.3 cert_name 自动 sanitize 规则

如果 config 里 `cert_name` 留空，从主域名（`Le_DomainMain`）按以下规则生成：

| 输入 | 输出 |
|------|------|
| `*.a.com` | `wildcard-a-com` |
| `a.com` | `a-com` |
| `www.a.com` | `www-a-com` |
| `A.B.com` | `A-B-com`（保留原大小写，sanitize 不会 normalize） |

**规则**：
1. 去掉开头的 `*.`（若有），前面拼上 `wildcard-` 前缀
2. 把 `.` 替换为 `-`
3. 不做大小写归一化

**约束**：生成的 cert_name 必须满足各服务的命名限制（字母、数字、`_`、`.`、`-`）。当前 sanitize 规则产生的字符集：字母、数字、`-`、以及首部的 `wildcard-`。**通过**。

### 5.4 凭据安全

- 凭据明文写在 config 文件中
- 文件权限建议 `chmod 600 /etc/ssl-update/config.yaml`
- `.gitignore` 必须包含 `config.yaml`，只提交 `config.example.yaml`
- README 强调"不要把真实凭据提交到 git"

### 5.5 凭据外置（可选，v1 不实现，仅留位）

v1 不做 env 变量引用或 key file 引用。如果未来有需求，扩字段：

```yaml
config:
  api_token_file: /run/secrets/safeline.token   # 二选一
  api_token_env: SAFELINE_TOKEN                  # 二选一
```

---

## 6. 核心接口（`internal/destination`）

### 6.1 `Destination` 接口

```go
package destination

import (
    "context"
    "time"
)

type CertBundle struct {
    Certificate []byte    // PEM 完整链
    PrivateKey  []byte    // PEM 私钥
    Domains     []string  // SAN 列表
    MainDomain  string    // 主域名
    NotAfter    time.Time
}

type DeployResult struct {
    CertID      string    // 服务侧 cert id（用于下次覆盖）
    CertName    string    // 服务侧 cert name（用户可见的别名）
    DeployedAt  time.Time
    Fingerprint string    // SHA256 of cert bytes
}

type Destination interface {
    Name() string
    Deploy(ctx context.Context, cert CertBundle, certIDHint string) (DeployResult, error)
    Validate(ctx context.Context) error
}
```

### 6.2 Registry

```go
type Factory func(name string, rawConfig map[string]any) (Destination, error)

func Register(typeName string, f Factory)
func Create(typeName, name string, rawConfig map[string]any) (Destination, error)
func ListTypes() []string
```

### 6.3 init 自注册约定

每个 destination 包的 `init()` 调用 `destination.Register`：

```go
// internal/destination/safeline/safeline.go
func init() {
    destination.Register("safeline", New)
}

func New(name string, rawConfig map[string]any) (destination.Destination, error) {
    // 用 mapstructure 或手 unmarshal 把 rawConfig 解析成自己的 struct
    // 返回实现了 destination.Destination 的实例
}
```

### 6.4 main.go 显式 import

```go
// cmd/ssl-update/main.go
import (
    _ "ssl-update/internal/destination/safeline"
    _ "ssl-update/internal/destination/aliyun_esa"
)
```

**原因**：Go 不会自动 import 任何包，必须显式列出来，否则 `init()` 不会执行，registry 为空。

---

## 7. 各 Destination 实现

### 7.1 Safeline (CE)

**API 基础**：`https://{host}:9443`，认证用 **API-TOKEN**（在 WAF "个人中心 → OPEN API" 生成）。

| 操作 | 接口 | 说明 |
|------|------|------|
| 列证书 | `GET /api/CertAPI?page=1&page_size=100` | 返回所有 cert（含 id, name） |
| 找 cert | 从 list 结果里按 `name` 过滤 | 用作 certIDHint 回退 |
| 首次创建 | `POST /api/UploadSSLCertAPI` | body 格式需实现期对照 WAF OpenAPI doc 确认（官方 OpenAPI doc 提供了端点但未公开示例 body） |
| 覆盖更新 | `PUT /api/open/cert/{cert_id}` | body: `{manual:{crt, key}, type: 2}`（参考社区脚本确认的格式） |

**config 字段**：
```yaml
type: safeline
config:
  api_url: https://10.0.0.5:9443
  api_token: xxxxx
  cert_name: ""             # 留空 = sanitize
  verify_tls: true          # 自签证书可设 false
```

**Validate**：调 `GET /api/CertAPI?page=1&page_size=1` 验 token 有效。

### 7.2 Aliyun ESA

**API**：`esa:SetCertificate`（version 2024-09-10）

| 操作 | 说明 |
|------|------|
| 首次创建 | `SetCertificate` with `Type=upload, Name, Certificate, PrivateKey` (无 Id) → 返回 Id |
| 覆盖更新 | `SetCertificate` with `Type=upload, Name, Certificate, PrivateKey, Id=<stored>` |

**cert name 约束**（重要）：ESA 限制为英文字母 / 数字 / `.` / `_` / `-`，**不允许 `*`**。所以 cert_name 必须经过 sanitize。

**config 字段**：
```yaml
type: aliyun_esa
config:
  access_key_id: xxxxx
  access_key_secret: xxxxx
  region: cn-hangzhou       # 中国站 / 国际站按账号
  site_id: 1234567890123
  cert_name: ""
  endpoint: esa.aliyuncs.com # 默认 esa.aliyuncs.com
```

**认证**：阿里云 OpenAPI 标准签名（v3），可用官方 Go SDK `github.com/alibabacloud-go/esa-20240910` 或手写 thin client（v1 选 thin client，减少依赖）。

**Validate**：调 `ListSites` 验 access key 有效 + site_id 存在。

---

## 8. State 管理

### 8.1 文件位置

`~/.local/share/ssl-update/state.json`（Linux only）。

### 8.2 Schema

```json
{
  "version": 1,
  "deployments": {
    "prod-safeline:wildcard-a-com": {
      "dest_name": "prod-safeline",
      "cert_name": "wildcard-a-com",
      "cert_id": "3",
      "last_deployed_at": "2026-08-15T10:30:00Z",
      "last_cert_fingerprint": "sha256:abc123..."
    },
    "prod-esa:wildcard-a-com": {
      "dest_name": "prod-esa",
      "cert_name": "wildcard-a-com",
      "cert_id": "babae7c40fef412d887688b91c9e****",
      "last_deployed_at": "2026-08-15T10:30:01Z",
      "last_cert_fingerprint": "sha256:abc123..."
    }
  }
}
```

**key 命名空间**：`<dest_name>:<cert_name>`。这样多个 cert 共享同一个 destination 时不会互相覆盖（每个 cert 自己的命名空间）。

### 8.3 读写行为

- **读**：load 整个 json 到内存（state 文件不会很大）；hash by key
- **写**：每次成功推送后**追加 / 覆盖**该 key 的条目，atomic rename 写回
- **写失败容忍**：state 写盘失败（磁盘满 / 权限错）→ 记 warn 日志，**不**影响本次 run 的 exit code（cert 已经推上去了，记录失败是次要的）
- **读失败容忍**：state 文件不存在 / 解析失败 → 视同首次部署（certIDHint=""），记 warn 日志
- **并发**：acme.sh reloadcmd 是串行触发的，单进程内 `sync.Mutex` 保护即可；不处理跨进程并发

### 8.4 清理（v1 不做）

- 不自动清理孤儿条目（dest 不再使用后保留的 cert_id 记录）
- 用户可手动 `rm state.json` 重置
- 未来可加 `ssl-update state prune` 子命令

---

## 9. 失败处理与退出码

### 9.1 退出码矩阵

**三档分类**：

- **`0` 成功**：run 正常完成（即使个别 `required: false` 的 destination 失败也属此类）
- **`1` 运行时失败**：run 启动了、cert 读到了，但至少一个 `required: true` 的 destination 推送失败
- **`2` 启动期失败**：run 都没启动起来（config 错、cert 文件读不到、未知 type 等）——这种情况下 acme.sh 的 cert 已经写盘了，只是 ssl-update 没法做事

| 场景 | 分类 | 退出码 |
|------|------|--------|
| 所有 destination 成功 | 成功 | 0 |
| 任意 `required: true` 失败 | 运行时失败 | 1 |
| 只有 `required: false` 失败 | 成功（部分） | 0 |
| 全部 destination 都失败（哪怕 required: false） | 成功（按规则） | 0 |
| config 解析失败 / 文件不存在 | 启动期失败 | 2 |
| cert 路径不存在 / PEM 损坏 | 启动期失败 | 2 |
| state 文件读不到 | 成功（warn 后继续） | 0 |
| 未知 destination type | 启动期失败 | 2 |
| 必填 destination 字段缺失（如 api_token） | 启动期失败 | 2 |

**对 acme.sh reloadcmd 的影响**：acme.sh 只看 exit code。
- `1` 会被 acme.sh 记录为 reloadcmd 失败 → 但 **cert 续期状态不变**（cert 已经写盘到 `~/.acme.sh/<domain>/`），只是没推送到服务
- `2` 同样不影响 cert 续期，但意味着配置或环境有问题，下次还得排查
- 用 `required: true` 还是 `false` 来表达"这个 destination 失败时算不算严重"

### 9.2 日志级别使用

- `debug`：HTTP 请求/响应内容（包含 cert 完整 body！**生产慎开**）
- `info`：正常推送进度
- `warn`：state 文件丢失、cert 内容未变（fingerprint 相同）等
- `error`：推送失败、必填校验失败

### 9.3 一次 run 的日志样例

```
[INFO] ssl-update v0.1.0 starting
[INFO] config loaded from /etc/ssl-update/config.yaml
[INFO] loaded cert: *.a.com (SAN: *.a.com, a.com; expires 2026-11-15)
[INFO] state loaded: 2 prior deployments
[INFO] deploying to 2 destinations (concurrency=5)
[INFO] [prod-safeline] starting deploy cert_name=wildcard-a-com hint_id=3
[INFO] [prod-esa]     starting deploy cert_name=wildcard-a-com hint_id=babae7c4****
[INFO] [prod-safeline] deployed cert_id=3 fingerprint=sha256:abc... (took 1.2s)
[ERROR] [prod-esa] deploy failed: InvalidParameter.SiteId (400): SiteId 参数无效
[ERROR] run finished with 1 required failure(s); exit 1
```

---

## 10. Runner 编排（`internal/runner`）

### 10.1 流程

```
1. 加载 config
2. 加载 state（warn-on-fail）
3. 读 cert（从 env 或 config 路径）
4. 并发 dispatch 到各 destination：
   for each destination d in cfg.Destinations:
     go func() {
       dest = registry.Create(d.Type, d.Name, d.Config)
       hint = state.Get(d.Name + ":" + d.CertName).CertID
       result, err = dest.Deploy(ctx, cert, hint)
       if err == nil: state.Set(d.Name + ":" + d.CertName, result)
     }()
5. 收集结果
6. 按退出码矩阵决定 exit code
```

### 10.2 并发模型

- semaphore channel 控制 concurrency（默认 5，可配置）
- 每个 destination 在独立 goroutine 跑
- 不做重试（v1）：失败就是失败，记日志 / 影响 exit code
- 不做 timeout 设置：依赖 context（CLI 默认 5 分钟超时——通过 cobra 上下文传入）

### 10.3 资源清理

- 写 state 用 atomic rename（写到 tmp 文件再 rename）
- HTTP client 复用 `http.Client`（每个 destination 内部各自一个）
- 不显式释放资源（依赖 Go GC）

---

## 11. 错误类型

```go
// internal/destination/destination.go
var (
    ErrInvalidConfig     = errors.New("invalid destination config")
    ErrUnknownType       = errors.New("unknown destination type")
    ErrCertNotFound      = errors.New("certificate not found in service")
    ErrAuth              = errors.New("authentication failed")
    ErrNetwork           = errors.New("network error")
    ErrCertRejected      = errors.New("certificate rejected by service")
    ErrQuota             = errors.New("service quota exceeded")
)
```

各 destination 包返回这些 sentinel error 或 wrapped error；runner 根据 error 类型决定日志级别和 exit code。

---

## 12. 依赖（go.mod）

| 库 | 用途 |
|----|------|
| `gopkg.in/yaml.v3` | YAML 解析 |
| `github.com/spf13/cobra` | CLI 子命令框架 |
| `github.com/mitchellh/mapstructure` | `map[string]any` → struct |
| 标准库 `crypto/x509`, `crypto/sha256` | cert 解析 / fingerprint |
| 标准库 `net/http` | HTTP client（Safeline 用） |

**v1 不引入**：阿里云官方 Go SDK（自己写 thin OpenAPI client，依赖少）

---

## 13. 测试策略

**v1 仅单元测试 + mock**，不写集成测试。

| 包 | 测试内容 |
|----|---------|
| `config` | YAML 解析正确 / 错误结构校验失败 / 缺失字段 |
| `cert` | PEM 解析 / sanitize 规则各 case / 损坏 PEM 报错 |
| `state` | 读写 / 损坏文件恢复 / 命名空间不冲突 |
| `destination`（interface）| mock destination 满足 interface |
| `destination/safeline` | mock HTTP server 模拟 Safeline API；覆盖：首次创建、覆盖更新、token 失效、cert name 冲突 |
| `destination/aliyun_esa` | mock HTTP server 模拟 ESA OpenAPI；覆盖：首次创建、覆盖更新、签名错误、SiteId 无效 |
| `runner` | mock destinations；覆盖：全成功、required 失败、required=false 失败、全部失败、并发 |
| `cli` | 不测（cobra 自己的 contract，靠手动验证） |

**mock 约定**：用 `httptest.NewServer` 提供 mock API；destination 包内不直接 import 对方，只测自己的 HTTP 行为。

---

## 14. 部署与运维

### 14.1 安装

```bash
# 1. 编译
go build -o ssl-update ./cmd/ssl-update

# 2. 安装
sudo install -m 0755 ssl-update /usr/local/bin/ssl-update

# 3. 准备 config
sudo install -d -m 0700 /etc/ssl-update
sudo cp config.example.yaml /etc/ssl-update/config.yaml
sudo chmod 600 /etc/ssl-update/config.yaml
# 然后填入真实凭据
```

### 14.1.1 接入 acme.sh reloadcmd

**情形 A：首次安装 acme.sh 证书**（acme.sh `--install-cert` 还没跑过）：

```bash
acme.sh --install-cert -d "*.a.com" \
  --reloadcmd "/usr/local/bin/ssl-update run --config /etc/ssl-update/config.yaml"
```

**情形 B：已有 acme.sh 任务，现在要加 reloadcmd**（用户当前场景，推荐）：

不要重新跑 `--install-cert`（会把 cert 重写到别的位置），直接编辑 acme.sh 的任务配置：

```bash
# 找到要改的任务文件
vi ~/.acme.sh/*.a.com/*.a.com.conf

# 在文件末尾追加一行（acme.sh 用这个变量做 reloadcmd）
Le_ReloadCmd='/usr/local/bin/ssl-update run --config /etc/ssl-update/config.yaml'
```

`~/.acme.sh/<domain>/<domain>.conf` 是 acme.sh 给每个域名的任务配置，acme.sh 每次签发/续期后会重读这个文件里的 `Le_ReloadCmd` 变量。改完保存即可生效，**不需要重启任何东西**，下次 acme.sh 检查续期（默认每天凌晨）就会用新 reloadcmd。

**注意**：
- reloadcmd 本身只在续期成功后才被触发
- 如果想立即验证 reloadcmd 配置正确，可以手动跑一次：
  ```bash
  ~/.acme.sh/acme.sh --renew -d "*.a.com" --force  # 强制续期（即使没到期）
  ```
- 不要把 reloadcmd 加到 `--renew` 的 `--reloadcmd` 里，那个是过期手动续期用的

### 14.2 systemd（可选）

ssl-update 本身**不需要独立 systemd unit**——acme.sh 自带 cron（每天检查续期），续期成功后才触发我们的 reloadcmd。

如需把日志接 journald，**只用 systemd-cat 包一层**即可（见 §14.3），无需写 unit 文件。

### 14.3 日志

**默认行为**：输出到 stdout/stderr，text 格式。

**接 journald 的两种方式**：

**方式 1：用 `systemd-cat` 包一层（推荐，最简）**

acme.sh 的 `Le_ReloadCmd` 改成：

```bash
Le_ReloadCmd='/usr/bin/systemd-cat -t ssl-update /usr/local/bin/ssl-update run --config /etc/ssl-update/config.yaml'
```

之后所有 reloadcmd 输出会进 journald，标签 `ssl-update`：

```bash
journalctl -t ssl-update           # 看本次启动后的所有日志
journalctl -t ssl-update -f        # 实时跟踪
journalctl -t ssl-update --since today
```

不依赖任何额外 Go 库。

**方式 2：slog JSON 格式 + 外部收集**

`config.yaml` 设 `log.format: json`，把 stdout 重定向到 log collector（Filebeat / Promtail / 阿里云 SLS 等）：

```yaml
log:
  level: info
  format: json
```

适合已经把日志接到了集中式日志平台的场景。

**v1 不内置**：文件日志（按日期 rotate 的 .log 文件）。需要的话外部 `tee` 一下：

```bash
Le_ReloadCmd='/usr/local/bin/ssl-update run --config /etc/ssl-update/config.yaml 2>&1 | tee -a /var/log/ssl-update.log'
```

记得配 logrotate。

### 14.4 升级

- 直接替换 `/usr/local/bin/ssl-update` 二进制
- state.json 保留（schema 带 `version` 字段，未来不兼容时迁移）

---

## 15. 风险与已知限制

| 风险 | 缓解 |
|------|------|
| state.json 损坏 → 全量重新创建 cert | file lock + atomic write + warn on parse fail |
| acme.sh 多个 cert 共享同一 destination（不同域名） | state 用 `dest_name:cert_name` 命名空间隔离 |
| ESA 不支持 custom cert 自动续期（官方原话） | 不影响我们——我们是手动调 `SetCertificate` |
| Safeline token 泄露 | 仅给"OPEN API" 权限范围勾选，不勾无关模块 |
| YAML 配置中凭据明文 | 600 权限 + .gitignore 排除 |
| 远端 API 临时不可用 → 整体失败 | v1 不做重试；未来可加 `--retry N` |
| 跨平台路径兼容 | v1 只支持 Linux |

---

## 16. 未来扩展（v1 不实现，仅记录）

- `ssl-update state prune` — 清理孤儿 state 条目
- 凭据外置（`api_token_env` / `api_token_file`）
- HTTP 代理支持（用于内网访问 WAF）
- webhook 通知（push 成功/失败发到 Slack / 飞书）
- retry with exponential backoff
- 更多 destination 实现（阿里云传统 CDN/DCDN、腾讯云 EdgeOne、CloudFront、HAProxy、nginx 配置等）

---

## 17. 验收标准

v1 完成的标志：

- [ ] `go build` 成功，生成 `ssl-update` 二进制
- [ ] `go test ./...` 全绿
- [ ] `config.example.yaml` 完整且注释清楚
- [ ] README 写清安装 / 配置 / 接入 acme.sh 步骤
- [ ] 手动 dry-run 通过
- [ ] 手动对 Safeline CE 真机 push 一次 cert 成功
- [ ] 手动对阿里云 ESA 真机 push 一次 cert 成功
- [ ] 模拟其中一个 destination 失败，验证 exit code 与日志行为符合 §9
