# AICodeAuditor

AICodeAuditor 是一个面向源代码的 AI 安全审计平台。把待审计项目作为任务上传，平台用 LLM 多智能体在本地阅读代码、追踪数据流、记录证据，产出可以复核的漏洞结论；同时内置一套不消耗 Token 的静态规则引擎，专门检查 AI 应用代码中的高风险写法。

整套 UI 由 Next.js 静态导出后嵌入后端，部署时只需要一个可执行文件和一个 PostgreSQL。

## 设计取向

- **只读、不出网**：Agent 只保留本地文件读写与平台数据库工具，Bash、WebFetch、浏览器、扫描器、MCP 等能力在装配层就被移除，配置也无法绕过。
- **过程可追溯**：每轮探索的意图、事实、命中的资产与最终漏洞都有血缘关系，结论能回到具体代码位置。
- **结论要复核**：漏洞进入「发现」后需要人工或 Agent 复核，支持有效 / 无效 / 待确认三态。
- **规则可解释**：静态规则全部是正则匹配，命中直接给出规则编号、文件、行号、代码片段和修复建议。

## 主要模块

| 模块 | 能力 |
| --- | --- |
| 任务 | 上传源码 zip，自动解压到独立工作目录；任务级并发上限、超时、暂停/恢复、排队 |
| 多智能体 | planner 拆解审计目标，worker 并发执行，主 Agent 统筹与收尾，支持人工介入对话 |
| 探索图谱 | 意图 → 事实 → 资产 → 漏洞的关联图，支持按任务回看审计路径 |
| 测试资产 | 接口、组件、第三方依赖的统一台账，带所需权限标注与覆盖状态 |
| 发现与复核 | 跨任务漏洞汇总、严重度分组、逐条复核与重测 |
| AI 代码审计 | 26 条内置静态规则，覆盖提示注入、模型输出执行、密钥泄露、工具滥用等 |
| LLM 管理 | 多套模型配置、轮询与故障切换、请求与响应录制 |
| Skill | 每个 `skills/<name>/SKILL.md` 即一个可被 Agent 调用的技能 |
| 组织权限 | 管理员 / 部门成员 / 部门访客，访客对任务只读，接口层独立校验 |
| 运维 | 通知推送、实时日志、版本检查与一键更新 |

## 一次审计的流程

1. 新建任务并上传源码包，平台解压到 `data/tasks/<id>/source`。
2. planner 根据任务描述和代码规模生成审计意图，分派给 worker。
3. worker 读取具体文件，记录事实与资产，遇到可疑点形成候选漏洞。
4. 主 Agent 汇总候选漏洞，补齐证据链，写入「发现」。
5. 在发现页逐条复核；确认有效的漏洞可以继续生成报告。
6. 任务结束后保留探索图谱，方便回溯某个结论是怎么得出来的。

## AI 代码审计（内置静态规则引擎）

LLM 擅长理解业务语义，但需要一层确定性检查来兜底，也方便在接入模型之前快速摸底。`aiaudit` 包实现了这层检查：

- 只读取文本，不执行代码、不联网、不调用模型；
- 规则集通过 `go:embed` 打进二进制，规则文件位于 `aiaudit/rules.json`，可直接增删；
- 默认跳过 `.git`、`node_modules`、`vendor`、构建产物、压缩文件与二进制文件，单文件上限 1 MB，可在代码中调整。

当前 26 条规则，按类别分布如下：

| 类别 | 规则示例 |
| --- | --- |
| 凭据与密钥 | AIC-001 硬编码模型/云平台密钥、AIC-003 `.env` 中的真实密钥 |
| 提示注入 | AIC-004 Python f-string 拼接用户输入、AIC-006 检索内容未隔离进入提示词 |
| 不安全代码执行 | AIC-007 模型输出进入 `eval` / `exec` / `subprocess` |
| 不安全反序列化 | AIC-008 `pickle` / `torch.load` 等不安全加载 |
| 供应链风险 | AIC-009 `trust_remote_code=True`、AIC-013 从网络直接执行脚本 |
| Agent 权限 | AIC-014 注册 Shell/Bash/REPL 工具、AIC-024 MCP 使用 `sh -c` 启动 |
| 数据与隐私 | AIC-021 系统提示词经接口返回、AIC-026 敏感环境变量发给模型 |
| 部署与暴露面 | AIC-016 监听 `0.0.0.0` / `share=True`、AIC-017 CORS `*` |
| 其他 | AIC-019 SSRF、AIC-020 路径穿越、AIC-023 记忆投毒 |

扫描结果包含：风险分（严重 25 / 高危 10 / 中危 4 / 低危 1，上限 100）、A–E 评级、按严重度与分类的统计、识别出的 AI 组件（OpenAI SDK、LangChain、PyTorch、MCP、向量库等）。

### 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/ai-audit/rules` | 规则目录 |
| `POST` | `/api/tasks/{id}/ai-audit/scan` | 扫描任务源码，可传 `{"include_tests": true}` |
| `GET` | `/api/tasks/{id}/ai-audit/report` | 读取最近一次扫描结果 |

扫描结果会同时落盘到 `data/tasks/<id>/ai-audit/report.json`，刷新页面仍可查看。任务没有上传源码时接口返回 409，避免误扫空目录。

## 目录结构

```
cmd/aicodeauditor/   进程入口、启动参数、自更新引导
server/              HTTP API、鉴权、任务编排、静态资源服务
agent/               多智能体运行时：planner / worker / 主 Agent / 复核
aiaudit/             AI 代码审计静态规则引擎与规则集
db/                  PostgreSQL 访问层、任务与资产模型
guard/               任务权限与访问控制
intercept/           工具调用拦截
javadeps/            Java 依赖索引与按需反编译
llmpool/ llmrec/     模型池、故障切换、请求录制
report/              报告生成
skills/              内置技能（SKILL.md）
third_party/harness  内置 Agent SDK（已源码化，无需外部下载）
web/                 Next.js 前端（静态导出）
```

## 部署

### 前置条件

- PostgreSQL 16（必需）
- 运行二进制时不需要 Node.js；Docker 镜像与预编译包都已包含前端资源

### 方式一：二进制

```bash
# 1. 准备配置：数据库连接可用 config.json 或环境变量
cp config.example.json config.json
#    编辑 database.host / port / user / password / dbname
#    或者直接 export AICODEAUDITOR_PG_DSN='postgres://user:pass@127.0.0.1:5432/aicodeauditor?sslmode=disable'

# 2. 启动（start.sh 会在进程退出后按退出码决定是否重新拉起，一键更新依赖它）
./start.sh

# 3. 浏览器打开 http://localhost:7878，首次访问会进入 /setup 创建管理员账号
```

可用参数：

```bash
./aicodeauditor -addr :7878 -data ./data
```

`-proxy` 默认关闭，平台不会主动对外发起请求。

### 方式二：Docker Compose

镜像只负责运行，二进制需要先编译好：

```bash
# 构建前端 + Linux 二进制（需要 Go、Node.js、rsync）
./build.sh --target linux/amd64

# 放到 Dockerfile 约定的位置
mkdir -p dist/amd64
cp dist/aicodeauditor-linux-amd64/aicodeauditor dist/amd64/

cp .env.example .env         # 必须设置 POSTGRES_PASSWORD
docker compose up -d --build
```

Compose 会把 `./data`（SQLite、任务源码）和 `./skills` 挂载进容器，重建容器不会丢数据。

### 方式三：源码构建

要求 Go 1.26.3、Node.js 20+、npm、rsync。

```bash
cd web
npm ci
npm run build:static
cd ..

mkdir -p server/webui/dist
rsync -a --delete web/out/ server/webui/dist/

CGO_ENABLED=0 go build -tags embedui -o aicodeauditor ./cmd/aicodeauditor
```

或者直接执行 `./build.sh`（自动完成前端构建、资源同步和编译）；加 `--release` 会交叉编译多平台并生成 zip。

## 配置

优先级：环境变量 > `config.json` > 默认值。

| 变量 | 说明 |
| --- | --- |
| `AICODEAUDITOR_CONFIG` | 配置文件路径，默认可执行文件同级的 `config.json` |
| `AICODEAUDITOR_PG_DSN` | PostgreSQL 连接串，优先于配置文件中的分字段配置 |
| `AICODEAUDITOR_SKILL_DIR` | 技能根目录，默认可执行文件同级的 `skills/` |
| `AICODEAUDITOR_LLM_PROVIDER` | `anthropic` 或 `openai` |
| `AICODEAUDITOR_LLM_MODEL` | 模型 ID，留空使用该供应商默认值 |
| `AICODEAUDITOR_LLM_BASE_URL` | 自定义 API 地址（兼容代理或自建网关） |
| `AICODEAUDITOR_LLM_PROXY` | 访问模型服务时使用的 HTTP 代理 |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | 对应的凭据，也可以在系统设置页填写 |
| `AICODEAUDITOR_JAVA_LOCAL_REPO` | 本机 Maven 仓库路径，开启按坐标读取 jar 的能力 |
| `AICODEAUDITOR_JAVA_PATH` / `AICODEAUDITOR_VINEFLOWER_JAR` / `AICODEAUDITOR_CFR_JAR` | Java 反编译相关路径 |
| `AICODEAUDITOR_DECOMPILE_TIMEOUT` / `AICODEAUDITOR_DECOMPILE_MAX_HEAP` | 反编译超时与堆上限 |

模型配置也可以在「系统 → LLM」中维护多套档位，按任务指定或自动轮询。

## 权限模型

| 角色 | 范围 |
| --- | --- |
| 管理员 | 所有任务、账号、部门与系统配置 |
| 部门成员 | 本部门任务可读写，可创建任务、发起对话 |
| 部门访客 | 本部门任务只读，不能暂停/删除任务，也不能发起对话 |

前端会按权限隐藏入口，但后端对每个 `/api/tasks/{id}/...` 请求独立校验，不能靠直接调接口绕过。

## 开发

```bash
# 后端
go build ./...
go test ./...

# 前端（离线演示数据，不需要后端）
cd web
NEXT_PUBLIC_MOCK=1 npm run dev

# 前端静态构建
npm run build:static
```

`server` 包的测试需要可连接的 PostgreSQL（通过 `AICODEAUDITOR_PG_DSN` 指定）；其余包可以直接运行。

## 许可

本项目使用 GNU Affero General Public License v3.0，详见 [LICENSE](LICENSE)。

LLM 生成的审计结论可能存在漏报与误报，请人工复核后再用于生产决策。请仅对你有权测试的代码使用本工具。
