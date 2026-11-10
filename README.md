# shellhunt · 离线 WebShell 静态检测引擎
## 合规与安全声明（必读）
- 仓库内置的"恶意样本"全部是**合成的、不可执行的文本 fixture**，统一以 `.phps` 扩展名存放，绝不使用可执行扩展名，仅用于检测能力的回归测试与演示。
- 本项目只做**静态文本分析**：不执行、不解释、不联网传输任何样本内容。
- 引擎面向"检测与防御"，不提供任何 WebShell 的生成、免杀、变形、利用功能；规则中的危险特征串必须打散或用占位符拼接书写，禁止出现可直接复制运行的完整后门代码。
> 所有 fixture 仅为检测回归用的合成文本，运行时只读取、不执行；请勿提交真实恶意代码。
## 1. 项目简介
shellhunt 面向断网环境中的网站源码体检：给定一个**白名单内**的源码目录，递归收集文本文件，融合四路信号并给出可解释的风险分：
1. **YAML 规则匹配**：危险函数、请求直连执行、回调后门、编码包裹、文件落地、家族标志等。
2. **token 级启发式**：动态函数调用、超全局变量与危险 sink 的直连、拼接/字符构造/变量变量等混淆特征。
3. **熵与编码链**：整体香农熵、高熵长串、嵌套解码链深度。
4. **哈希与基线**：已知坏哈希、人工审核白名单、干净基线的新增/修改标记。
Web 端提供扫描任务管理、状态轮询、文件明细、HTML/JSON 离线报告；CLI 提供扫描、基线和建库入口。默认绑定 `127.0.0.1:8000`，不使用任何外网服务。
能力边界：仅做**静态文本分析**，不执行/沙箱运行样本，不做动态检测；不是杀毒软件或通用 SAST，存在**误报与漏报**。不做实时监控、压缩包递归、在线更新、云端查杀、告警推送、多用户鉴权。PHP 分析为 token 级近似（无 AST），ASP/JSP 仅走通用规则与特征。
## 2. 快速开始
```bash
python -m pip install -r requirements.txt  # 仅 Flask / PyYAML / pytest
python app.py                             # 首次启动自动建表
```
浏览器打开 `http://127.0.0.1:8000`。
首页有两种使用方式：
- 点击 **Scan demo site**：一键扫描 `fixtures/site_demo/`，完成后查看任务详情。
- 在 **Scan a directory** 中选择白名单内的目录、规则集与阈值，点击 **Start scan**。
也可以完全使用命令行：
```bash
python app.py initdb
python app.py scan fixtures/site_demo
python app.py scan fixtures/corpus/benign --json
python app.py baseline fixtures/corpus/benign --output data/clean-baseline.json
python app.py serve --host 127.0.0.1 --port 8000
```
运行测试：
```bash
pytest -q
```
测试使用 `tmp_path` 隔离文件与 SQLite，不访问网络；无符号链接权限的 Windows 会自动跳过相关用例。已安装 `pytest-cov` 时可运行 `pytest -q --cov=shellhunt.engine --cov-report=term-missing`，当前引擎总体覆盖率约 92%，满足核心 ≥85% 的目标。
## 3. 演示站点预期检出
`fixtures/site_demo/` 共有 29 个文件，其中 20 个正常业务 `.phps` + CSS/JS/README，另混入 6 个不同手法的合成后门。任务详情应显示 **6 个 malicious、20 个 clean、0 个 suspicious**：
| 文件 | 手法 | 预期 |
| --- | --- | --- |
| `modules/cache_thumb.phps` | 直接求值 sink + 请求注释占位 | malicious |
| `modules/gallery_callback.phps` | 请求选择回调 | malicious |
| `modules/stats_loader.phps` | 解码链 + 求值 | malicious |
| `modules/avatar_payload.phps` | 高熵载荷 + 解码/求值 | malicious |
| `modules/plugin_writer.phps` | 请求内容写入文件 | malicious |
| `modules/legacy_import.phps` | 请求控制 include | malicious |
这 6 个文件同时登记在 `known_bad.sha256` 中，因此哈希命中会把最终分强制为 100；报告仍会列出规则证据、特征明细与熵信号，便于人工复核。正常文件不产生规则命中，且维护白名单以免误报。
语料回归硬指标：
- `fixtures/corpus/malicious/`：35 个合成后门，全部 suspicious 及以上；其中 35 个均为已登记哈希，实际判 malicious。
- `fixtures/corpus/benign/`：26 个正常业务文件，全部 clean。
## 4. 规则 DSL 教程
规则目录中的每个 `*.yaml` 文件形如：
```yaml
rules:
  - id: CUSTOM-001
    name: Rule title
    severity: high
    weight: 30
    match: regex
    pattern: '(?i)\bmy_marker\s*\('
    description: What this rule means.
    remediation: How to review or remove it.
```
字段：
| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 3–64 位字母、数字、点、下划线、短横线；目录内与合并规则集内唯一 |
| `name` | 是 | 展示名 |
| `severity` | 是 | `low` / `medium` / `high` / `critical` |
| `weight` | 是 | 1–100，评分时受单规则与规则总分封顶 |
| `match` | 是 | `regex` / `literal` / `token_seq` / `multiline_regex` |
| `pattern` | 是 | 正则、字面串，或 token_seq 的 token 列表 |
| `description` | 是 | 规则含义 |
| `remediation` | 是 | 处置建议 |
| `flags` | 否 | regex 标志，支持 `i` / `m` / `s` / `x` |
| `max_gap` | 否 | token_seq 的最大 token 间隔，默认 8 |
`match` 类型：
- `regex`：单行/常规正则，适合函数调用与单行组合。
- `literal`：大小写不敏感的字面串匹配。
- `token_seq`：按“token 顺序 + 最大间隔”近似匹配，忽略注释和空白；不会要求完整 AST。
- `multiline_regex`：强制 `MULTILINE | DOTALL`，适合跨行组合。
### 示例 1：regex
```yaml
rules:
  - id: CUSTOM-EVAL-01
    name: Split dynamic evaluation signature
    severity: critical
    weight: 35
    match: regex
    pattern: '(?i)\bev[a]l\s*\('
    description: Dynamic evaluation construct appears in source.
    remediation: Trace the argument origin and remove the sink.
```
### 示例 2：token_seq
```yaml
rules:
  - id: CUSTOM-SEQ-01
    name: Error suppression near configuration
    severity: medium
    weight: 12
    match: token_seq
    pattern: ['error_reporting', '(', '0']
    max_gap: 4
    description: Error reporting is disabled in source.
    remediation: Restore diagnostics and review the surrounding change.
```
### 示例 3：multiline_regex
```yaml
rules:
  - id: CUSTOM-CHAIN-01
    name: Decoder chained to evaluation marker
    severity: critical
    weight: 38
    match: multiline_regex
    pattern: '(?is)base64_deco[d]e[\s\S]{0,200}(?:ev[a]l)\s*\('
    description: A decoder and an execution marker occur close together across lines.
    remediation: Decode in isolation and remove any executable path.
```
使用自定义规则：
```bash
mkdir my_rules
# 将上面的规则保存为 my_rules/rules.yaml
python app.py scan fixtures/site_demo --ruleset my_rules
```
自定义规则与内置规则合并，**相同 id 覆盖内置规则**。Web 端不接收任意路径：把可信目录加入 `config.yaml` 的 `engine.custom_rules_dirs`，目录名会出现在规则集下拉框中。
坏 YAML、非法 severity、重复 id、正则编译失败都会抛出带 `文件:行号` 的错误。
## 5. 评分模型
每个文件的最终分为 0–100，默认阈值：`0–19` → `clean`，`20–59` → `suspicious`，`60–100` → `malicious`。默认信号权重与封顶（可在 `config.yaml` 的 `scoring` 中调整）：
| 信号 | 权重 / 上限 |
| --- | --- |
| 每条规则 | 使用规则 `weight`，单规则最多 40；每个 id 每个文件只计一次 |
| 规则总分 | 封顶 70 |
| 请求直连 `direct_input` | 子分数 × 22 |
| 动态调用 `dynamic_call` | 子分数 × 18 |
| 危险执行调用 `dangerous_calls` | 子分数 × 8 |
| 混淆 `obfuscation` | 子分数 × 10 |
| 特征总分 | 封顶 40 |
| 高熵长串 | 每个 +2，类内最多 +8 |
| 嵌套编码链 | 每层 +4，类内最多 +12 |
| 整体高熵 | +3 |
| 熵总分 | 封顶 15 |
| 基线外新增 | +8 |
| 基线内被修改 | +12 |
| 基线总分 | 封顶 15 |
| 已知坏哈希 | 直接 100，`malicious`，覆盖其他分数 |
| 人工白名单哈希 | 直接 0，`clean`，但已知坏哈希优先 |
报告中的每条加分都有来源：规则 id、命中行、证据片段、特征行或熵统计。`hits` 表保留每条证据；同一规则重复命中不重复计分。封顶会让“单条规则把分数打满”失效，避免过度自信。
修改阈值：
```yaml
thresholds:
  suspicious: 25
  malicious: 70
```
Web 创建任务时也可临时覆盖这两个阈值。任务会保存当时的阈值快照。
## 6. 目录结构
```text
shellhunt/
├── app.py                         # create_app + serve/scan/baseline/initdb CLI
├── config.example.yaml
├── requirements.txt
├── shellhunt/
│   ├── config.py                  # 配置、白名单根目录、路径穿越校验
│   ├── db.py                      # SQLite 建表与 DAO
│   ├── engine/                    # loader/tokenizer/rules/features/entropy/hashdb/scoring/scanner
│   ├── ruleset/                   # core_rules.yaml（25 条内置规则）、known_bad/allowlist
│   ├── service/                   # jobs 状态机、JSON/自包含 HTML 报告
│   └── web/                       # routes、Jinja2 模板、离线 CSS
├── fixtures/
│   ├── corpus/malicious/          # 35 个 .phps 合成样本
│   ├── corpus/benign/             # 26 个 .phps 正常样本
│   └── site_demo/                 # 29 个文件的演示站点（6 个后门）
└── tests/                         # pytest / Flask test client
```
所有扫描结果保存在 `data/shellhunt.db`，可在 `config.yaml` 修改。运行生成的数据库与基线文件默认被 `.gitignore` 忽略。
## 7. 路由一览
| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/` | 首页、扫描表单、历史任务、演示按钮 |
| POST | `/scans` | 表单创建扫描任务（303 跳转详情） |
| POST | `/demo` | 一键扫描演示站点 |
| GET | `/scans/<id>` | 任务详情：状态、定级分布、Top 风险、规则排行、证据 |
| POST | `/scans/<id>/delete` | 删除任务及其文件/命中（级联） |
| GET | `/api/scans` | 任务历史 JSON |
| POST | `/api/scans` | 创建任务，返回 202 与轮询地址 |
| GET | `/api/scans/<id>` | 任务状态与汇总 |
| GET | `/api/scans/<id>/report` | 完整 JSON 报告（未完成返回 409） |
| GET | `/reports/<id>.json` | 下载 JSON 报告 |
| GET | `/reports/<id>.html` | 打开自包含离线 HTML 报告 |
| GET | `/healthz` | 本地健康检查 |
创建任务的 JSON 示例：
```bash
curl -s -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"fixtures/site_demo","suspicious":20,"malicious":60}'
```
服务只接受配置白名单根目录内的真实目录。包含 `..` 的请求、指向白名单外的符号链接目标、越界路径均返回 400；扫描器本身不跟随符号链接。
## 8. 误报与漏报处理
### 8.1 添加人工白名单哈希
对已人工确认安全的文件，计算 SHA-256 并加入 `shellhunt/ruleset/allowlist.sha256`：
```bash
python -c "import hashlib,pathlib; p=pathlib.Path('path/to/reviewed-file.phps'); print(hashlib.sha256(p.read_bytes()).hexdigest(), 'reviewed-clean')"
```
把输出粘贴到文件（格式：`<sha256>  <备注>`），重新扫描即可将该文件固定为 clean。已知坏哈希的优先级更高；同时命中的文件仍判 malicious。
### 8.2 使用干净基线
```bash
python app.py baseline fixtures/corpus/benign
```
目标同样必须在允许根目录内。默认写入 `data/baseline.json`；当扫描目标与基线根目录一致时，新增文件 +8、修改文件 +12，可把“刚冒出来的文件”与“被篡改文件”排到前面。基线不是杀毒库，只代表生成时的已知状态。
### 8.3 调整阈值与规则
- 误报多：提高 `thresholds.suspicious` / `thresholds.malicious`，或为具体文件加白名单哈希。
- 规则不符业务：在 `custom_rules_dirs` 中覆盖同 id 规则，或降低该规则 `weight`。
- 漏报：添加自定义规则，优先使用跨行组合与 token_seq，减少单关键词噪声。
- 不要为了让某个样本通过而删除通用规则；优先使用白名单或基线。
## 9. 安全约束与已知限制
- 完全离线：没有外网请求、云端模型、遥测或在线更新。
- 默认只绑定 `127.0.0.1`，不要在没有认证与反向代理保护的情况下暴露到公网。
- 目标目录必须在 `security.allowed_roots` 内；路径穿越与符号链接逃逸在入口和遍历层双重拒绝。
- 默认跳过大于 2 MiB 的文件、前 8 KiB 含 NUL 的二进制文件和未知扩展名；跳过原因会出现在报告里。
- 静态规则可能被传统混淆绕过；熵与特征只能提供相关信号，不等价于沙箱结论。
- 哈希命中对应的是当前 fixture 的精确字节；修改任一空格都会改变哈希，因此哈希库主要用于回归与已知样本。
## 10. 验收自检
```bash
pytest -q
python app.py initdb
python app.py scan fixtures/site_demo
```
预期：
- `pytest -q` 全绿。
- 演示站点 6 个 malicious、20 个 clean、0 个 suspicious。
- 恶意语料 35/35 suspicious 及以上，正常语料 26/26 clean。
- HTML 报告可离线打开，证据自动转义且截断至 120 字符；JSON 报告包含 `job / summary / files / hits / signals / features / entropy`。
- 坏规则报错包含文件名与行号；同 id 自定义规则覆盖内置规则。
