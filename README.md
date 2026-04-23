# Webshell Agent (WSA)

基于 LangGraph 的 Agent 化 Webshell 检测系统。核心思路：**规则做召回，语义做精度，沙箱做确认**。

覆盖 Nginx-PHP、Tomcat（JSP/Servlet）、Spring Boot（含内存马）三大技术栈，支持离线批量扫描和实时监测两种模式。

## 系统架构

```mermaid
graph TB
    subgraph Input["输入层"]
        A1[离线批量扫描]
        A2[inotify 实时监控]
        A3[审计日志]
        A4[远程探针]
    end

    subgraph Core["LangGraph 编排核心"]
        direction TB
        B1[Ingest<br/>文件读取 · Hash · 熵 · MIME]
        B2[Classify<br/>技术栈识别]
        B3[Deobfuscate<br/>多层反混淆]
        B4[Fast Fail<br/>未知类型快速退出]

        subgraph Static["静态分析流水线"]
            C1[Regex Scan<br/>26 条规则]
            C2[YARA Scan<br/>10 条规则]
            C3[AST Analysis<br/>污点分析 · 反射链 · ClassLoader]
            C4[Stat Features<br/>熵 · 行长 · Base64 密度]
        end

        D1[Confidence Gate<br/>加权评分 · 多源加成]

        subgraph Deep["深度分析（按需）"]
            E1[LLM Judge<br/>Claude 语义研判]
            E2[Sandbox<br/>Docker + strace]
        end

        F1[Aggregate<br/>证据融合 · 最终判定]
        F2[Emit<br/>ECS 告警输出]
    end

    subgraph Output["输出层"]
        G1[CLI 表格/JSON]
        G2[ECS 告警]
        G3[MITRE ATT&CK 映射]
    end

    A1 & A2 & A3 & A4 --> B1
    B1 --> B2
    B2 -->|php/jsp| B3
    B2 -->|java_class| C3
    B2 -->|script| C1
    B2 -->|unknown| B4
    B3 --> C1 --> C2 --> C3
    C3 --> C4 --> D1
    B4 --> F1
    D1 -->|"≥0.9 或 ≤0.1"| F1
    D1 -->|"0.3~0.7"| E1
    D1 -->|"0.7~0.9"| E2
    E2 --> E1 --> F1
    F1 --> F2
    F2 --> G1 & G2 & G3

    style Core fill:#1a1a2e,color:#fff
    style Static fill:#16213e,color:#fff
    style Deep fill:#0f3460,color:#fff
```

## LangGraph 管道流程

```mermaid
stateDiagram-v2
    [*] --> ingest
    ingest --> classify

    classify --> deobfuscate: php / jsp
    classify --> ast_java: java_class
    classify --> regex_scan: script
    classify --> fast_fail: unknown

    deobfuscate --> regex_scan
    regex_scan --> yara_scan
    yara_scan --> ast_php: php
    yara_scan --> ast_jsp: jsp
    yara_scan --> stat_features: other

    ast_java --> stat_features
    ast_php --> stat_features
    ast_jsp --> stat_features

    stat_features --> confidence_gate

    confidence_gate --> aggregate: direct (≥0.9 / ≤0.1)
    confidence_gate --> llm_judge: llm (0.3~0.7)
    confidence_gate --> sandbox: sandbox (0.7~0.9)

    sandbox --> llm_judge
    llm_judge --> aggregate

    fast_fail --> aggregate
    aggregate --> emit
    emit --> [*]
```

## 置信门决策逻辑

```mermaid
graph LR
    A[综合置信度] --> B{confidence}
    B -->|"≥ 0.9"| C[直出 → malicious]
    B -->|"≤ 0.1"| D[直出 → benign]
    B -->|"0.7 ~ 0.9"| E[Sandbox 分析]
    B -->|"0.3 ~ 0.7"| F[LLM 语义研判]
    B -->|"0.1 ~ 0.3"| G[直出 → benign/unknown]
    E --> F
    F --> H[Aggregate 最终判定]
    C & D & G --> H

    style C fill:#e74c3c,color:#fff
    style D fill:#2ecc71,color:#fff
    style E fill:#f39c12,color:#fff
    style F fill:#3498db,color:#fff
```

## 快速开始

### 环境要求

- Python 3.11+（推荐 3.12）
- [uv](https://github.com/astral-sh/uv) 包管理器
- JDK 11+（可选，用于 .class 反编译）
- Anthropic API Key（可选，用于 LLM 语义研判）

### 安装

```bash
# 克隆项目
git clone <repo-url> webshell-agent
cd webshell-agent

# 创建虚拟环境并安装依赖
uv venv --python 3.12
uv pip install -e ".[dev]"

# 配置 LLM（可选）
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 基本使用

```bash
# 扫描单个文件
wsa scan suspicious.jsp

# 扫描目录（递归）
wsa scan /var/www/html/ --verbose

# 扫描 JAR/WAR 包
wsa scan app.war

# 输出 JSON 格式
wsa scan target/ --format json --output results.json

# 跳过 LLM 分析（纯静态检测，更快）
wsa scan target/ --no-llm

# 并发扫描，指定线程数
wsa scan /opt/tomcat/webapps/ --workers 8

# 按扩展名过滤
wsa scan target/ --include "*.jsp"
```

### CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `TARGET` | 扫描目标（文件/目录/ZIP） | 必填 |
| `--format, -f` | 输出格式：table / json / jsonl | table |
| `--output, -o` | 输出到文件 | stdout |
| `--workers, -w` | 并发线程数 | 4 |
| `--include` | Glob 包含模式 | 全部 |
| `--exclude` | Glob 排除模式 | 无 |
| `--no-llm` | 跳过 LLM 分析 | false |
| `--verbose, -v` | 详细输出（显示 Top Evidence） | false |

### 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 全部 benign |
| 1 | 发现 malicious |
| 2 | 发现 suspicious |
| 3 | 扫描出错 |

### 输出示例

```
                              Scan Results
┌──────────────────┬───────┬────────────┬────────────┬──────────┐
│ File             │ Stack │  Verdict   │ Confidence │ Evidence │
├──────────────────┼───────┼────────────┼────────────┼──────────┤
│ behinder_v3.jsp  │ jsp   │ MALICIOUS  │     100.0% │        5 │
│ cmd_exec.jsp     │ jsp   │ MALICIOUS  │     100.0% │        3 │
│ godzilla.jsp     │ jsp   │ MALICIOUS  │     100.0% │        3 │
│ script_engine.j… │ jsp   │ MALICIOUS  │      90.0% │        3 │
│ file_upload.jsp  │ jsp   │ SUSPICIOUS │      68.0% │        2 │
│ hello.jsp        │ jsp   │   BENIGN   │       5.0% │        0 │
│ dashboard.jsp    │ jsp   │   BENIGN   │       5.0% │        0 │
└──────────────────┴───────┴────────────┴────────────┴──────────┘
┌─────────────────────── Summary ───────────────────────┐
│ Total: 7 │ 4 malicious │ 1 suspicious │ 2 benign     │
└──────────────────────────────────────────────────────-┘
```

## 配置

所有配置通过环境变量设置，前缀 `WSA_`：

```bash
# LLM 配置
export WSA_LLM_PROVIDER=anthropic          # anthropic / openai / local
export WSA_LLM_MODEL=claude-sonnet-4-20250514
export WSA_LLM_TEMPERATURE=0.0

# 置信门阈值
export WSA_GATE_HIGH=0.9                   # ≥ 此值直出 malicious
export WSA_GATE_LOW=0.1                    # ≤ 此值直出 benign

# 扫描参数
export WSA_MAX_FILE_SIZE_MB=50
export WSA_SCAN_TIMEOUT_SEC=30
export WSA_SCAN_WORKERS=4

# 规则目录
export WSA_RULES_DIR=rules
export WSA_YARA_DIR=rules/yara
export WSA_REGEX_DIR=rules/regex
```

## 检测能力

### 检测引擎

| 引擎 | 方法 | 规则数 | 权重 | 用途 |
|------|------|--------|------|------|
| Regex | YAML 驱动正则匹配 | 26 条 | 0.9 | 已知特征召回 |
| YARA | 二进制/文本模式匹配 | 10 条 | 1.0 | 字节码级检测 |
| AST | javalang 污点分析 | 4 类检测 | 1.0 | Source→Sink 路径 |
| Stat | 熵/行长/Base64 密度 | 3 类异常 | 0.5 | 辅助信号 |
| LLM | Claude 语义研判 | - | 0.8 | 未知变种精度 |

### 覆盖的威胁类型

**JSP Webshell（14 条 Regex + 5 条 YARA）：**
- Runtime.exec / ProcessBuilder 命令执行
- 反射链（Class.forName → getMethod → invoke）
- BCEL ClassLoader 滥用
- 冰蝎（Behinder）v3/v4
- 哥斯拉（Godzilla）
- ScriptEngine 动态执行
- 文件写入后门
- Thread ClassLoader 操纵

**Java .class（12 条 Regex + 5 条 YARA）：**
- Runtime.exec / ProcessBuilder
- 反射链 / defineClass
- BCEL / Unsafe
- 反序列化（ObjectInputStream）
- JNDI 注入
- EL 表达式注入
- Base64 + ClassLoader 组合

**AST 分析（4 类检测）：**
- 污点分析：request.getParameter → exec/eval/FileOutputStream
- 反射链检测：Class.forName → getMethod → invoke
- ClassLoader 滥用：defineClass / loadClass
- 危险类型实例化：Runtime / ProcessBuilder / ScriptEngine

### 判定逻辑

```
最终判定 = f(静态置信度, LLM 判定, Sandbox 报告)

静态置信度 = max(各证据加权分) + 多源加成(+0.1) + 统计异常加成(+0.05)
  权重: yara=1.0, regex=0.9, ast=1.0, stat=0.5

LLM 融合:
  静态说 malicious + LLM 说 benign → 0.7×静态 + 0.3×LLM（保守）
  其他情况 → 0.6×静态 + 0.4×LLM

判定阈值:
  ≥ 0.8 → malicious
  ≥ 0.4 → suspicious
  ≤ 0.15 → benign
  其他 → unknown
```

## 项目结构

```
webshell-agent/
├── pyproject.toml                    # 项目配置 & 依赖
├── webshell_agent_design.md          # 完整设计文档
├── rules/
│   ├── regex/
│   │   ├── java_webshell.yaml        # 12 条 Java 正则规则
│   │   └── jsp_webshell.yaml         # 14 条 JSP 正则规则
│   ├── yara/
│   │   ├── java/suspicious_class.yar # 5 条 Java YARA 规则
│   │   └── jsp/webshell_generic.yar  # 5 条 JSP YARA 规则
│   └── java_lib_whitelist.yaml       # JAR 白名单（Spring, Tomcat 等）
├── src/wsa/
│   ├── config.py                     # pydantic-settings 配置
│   ├── state.py                      # ScanState / Evidence / FileMeta
│   ├── graph.py                      # LangGraph 主图（15 节点）
│   ├── cli/scan.py                   # Typer + Rich CLI
│   ├── nodes/
│   │   ├── ingest.py                 # 文件读取 · Hash · 熵
│   │   ├── classify.py               # 技术栈识别
│   │   ├── deobfuscate.py            # Base64/Hex 反混淆
│   │   ├── regex_scan.py             # 正则规则扫描
│   │   ├── yara_scan.py              # YARA 规则扫描
│   │   ├── ast_jsp.py                # JSP → Java 合成 → AST 分析
│   │   ├── ast_java.py               # .class 反编译 → AST 分析
│   │   ├── stat_features.py          # 统计特征提取
│   │   ├── gate.py                   # 置信门 & 路由决策
│   │   ├── llm_judge.py              # LLM 语义研判
│   │   ├── aggregate.py              # 证据汇总 & 最终判定
│   │   └── fast_fail.py              # 未知类型快速退出
│   ├── tools/
│   │   ├── fs.py                     # 文件 I/O · Hash · 熵 · MIME
│   │   ├── jsp_preprocess.py         # JSP 解析 & Java 代码合成
│   │   ├── java_ast.py               # Java AST 污点分析
│   │   ├── cfr.py                    # CFR 反编译 / javap 降级
│   │   └── jar_scanner.py            # JAR/WAR 解压 & 遍历
│   └── rules/
│       ├── regex_engine.py           # YAML 驱动正则引擎
│       └── yara_loader.py            # YARA 编译 & 扫描封装
├── tests/
│   ├── unit/                         # 15 个单元测试文件
│   ├── e2e/                          # 端到端集成测试
│   └── fixtures/                     # 测试样本
│       ├── malicious/                # 8 个恶意 JSP 样本
│       ├── benign/                   # 4 个良性 JSP 样本
│       └── hard_negatives/           # 3 个困难负样本
└── bench/                            # 基准测试（规划中）
```

## 测试

```bash
# 运行全部测试（77 个）
uv run pytest tests/ -v

# 仅单元测试
uv run pytest tests/unit/ -v

# 仅端到端测试
uv run pytest tests/e2e/ -v

# 运行特定测试
uv run pytest tests/e2e/test_java_pipeline.py::TestMetrics -v -s
```

### 当前测试指标

| 指标 | 值 | 目标 |
|------|-----|------|
| 测试总数 | 77 | - |
| 通过率 | 100% | 100% |
| Recall（恶意检出率） | 100%（8/8） | ≥ 85% |
| FPR（误报率） | 0%（0/7） | ≤ 1% |
| 执行时间 | ~23s | - |

## 开发路线图

```mermaid
gantt
    title Webshell Agent 开发路线图
    dateFormat YYYY-MM-DD
    axisFormat %m月

    section M1 最小闭环
    项目脚手架 & 配置           :done, m1s01, 2025-01-01, 1d
    State & Evidence 模型       :done, m1s02, after m1s01, 1d
    Ingest 节点                 :done, m1s03, after m1s02, 1d
    Classify 节点               :done, m1s04, after m1s03, 1d
    Regex 引擎 & 规则集         :done, m1s05, after m1s02, 2d
    YARA 加载器 & 规则集        :done, m1s06, after m1s02, 2d
    反混淆节点                  :done, m1s07, after m1s02, 2d
    统计特征节点                :done, m1s09, after m1s02, 1d
    置信门节点                  :done, m1s10, after m1s09, 1d
    LLM 语义研判                :done, m1s11, after m1s10, 2d
    Aggregate & Emit            :done, m1s12, after m1s11, 1d
    主图构建                    :done, m1s13, after m1s12, 2d
    CLI 扫描入口                :done, m1s14, after m1s13, 2d

    section M2 JSP/Java 检测
    JSP 预处理                  :done, m2s01, after m1s14, 2d
    Java AST 分析               :done, m2s02, after m2s01, 2d
    CFR 反编译集成              :done, m2s03, after m1s14, 2d
    Java .class 检测            :done, m2s04, after m2s03, 2d
    Fat Jar/WAR 扫描            :done, m2s05, after m2s04, 3d
    集成测试 & 基准             :done, m2s06, after m2s05, 2d

    section M3 内存马探测
    Java Agent 探针核心         :m3s01, after m2s06, 5d
    Python JVM Attach 工具      :m3s02, after m3s01, 2d
    Memshell Hunter Agent       :m3s03, after m3s02, 3d
    子图 & 主图集成             :m3s04, after m3s03, 2d
    端到端测试                  :m3s05, after m3s04, 3d

    section M4 生产化部署
    PostgreSQL 存储层           :m4s01, after m3s05, 3d
    Checkpoint 持久化           :m4s02, after m4s01, 2d
    FastAPI 服务层              :m4s03, after m4s02, 3d
    Docker Compose              :m4s04, after m4s03, 2d
    K8s Helm Chart              :m4s05, after m4s04, 3d
    主机探针 Agent              :m4s06, after m4s03, 3d
    SOC 工作台                  :m4s07, after m4s03, 5d
    生产加固 & 全量回归         :m4s08, after m4s07, 3d

    section M5/M6 持续演进
    RAG 样本库扩张              :m5s01, after m4s08, 14d
    对抗变形器                  :m6s01, after m5s01, 14d
```

### 里程碑详情

| 里程碑 | 周期 | 状态 | 目标 |
|--------|------|------|------|
| **M1: 最小闭环** | 4 周 | ✅ 已完成 | 核心管道全链路：Ingest → Classify → Regex/YARA → StatFeatures → Gate → LLM → Aggregate → Emit；CLI 扫描 |
| **M2: JSP/Java 检测** | 4 周 | ✅ 已完成 | JSP 预处理 & AST 分析；CFR 反编译；Java .class 检测；Fat Jar/WAR 扫描；Recall ≥ 85% |
| **M3: 内存马探测** | 4 周 | 📋 规划中 | 独立 Java Agent（JVM Attach）；Filter/Servlet/Controller 枚举；ClassAnalyzer 打分；Python 集成 |
| **M4: 生产化部署** | 4 周 | 📋 规划中 | PostgreSQL 持久化；FastAPI REST API；Docker Compose；K8s Helm Chart；主机探针；SOC 工作台 |
| **M5: 智能演进** | 持续 | 📋 规划中 | RAG 样本库扩张；模型微调；主动学习 |
| **M6: 对抗增强** | 持续 | 📋 规划中 | 对抗变形器；SOAR 对接；自动修复 |

### M3 内存马探测（规划）

```mermaid
graph LR
    A[discover_jvms<br/>jps -lv] --> B[jvm_attach_probe<br/>注入 Agent]
    B --> C[HandlerEnumerator<br/>反射枚举 Filter/Servlet/Controller]
    C --> D[ClassAnalyzer<br/>可疑度打分]
    D --> E{score ≥ 60?}
    E -->|Yes| F[dump_class<br/>提取字节码]
    F --> G[ast_java 分析]
    E -->|No| H[正常]
    G --> I[Evidence 汇总]
```

打分规则：
- +30 非标准 ClassLoader
- +40 类文件磁盘不存在
- +20 包名不在白名单
- +10 随机类名（熵 > 3.5）
- +30 方法体含 Runtime/ProcessBuilder
- -20 已知框架类（Spring Security, Shiro）

### M4 生产化部署（规划）

```mermaid
graph TB
    subgraph K8s["Kubernetes 集群"]
        API[API Server<br/>FastAPI + Uvicorn]
        Worker[Worker<br/>LangGraph 扫描]
        Probe[主机探针<br/>DaemonSet]
        Sandbox[沙箱<br/>gVisor 隔离]
    end

    subgraph Storage["存储层"]
        PG[(PostgreSQL<br/>6 张核心表)]
        Redis[(Redis<br/>任务队列 + 缓存)]
    end

    subgraph Monitor["监控"]
        Prom[Prometheus]
        Grafana[Grafana<br/>3 个 Dashboard]
        LS[LangSmith<br/>Trace]
    end

    API --> Redis --> Worker
    Worker --> PG
    Worker --> Sandbox
    Probe -->|inotify| API
    Worker --> Prom --> Grafana
    Worker --> LS
```

## 告警输出格式

ECS（Elastic Common Schema）兼容：

```json
{
  "@timestamp": "2025-01-15T10:30:00Z",
  "event": {
    "kind": "alert",
    "category": "malware",
    "severity": 90
  },
  "file": {
    "path": "/var/www/html/shell.jsp",
    "hash": {
      "sha256": "a1b2c3...",
      "md5": "d4e5f6..."
    },
    "size": 1234
  },
  "threat": {
    "technique": {
      "id": "T1505.003",
      "name": "Web Shell"
    }
  },
  "wsa": {
    "verdict": "malicious",
    "confidence": 0.95,
    "tech_stack": "jsp",
    "evidence_count": 3,
    "explanation": "[regex/jsp_runtime_exec] score=0.95; [yara/jsp_runtime_exec] score=0.90; [ast/ast.taint_exec] score=0.90"
  }
}
```

## 扩展规则

### 添加 Regex 规则

在 `rules/regex/` 下创建 YAML 文件：

```yaml
rules:
  - id: my_custom_rule
    stack: jsp          # jsp / java_class / php / script / any
    description: "描述"
    pattern: 'your_regex_pattern'
    severity: critical  # critical / high / medium / low
    confidence: 0.90    # 0.0 ~ 1.0
    tags: [webshell, rce]
```

### 添加 YARA 规则

在 `rules/yara/<stack>/` 下创建 `.yar` 文件：

```yara
rule my_custom_rule {
    meta:
        author = "your_name"
        description = "描述"
        confidence = "0.85"
        severity = "high"
        tags = "webshell,rce"
    strings:
        $s1 = "pattern1" ascii
        $s2 = "pattern2" ascii
    condition:
        $s1 and $s2
}
```

## License

MIT
