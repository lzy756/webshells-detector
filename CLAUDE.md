# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language

Always respond in Chinese-simplified.And also generate contents with no whitespaces between Chinese Characters and non Chinese characters(don't write like"用当前文件夹下 uv 配置的虚拟环境", but write like "用当前文件夹下uv配置的虚拟环境")

## Environment

所有 Python 代码运行和测试均使用当前文件夹下 uv 配置的虚拟环境。命令前缀统一用 `uv run`。

## Common Commands

```bash
# 安装依赖（含 dev）
uv sync --all-extras

# 运行 CLI 扫描
uv run wsa scan <target>
uv run wsa scan <target> --no-llm        # 跳过 LLM
uv run wsa scan <target> --format json    # JSON 输出

# 测试
uv run pytest                             # 全量测试
uv run pytest tests/unit/test_gate.py     # 单个文件
uv run pytest tests/unit/test_gate.py::test_gate_high_yara  # 单个用例
uv run pytest -k "llm"                    # 按关键字筛选

# Lint & Type Check
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/
```

## Architecture

Static-first、LLM-assisted 的 webshell 检测系统。核心是一个 15 节点的 LangGraph 有向图。

### Pipeline Flow

```
START → ingest → classify ─┬─ php/jsp → deobfuscate → regex_scan → yara_scan → AST → stat_features ─┐
                            ├─ java_class → ast_java → stat_features ─────────────────────────────────┤
                            ├─ script → regex_scan → ...                                              │
                            └─ unknown → fast_fail → aggregate                                        │
                                                                                                      │
stat_features → confidence_gate ─┬─ conf ≥ 0.9 or ≤ 0.1 → aggregate (direct)                         │
                                 ├─ conf ≥ 0.7 + sandbox_enabled → sandbox → llm_judge → aggregate    │
                                 └─ conf ≥ 0.3 → llm_judge → aggregate                               │
                                                                                                      │
aggregate → emit → END
```

### Key Modules

- `src/wsa/graph.py` — LangGraph 图定义，`build_graph()` 构建完整 pipeline
- `src/wsa/state.py` — `ScanState`（TypedDict）和 `Evidence`（Pydantic model），所有节点通过 state 传递数据
- `src/wsa/config.py` — `Settings`（pydantic-settings），环境变量前缀 `WSA_`
- `src/wsa/llm_provider.py` — LLM 工厂函数，支持 anthropic/openai/local(Ollama)
- `src/wsa/nodes/gate.py` — 置信度计算 + 路由决策，权重：yara=1.0, regex=0.9, ast=1.0, stat=0.5, llm=0.8
- `src/wsa/nodes/llm_judge.py` — 结构化证据包输入，Pydantic schema 校验输出，支持重试/降级
- `src/wsa/nodes/sandbox.py` — Docker 容器行为分析，无 Docker 时降级
- `src/wsa/nodes/aggregate.py` — 静态+LLM+Sandbox 置信度融合，ECS 格式输出

### Detection Rules

- `rules/regex/` — YAML 格式正则规则（jsp_webshell.yaml, java_webshell.yaml）
- `rules/yara/` — YARA 规则按语言分子目录（jsp/, java/）
- `rules/java_lib_whitelist.yaml` — 良性 Java 库白名单

### Evidence Accumulation

`ScanState` 中的 `*_findings` 和 `evidences` 字段使用 `Annotated[list[dict], operator.add]`，LangGraph 自动合并各节点产出的证据列表。

### Confidence Gate Logic

`gate_decision()` 路由规则：
- `no_llm=True` → 强制 direct（跳过 LLM）
- conf ≥ gate_high(0.9) 或 ≤ gate_low(0.1) → direct
- conf ≥ 0.7 且 sandbox_enabled → sandbox
- conf ≥ 0.3 → llm
- 其余 → direct

## Conventions

- src layout：源码在 `src/wsa/`，测试在 `tests/unit/` 和 `tests/e2e/`
- 每个 LangGraph 节点是一个函数 `xxx_node(state: ScanState) -> dict`，返回要更新的 state 字段
- Ruff：line-length 120，select E/F/I/W
- 测试 fixtures 在 `tests/fixtures/`（malicious/, benign/, hard_negatives/）
- CLI exit codes：0=benign, 1=malicious, 2=suspicious, 3=error

## Stub Nodes

`ast_php` 目前是 stub（`_stub_node`），尚未实现。
