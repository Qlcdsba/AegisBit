```text
     _                    _       ____  _ _   
    / \   ___  __ _  ___ (_)___  | __ )(_) |_ 
   / _ \ / _ \/ _` |/ _ \| / __| |  _ \| | __|
  / ___ \  __/ (_| |  __/| \__ \ | |_) | | |_ 
 /_/   \_\___|\__, |\___|/ |___/ |____/|_|\__|
              |___/    |__/                   
      -= ☾ A E G I S B I T · 神 盾 比 特 ☽ =-
    « Wasm-Native Attack Filter & AI Agent Security Guard »
```

<div align="center">

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-8A2BE2?style=for-the-badge&logo=webassembly)](https://www.moonbitlang.com)
[![Mooncakes](https://img.shields.io/badge/Mooncakes-Qlcdsba%2Faegisbit-blue?style=for-the-badge&logo=package)](https://github.com/Qlcdsba/AegisBit)
[![CI](https://img.shields.io/github/actions/workflow/status/Qlcdsba/AegisBit/ci.yml?branch=main&style=for-the-badge&label=Build%20%26%20Test&logo=githubactions)](https://github.com/Qlcdsba/AegisBit/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)
[![Target](https://img.shields.io/badge/Target-Wasm%20%7C%20Native-orange?style=for-the-badge)](https://www.moonbitlang.com)

**MoonBit 国产基础软件生态开源大赛 (OSC 2026) 参赛作品**  
*探索基于纯 MoonBit 实现的零依赖、Wasm 原生高吞吐安全规则检测与 AI Agent 提示词护栏引擎*

</div>

---

## 📜 项目历史演进与更名说明 (Project Lineage & Renaming)

为了保证开源项目历史演进的完整性与透明度，特此说明本项目的演进轨迹：

- **早期代号**：本项目在立项构思与初始原型开发阶段，曾使用测试代号 `MoonShield`（月盾）。
- **正式升格与重命名**：在完成初版核心算法与解码器验证后，为了更好凸显网络安全攻防中的主动防御理念与希腊神话至高神盾（Aegis）的硬核质感，项目于 2026 年 9 月正式更名为 **`AegisBit` (神盾比特)**，并将 GitHub 远端仓库与 MoonBit 模块包名统一迁移至 `Qlcdsba/aegisbit`。
- **功能继承与重大升级**：`AegisBit` 全面继承并大幅升级了前期的防护模型，代码规模由原型的 700 余行扩充至近 4000 行纯 MoonBit 源码，实现了 **Aho-Corasick 多模式匹配自动机**、**全套 HTTP/1.1 协议深度解析器**、**多阶段反绕过归一化解码器**、**企业级 SIEM JSON/CEF 审计导出**与**滑动窗口防爆破限流器**。

---

## 📌 项目定位与边界说明 (Scope & Limitations)

### 1. 项目定位
本项目为一个**实验性安全规则检测原型与轻量级护栏 (Experimental Security Rule Detector & AI Guardrail Prototype)**。核心目的在于探索利用国产编程语言 [MoonBit](https://www.moonbitlang.com) 的状态机模式匹配、无 GC / 轻量 GC 特性与 WebAssembly (Wasm) 沙箱能力，在边缘网关或 AI Agent 工具链中提供低开销、零外部依赖的威胁防御能力。

### 2. 原型已具备的能力
- **多层深度归一化引擎 (`decoder.mbt`)**：递归 URL Percent 解码（防双重/多重编码绕过）、IIS `%u` 编码解码、`\xHH` 十六进制转义与 `\uHHHH` Unicode 转义解码、HTML 十进制/命名实体转换、全角 Unicode 归一化、SQL 内联注释消除、空白折叠与 Base64 解码。
- **Aho-Corasick 多模式匹配自动机 (`ac.mbt`)**：构建 Trie 字典树与 BFS 失败指针（Failure Links），在 $O(N)$ 线性时间内并发检索数百条高危规则签名。
- **HTTP/1.1 协议深度解构 (`http.mbt`)**：线缆报文解析为请求行、URI、Path、查询参数对、请求头、Cookie 字典与 Body，并提供自动注入 OWASP 安全响应头（CSP、X-Frame-Options、HSTS）的 `HttpResponse` 构造器。
- **覆盖 OWASP Web + LLM 双十威胁库 (`rules.mbt`)**：内置精心校准的规则库，覆盖 SQL 注入、XSS、命令注入、路径遍历、SSRF、XXE、反序列化、WebShell、NoSQL 注入、SSTI 模板注入、原型链污染、ChatML/Llama 特殊标记注入、越狱提示词与密钥凭据泄露。
- **企业级 SIEM 审计与遥测 (`audit.mbt`)**：支持格式化输出结构化 JSON、CEF (Common Event Format)、Syslog (RFC 5424)、高吞吐流式 JSONL 以及 CSV 日志，并包含实时安全指标聚合器。
- **多维安全控制引擎 (`engine.mbt`)**：IP 黑白名单过滤、滑动窗口客户端频控限流（`RateLimiter`）与加权风险评分判定逻辑（支持 Allow / Monitor / Sanitize / Challenge / Block 多态裁决）。

### 3. 与生产级重型商业产品的客观差距
- **非语义级大模型推理**：当前针对 Prompt 注入与越狱采用特征模式与结构分析，并非基于数十亿参数深度学习模型的动态上下文语义嵌入。
- **非全功能代理服务器**：当前专注安全检测与报文 AST 校验，不包含完整的 TLS 握手解密、TCP 连接池管理等反向代理网络栈。
- **建议部署形态**：建议作为 Wasm 插件嵌入 Envoy / OpenResty / Nginx 边缘节点，或作为 Sidecar 运行在 AI Agent 框架的前置拦截管道中。

---

## 🤖 人机协作与 AI 辅助申报 (Human-AI Collaboration & Governance)

遵循开源大赛关于 AI 辅助编程规范与知识产权透明度要求，本项目在此清晰界定人机协作边界：

1. **人工核心决策点 (Human Architectural & Engineering Decisions)**：
   - **架构分层设计**：确立“报文解析 -> 归一化去混淆 -> AC 自动机并发匹配 -> 启发式加权裁决 -> SIEM 审计日志”的标准五层过滤流水线。
   - **反绕过攻防博弈**：根据实际攻防经验，设计递归 URL 解码、全角 ASCII 归一化及 SQL 注释剥离，有效封堵黑客常用的混淆绕过向量。
   - **严格阈值策略**：确立 50 分为基准阻断阈值，20 分为监控告警阈值，High/Critical 单条直接阻断，Low/Medium 关联累计阻断。
   - **测试覆盖设计**：亲自设计 45 组覆盖单双层编码、畸形边界、阈值临界点、NoSQL/SSTI、Agent 提示词与正常业务零误报的测试用例集。

2. **AI 工具辅助范畴 (AI Assistance Scope)**：
   - 辅助 MoonBit 语言新特有语法（`UInt16` 码点、`StringView`、`to_owned()`、Block Marker `///|`）的语法适配。
   - 辅助生成规则库初始 CWE 编号与规则元数据模板。
   - 辅助排版与检查 GitHub Actions CI 流水线 YAML 文件。

3. **人工验收确认 (Human Verification & Acceptance)**：
   - 全部代码由开发者在本地通过 `moon check`、`moon test`（45/45 通过）、`moon fmt --check`、`moon run cmd/main` 与 `moon build --target wasm`，并在 GitHub Actions 真实环境验证通过。

---

## 📦 Mooncakes 包注册表状态 (Package Registry)

- **模块包名 (Package Name)**: `Qlcdsba/aegisbit`
- **代码仓库 (Repository)**: [https://github.com/Qlcdsba/AegisBit](https://github.com/Qlcdsba/AegisBit)
- **当前发布状态**: 项目已在 `moon.mod` 中严格按照 Mooncakes 规范声明元数据，本地执行 `moon publish --dry-run` 格式与依赖验证通过。由于官方中心注册表索引审核排队，建议通过 Git 依赖方式直接引用：
  ```bash
  moon add Qlcdsba/aegisbit --git https://github.com/Qlcdsba/AegisBit.git
  ```

---

## 🛠️ 项目源码布局 (Source Layout)

本项目由近 4000 行纯 MoonBit 代码构成，无任何第三方包依赖：

| 文件 | 规模 (LOC) | 职责与工程意义 |
| :--- | :--- | :--- |
| `types.mbt` | ~250 行 | 定义核心数据结构：威胁级别、攻击分类（含 CWE 映射）、处置判定、检测规则、上下文与结果 |
| `decoder.mbt` | ~450 行 | 多阶段去混淆引擎：递归 URL 解码、IIS 编码、Hex/Unicode 转义、HTML 实体、SQL 注释剥离、Rot13、Base64 |
| `ac.mbt` | ~450 行 | 纯 MoonBit 实现的 Aho-Corasick 多模式匹配自动机（字典树 + BFS 失败跳转），支持 $O(N)$ 线性检索 |
| `http.mbt` | ~550 行 | HTTP/1.1 协议解析器、查询参数与 Cookie 提取器、多目标扁平化提取、防御性 `HttpResponse` 生成器 |
| `rules.mbt` | ~1200 行 | 工业级安全规则库：覆盖 OWASP Top 10 Web、NoSQL、SSTI、原型链污染及 LLM 提示词注入/越狱等威胁 |
| `audit.mbt` | ~350 行 | SIEM 审计与合规导出：结构化 JSON、CEF、Syslog RFC 5424、JSONL、CSV 格式化器与遥测指标收集器 |
| `engine.mbt` | ~450 行 | 核心检测引擎编排：规则加载与 AC 编译、IP 黑白名单过滤、滑动窗口防暴破限流器与综合评分裁决 |
| `aegisbit_test.mbt` | ~550 行 | 35 组集成验证测试：覆盖各类编码混淆、威胁类型拦截、阈值边界及正常流量防误报 |
| `aegisbit_wbtest.mbt` | ~120 行 | 10 组白盒单元测试：验证字典树节点演化、数学对称性、限流器时间窗口推进与内部数据结构 |
| `cmd/main/main.mbt` | ~200 行 | 交互式命令行演示程序：生动展示攻击拦截、双重编码防御、Agent 护栏、限流防护与实时 SIEM 日志 |

---

## 🧪 验证与测试 (Verification & Testing)

项目遵循“边做边验”的测试驱动开发规范，所有功能模块均具备 100% 确定性测试保障。

### 1. 运行全量单元测试
```bash
moon test
```
*输出：`Total tests: 45, passed: 45, failed: 0.`（包含 35 组集成黑盒测试与 10 组白盒单元测试）*

### 2. 运行代码格式检查
```bash
moon fmt --check
```

### 3. 运行静态诊断检查
```bash
moon check
```

### 4. 运行命令行演示 DEMO
```bash
moon run cmd/main
```

### 5. 编译为 WebAssembly 目标
```bash
moon build --target wasm
```

---

## 🔄 持续集成 (Continuous Integration)

仓库配置了真实的 GitHub Actions 自动化流水线 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，在每次代码推送到 `main` 分支或提交 Pull Request 时自动执行：
- 环境安装与版本信息检查 (`moon version --all`)
- 代码规范与格式验证 (`moon fmt --check`)
- 静态编译诊断与类型检查 (`moon check`)
- 45 项全量单元测试执行 (`moon test`)
- 编译构建 WebAssembly 产物 (`moon build --target wasm`)
- 执行命令行演示验证全流程 (`moon run cmd/main`)

---

## 📜 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 许可证开源。