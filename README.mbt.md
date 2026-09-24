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
[![Mooncakes](https://img.shields.io/badge/Mooncakes-Qlcdsba%2Faegisbit-blue?style=for-the-badge&logo=package)](https://mooncakes.io/docs/#/Qlcdsba/aegisbit)
[![CI](https://img.shields.io/github/actions/workflow/status/Qlcdsba/AegisBit/ci.yml?branch=main&style=for-the-badge&label=Build%20%26%20Test&logo=githubactions)](https://github.com/Qlcdsba/AegisBit/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)
[![Target](https://img.shields.io/badge/Target-Wasm%20%7C%20Native-orange?style=for-the-badge)](https://www.moonbitlang.com)

**MoonBit 国产基础软件生态开源大赛 (OSC 2026) 参赛作品**  
*探索基于 WebAssembly 边缘沙箱与 AI 智能体调用的轻量级攻防过滤原型*

</div>

---

## 📜 项目历史演进与更名说明 (Project Lineage & Renaming)

为了保证开源项目历史演进的完整性与透明度，特此说明本项目的演进轨迹：

- **早期代号**：本项目在立项构思与初始原型开发阶段，曾使用测试代号 `MoonShield`（月盾）。
- **正式升格与重命名**：在完成初版核心算法与解码器验证后，为了更好凸显网络安全攻防中的主动防御理念与希腊神话至高神盾（Aegis）的硬核质感，项目于 2026 年 9 月正式更名为 **`AegisBit` (神盾比特)**，并将 GitHub 远端仓库与 MoonBit 模块包名统一迁移至 `Qlcdsba/aegisbit`。
- **功能继承与升级**：`AegisBit` 完全继承了前期的威胁检测模型，并在原有基础上实现了**防 WAF 绕过的递归多重解码（Recursive URL Decoding）**、**严格的 50 分基准阈值研判**与**真实的 GitHub Actions CI 自动化流水线**。

---

## 📌 项目定位与边界说明 (Scope & Limitations)

### 1. 项目定位
本项目为一个**实验性安全规则检测原型 (Experimental Security Rule Detector Prototype)**。核心目的在于探索利用国产编程语言 [MoonBit](https://www.moonbitlang.com) 的模式匹配与 WebAssembly (Wasm) 轻量化特性，在边缘或沙箱环境中实现基础的 Web 攻击特征识别与 AI Agent 提示词输入过滤。

### 2. 能力边界与非生产级声明
为确保工程诚实性与技术严谨性，特此明确本原型的能力边界：

- **当前原型已具备的能力**：
  - 基于状态机的**递归多重 URL Percent-Decoding 解码**，有效抵御双重编码绕过（如 `%2527` -> `'`）。
  - 大小写归一化清洗，化解简单的大小写交织混淆。
  - 基于特征子串的规则模式匹配（覆盖 SQLi、XSS、Path Traversal、SSRF 以及基础 Prompt 注入）。
  - 基于多维严重等级（Low, Medium, High, Critical）的累加风险评分判定机制（基准阈值 50 分）。
  - 具备全量确定性单元测试（含双重编码、阈值临界点、畸形字符与正常流量安全样例）。
  - 具备跨平台 WebAssembly 编译验证能力。

- **与生产级工业 WAF / Guardrail 的差距（明确不具备的能力）**：
  - **无复杂 AST 语法树解析**：当前为特征模式匹配，不包含针对 SQL 或 JavaScript 的完整语法抽象解析器（AST Parser）。
  - **无深度语义大模型**：针对 Prompt 注入采用关键词规则拦截，非基于 Transformer 大模型的动态意图向量识别。
  - **无网络协议栈与流量控制**：不包含 TLS 解密、TCP 连接池管理、分布式限流或防 CC/DDoS 模块。
  - **仅供学习与原型验证**：不可直接作为高危商业生产环境的唯一安全边界。

---

## 🤖 人机协作与 AI 辅助申报 (Human-AI Collaboration & Governance)

遵循开源大赛关于 AI 辅助编程规范与知识产权透明度要求，本项目在此清晰界定人机协作边界：

1. **人工核心决策点 (Human Architectural & Engineering Decisions)**：
   - **攻防模型制定**：确立结合网警网络安全实战的防护模型，重点防御常见 Web 渗透与 AI 智能体提权交互。
   - **反绕过设计决策**：设计并引入多层递归解码（Recursive Decoding）以对抗利用双重 URL 编码绕过 WAF 的攻击手法。
   - **阈值策略裁定**：确立 50 分为基准拦截阈值，High/Critical 严重级别单条即时阻断，Low/Medium 多条累计协同拦截。
   - **测试边界裁定**：设计覆盖单层/双重编码、阈值临界点（49分放行 vs 50分拦截）、畸形输入防崩溃以及正常业务请求零误报的安全样例集。
   - **仓库纯净度控制**：审查并彻底剔除默认模版生成的冗余 Agent 配置文件。

2. **AI 工具辅助范畴 (AI Assistance Scope)**：
   - 辅助 MoonBit 语言特有语法（如 `UInt16` 码点转换、`StringBuilder`、Block 结构）的参考与调用适配。
   - 辅助生成重复性的单元测试用例脚手架代码。
   - 辅助排版与校对 GitHub Actions CI 工作流 YAML 文件。

3. **人工验收确认 (Human Verification & Acceptance)**：
   - 全部代码由开发者在本地经过多轮 `moon check`、`moon test`、`moon fmt --check` 与 GitHub Actions CI 真实环境联调，确认 100% 绿色通过后合入。

---

## 📦 Mooncakes 包注册表状态 (Package Registry)

- **包名 (Package Name)**: `Qlcdsba/aegisbit`
- **在线文档与索引 (Docs & Registry)**: [https://mooncakes.io/docs/#/Qlcdsba/aegisbit](https://mooncakes.io/docs/#/Qlcdsba/aegisbit)
- **本地依赖引用 (MoonBit Dependency)**:
  在 `moon.mod` 中声明或使用 CLI 引入：
  ```bash
  moon add Qlcdsba/aegisbit
  ```

---

## 🛠️ 模块架构

```
+-------------------------------------------------------------------+
|                        输入数据 Payload                           |
|       (HTTP Method, URI, Body / AI User Prompt / Tool Call)       |
+-------------------------------------------------------------------+
                                  |
                                  v
                +-----------------------------------+
                |  Recursive Payload Normalizer     |
                | (Multi-layer URL-Decode, Lower)   |
                +-----------------------------------+
                                  |
                                  v
                +-----------------------------------+
                |      AegisBit Rule Evaluator      |
                |   - Web 基础规则 (SQLi/XSS/SSRF)  |
                |   - AI 护栏规则 (Prompt/ToolCall) |
                +-----------------------------------+
                                  |
                                  v
                +-----------------------------------+
                |   Risk Accumulator & Threshold    |
                +-----------------------------------+
                   /                             \
                  /                               \
                 v                                 v
        [Risk >= Threshold]               [Risk < Threshold]
      ❌ Action: BLOCKED                  ✅ Action: ALLOWED
```

---

## 🧪 验证与测试 (Verification & Testing)

项目坚持“边做边验”的测试驱动开发流程，所有核心模块均配有确定性单元测试。

### 1. 运行本地单元测试
```bash
moon test
```
*当前包含 13 组独立测试用例，覆盖单层/双重编码边界、畸形字符容错、阈值临界点、攻击载荷及正常业务请求。*

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

仓库配置了真实的 GitHub Actions 自动化工作流 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，在每次代码推送到 `main` 分支或提交 Pull Request 时自动执行：
- 环境安装与版本检查 (`moon version --all`)
- 代码格式验证 (`moon fmt --check`)
- 静态编译诊断 (`moon check`)
- 全量单元测试 (`moon test`)
- WebAssembly 目标编译构建 (`moon build --target wasm`)

---

## 📜 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 许可证开源。