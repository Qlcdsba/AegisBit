```text
  __  __                       ____  _     _      _     _ 
 |  \/  | ___   ___  _ __     / ___|| |__ (_) ___| | __| |
 | |\/| |/ _ \ / _ \| '_ \ ___\___ \| '_ \| |/ _ \ |/ _` |
 | |  | | (_) | (_) | | | |_____|__) | | | | |  __/ | (_| |
 |_|  |_|\___/ \___/|_| |_|    |____/|_| |_|_|\___|_|\__,_|
       -= ☾ M O O N S H I E L D · 月 盾 守 望 ☽ =-
   « Wasm-Native Attack Filter & AI Agent Security Guard »
```

<div align="center">

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-8A2BE2?style=for-the-badge&logo=webassembly)](https://www.moonbitlang.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Qlcdsba/moonshield/ci.yml?branch=main&style=for-the-badge&label=Build%20%26%20Test&logo=githubactions)](https://github.com/Qlcdsba/moonshield/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)
[![Target](https://img.shields.io/badge/Target-Wasm%20%7C%20Native-orange?style=for-the-badge)](https://www.moonbitlang.com)

**MoonBit 国产基础软件生态开源大赛 (OSC 2026) 参赛作品**  
*探索基于 WebAssembly 边缘沙箱与 AI 智能体调用的轻量级攻防过滤原型*

</div>

---

## 📌 项目定位与边界说明 (Scope & Limitations)

### 1. 项目定位
本项目为一个**实验性安全规则检测原型 (Experimental Prototype)**。核心目的在于探索利用国产编程语言 [MoonBit](https://www.moonbitlang.com) 的模式匹配与 WebAssembly (Wasm) 轻量化特性，在边缘或沙箱环境中实现基础的 Web 攻击特征识别与 AI Agent 提示词输入过滤。

### 2. 能力边界与非生产级声明
为确保工程诚实性与技术严谨性，特此明确本原型的能力边界：

- **当前原型已具备的能力**：
  - 基于状态机的基础 URL Percent-Decoding 解码与多重编码还原。
  - 大小写归一化清洗，用于化解简单的 WAF 字符混淆。
  - 基于字符串与规则特征的轻量模式匹配（覆盖 SQLi、XSS、Path Traversal、SSRF 以及基础 Prompt 注入）。
  - 基于多维严重等级（Low, Medium, High, Critical）的累加风险评分判定机制。
  - 具备全量单元测试与跨平台 WebAssembly 编译验证能力。

- **与生产级工业 WAF / Guardrail 的差距（明确不具备的能力）**：
  - **无复杂 AST 语法树解析**：当前为特征模式匹配，不包含针对 SQL 或 JavaScript 的完整词法语法解析器（AST Parser）。
  - **无深度上下文与语义模型**：针对 Prompt Injection 采用关键词规则拦截，非基于大语言模型或向量嵌入的动态语义意图识别。
  - **无网络协议栈与流量管理**：不包含 TLS 解密、TCP 连接池管理、分布式限流或防 CC/DDoS 模块。
  - **仅供学习与原型验证**：不可直接作为高危生产环境的唯一安全边界。

---

## 🤖 人机协作与 AI 辅助申报 (Human-AI Collaboration)

遵循开源大赛关于 AI 辅助编程规范与知识产权透明度要求，本项目在此清晰界定人机协作边界：

1. **开发者主导职责**：
   - 选题构思与网络安全专业背景对齐（聚焦 WebAssembly 边缘防护与 AI Agent 安全交互痛点）。
   - 系统整体架构设计（Decoder 归一化 -> Rule 匹配 -> 阈值研判 -> Action 处置）。
   - 规则库威胁模型制定与分值校准（SQLi, XSS, SSRF, Prompt Injection 等关键攻击载荷定义）。
   - 核心功能验收、回归测试设计、阈值判定校准与工程质量把控。

2. **AI 工具辅助范畴**：
   - 使用 AI 编码辅助工具进行 MoonBit 语言特有语法（如 `UInt16` 字符处理、Block 结构）的适配与参考。
   - 辅助生成重复性的单元测试用例脚手架与基础字符串匹配模板。
   - 辅助整理与格式化 Markdown 技术说明文档。
   - 移除了默认模版生成的冗余 Agent 配置文件，保证仓库依赖与工作流纯净。

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
                |       Payload Normalizer          |
                | (URL Percent-Decode, Lowercase)   |
                +-----------------------------------+
                                  |
                                  v
                +-----------------------------------+
                |     MoonShield Rule Evaluator     |
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

项目坚持“边做边验”的开发流程，所有核心模块均配有确定性单元测试。

### 1. 运行本地单元测试
```bash
moon test
```
*当前包含 10 组独立测试用例，覆盖编解码边界、各类攻击载荷及正常业务请求。*

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