# 🛡️ MoonShield (月盾)

> **MoonBit 国产基础软件生态开源大赛 (OSC 2026) / 黑客松参赛项目**  
> 纯 MoonBit 原生开发的高性能、零依赖云原生 Web 应用防火墙 (WAF) 与 AI Agent 实时安全防护护栏 (Security Guardrail)。

---

## 📌 项目背景与解决痛点

随着国产基础软件生态（信创）与 WebAssembly (Wasm) 在云原生网关、边缘计算以及 AI Agent 领域的快速演进，嵌入式应用面临着两类严峻的安全威胁：

1. **传统 Web 渗透与 WAF 混淆绕过**：
   - 现有的 WAF 大多依赖庞大的 C/C++ 动态库或重量级 Python/Go 运行时，难以轻量化嵌入到 WebAssembly 边缘沙箱中。
   - 攻击者常利用 URL 百分号二次编码、大小写交织（如 `uNiOn+sElEcT`）以及十六进制变形绕过常规关键词拦截。
2. **AI Agent 时代的新型注入与越权提权**：
   - 大模型在与外界环境交互调用系统工具（Tool Calls）时，极易受到 **Prompt Injection（提示词注入）**、**Jailbreak（越狱夺权）** 与 **Unsafe System Call（越权调用高危指令）** 的恶意劫持，导致企业敏感数据泄露或底层主机被攻陷。

**MoonShield (月盾)** 应运而生。结合网络安全/网警实战防御体系，利用 MoonBit 语言**极小的编译体积（KB 级 Wasm）、极高的执行效率、严格的类型安全与代数数据类型模式匹配**，构建了一套兼具传统 Web 威胁阻断与 AI 智能体动态安全护栏的现代化云原生防御引擎。

---

## ✨ 核心特性

- 🚀 **100% 纯 MoonBit 原生实现 (Zero External Dependencies)**：
  - 核心编解码、模式匹配与评分判定完全自主可控，无需任何第三方外部 C/JS 动态库，天然免疫供应链依赖漏洞。
- 🛡️ **双引擎立体纵深防御 (Dual-Engine Protection)**：
  - **Web WAF 模块**：精准覆盖 SQL 注入（永真式、联合查询、破坏性语句）、XSS 跨站脚本、命令注入、目录遍历以及云原生 SSRF（云元数据探测、内网回环探测）。
  - **AI Agent Guardrail 模块**：深度阻断 Prompt Injection 提示词覆写、DAN 越狱夺权、敏感 API 密钥诱导提取与非授权高危工具调用（如 `system.execute` / `file.delete`）。
- ⚡ **深度 Payload 规范化与混淆规整 (Normalization)**：
  - 内置 URL Percent-Encoding 状态机解码器与大小写统一归一化处理器，在特征匹配前彻底展开混淆载荷，精准化解攻击者的各类 WAF Evasion 绕过手段。
- 📊 **动态风险评分与可配置阈值阻断 (Dynamic Risk Scoring)**：
  - 区别于单一规则一票否决，MoonShield 采用规则多维累加评分机制（涵盖 Low, Medium, High, Critical 四级严重度），支持毫秒级综合研判并执行自动化脱敏与阻断。
- 🌐 **天然全栈多目标适配 (Native & Wasm)**：
  - 支持编译为本地原生二进制或体积轻巧的 WebAssembly 模块，可无缝内嵌至 Nginx/Envoy 边缘网关、Node.js 服务端以及浏览器前端沙箱中。

---

## 🏗️ 系统架构图

```
+-------------------------------------------------------------------------+
|                           Incoming Request                              |
|       (HTTP Method, URI, Body / AI User Prompt / Tool Call JSON)        |
+-------------------------------------------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |     Payload Normalizer & Decoder      |
                 | (URL Hex Percent-Decode, Lowercase)   |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |       MoonShield Rule Evaluator       |
                 |  ┌─────────────────┬────────────────┐ |
                 |  │   Web WAF Rules │  AI Guardrail  │ |
                 |  │ (SQLi/XSS/SSRF) │ (Prompt/Tools) │ |
                 |  └─────────────────┴────────────────┘ |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |    Risk Score Accumulator & Policy    |
                 +---------------------------------------+
                    /                                 \
                   /                                   \
                  v                                     v
         [Total Risk >= Threshold]             [Total Risk < Threshold]
        ❌ Action: BLOCK & SANITIZE            ✅ Action: ALLOW & PASS
```

---

## 🧪 边做边验与测试验证 (Test Coverage)

项目遵循严谨的工程化标准与测试驱动开发流程，内置覆盖各类攻击向量与正常业务流量的全量测试用例：

```bash
# 运行全部单元测试
moon test
```

### 当前测试覆盖范围 (10/10 全部通过)：
- [x] URL Percent 深度解码验证（SQLi 与 XSS 载荷）
- [x] 大小写混淆与 WAF 绕过归一化校验
- [x] SQL 注入攻击检测与阻断阈值评估
- [x] XSS 跨站脚本载荷拦截
- [x] 命令注入与敏感文件路径遍历探测
- [x] SSRF 云元数据（169.254.169.254）与内网探测拦截
- [x] AI Agent 提示词注入与越狱对抗拦截
- [x] AI Agent 高危工具调用审计
- [x] 正常合法业务流量零误报放行 (Zero False-Positive)
- [x] 运行时自定义安全规则动态扩展

---

## 🚀 快速上手与使用

### 1. 运行交互式命令行 DEMO
```bash
moon run cmd/main
```
输出将直观呈现对恶意 SQL 注入流量、AI 提示词攻击以及正常业务请求的即时研判与阻断过程。

### 2. 编译为 WebAssembly 目标
```bash
moon build --target wasm
```

---

## 📜 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 开源许可证。
严格遵守 MoonBit OSC 2026 大赛规范。