<p align="center">
  <img src="assets/logo.png" width="88" height="88" alt="ToSing Logo" />
</p>

<h1 align="center">ToSing</h1>

<p align="center">
  <strong>Universal Ingestion. Absolute Normalization. Native Speed.</strong><br/>
  面向下一代 <code>sing-box</code> 内核的极速通用订阅聚合器与拓扑规范化编译器。
</p>

<p align="center">
  <a href="https://dotnet.microsoft.com/"><img src="https://img.shields.io/badge/.NET-11.0_Preview-512BD4?style=flat-square&logo=dotnet&logoColor=white" alt=".NET 11" /></a>
  <a href="https://learn.microsoft.com/dotnet/csharp/"><img src="https://img.shields.io/badge/C%23-15.0-239120?style=flat-square&logo=csharp&logoColor=white" alt="C# 15" /></a>
  <a href="https://learn.microsoft.com/dotnet/core/deploying/native-aot/"><img src="https://img.shields.io/badge/Runtime-Native_AOT-007ACC?style=flat-square" alt="Native AOT" /></a>
  <a href="https://avaloniaui.net/"><img src="https://img.shields.io/badge/GUI-Avalonia_12-8A2BE2?style=flat-square" alt="Avalonia 12" /></a>
  <a href="https://sing-box.sagernet.org/"><img src="https://img.shields.io/badge/sing--box-1.11%2B_Endpoints-E11D48?style=flat-square" alt="sing-box 1.11+" /></a>
  <img src="https://img.shields.io/badge/Replay_Pass_Rate-99.996%25-10B981?style=flat-square" alt="99.996% Pass" />
</p>

<p align="center">
  <a href="#english">English</a> &nbsp;•&nbsp; <a href="#中文">简体中文</a>
</p>

---

<div id="english"></div>

## 🌐 English

### Black-Box Pipeline

```mermaid
flowchart LR
    classDef input fill:#1E293B,stroke:#475569,stroke-width:1px,color:#F8FAFC,rx:5,ry:5
    classDef core fill:#0F172A,stroke:#EF4444,stroke-width:2px,color:#FFFFFF,rx:6,ry:6
    classDef output fill:#1E293B,stroke:#10B981,stroke-width:1px,color:#F8FAFC,rx:5,ry:5

    subgraph Inputs [" 📥 Ingestion Layer "]
        direction TB
        I1["🌐 Remote URL (HTTP/HTTPS)"]
        I2["📦 Clash / Meta (YAML / JSON)"]
        I3["🔗 URIs (8 Protocols / AnyTLS)"]
        I4["🔒 Base64 Cipher Blobs"]
        I5["🛡️ WireGuard (.conf / Multi-Peer)"]
    end

    subgraph Engine [" ⚡ ToSing Black-Box Core "]
        direction TB
        E1["Token Scanner & AST Probe"]
        E2["Ad & Stale Node Sanitizer"]
        E3["Contract Validator (FrozenDict)"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" 📤 Canonical Egress "]
        direction TB
        O1["🚀 Outbounds Array"]
        O2["🛡️ Top-Level Endpoints"]
        O3["📋 Standalone JSON / GUI"]
    end

    Inputs ==> Engine
    Engine ==> Outputs

    class I1,I2,I3,I4,I5 input
    class E1,E2,E3 core
    class O1,O2,O3 output
```

### Architecture & Principles
- **Stateless Pipeline**: Zero runtime database or state leakage. Operates purely in-memory as an idempotent sanitizer and schema normalizer.
- **AST Dialer & Schema Alignment**: Ingests unstructured inputs, decomposes URIs/YAML into dialect-agnostic syntax trees, and maps directly onto sing-box contract definitions.
- **O(1) Contract Verification**: Employs static schemas indexed with `FrozenDictionary` to validate fields, Curve25519 keys, CIDRs, and transport protocols with zero heap-allocated linear scans.

### Tech Stack
| Component | Technology | Role |
| :--- | :--- | :--- |
| **Language & Platform** | C# 15 / .NET 11 Preview | High-performance, memory-safe execution |
| **Compiler & Binary** | Native AOT | Standalone, self-contained single-file executable (~26MB, zero runtime dependencies) |
| **Desktop Workbench** | Avalonia 12.1.2 | Windows 11 Fluent Mica desktop UI with background parallel tasks |
| **Data Engine** | Source-Gen `System.Text.Json` | Zero-reflection serialization fully compatible with AOT trimming |

### Empirical Validation
Stress-tested against **301,513 real-world network records** across 36 heterogeneous sources (Clash Meta, v2ray, Base64 pools, and multi-peer WireGuard configs):
- **Parsed**: `245,717` valid outbounds extracted
- **Official Kernel Verification**: `245,708` passed strict official sing-box check
- **Alignment Pass Rate**: **`99.996%`**

### Upstream Alignment Guarantee
Built strictly to match the latest **`sing-box 1.11+` specification** (including top-level `endpoints`, IPv4/IPv6 dual-stack CIDR masks, and AnyTLS). Continuously synchronized with upstream kernel releases.

---

<div id="中文"></div>

## 🇨🇳 中文

### 黑盒流转图

```mermaid
flowchart LR
    classDef input fill:#1E293B,stroke:#475569,stroke-width:1px,color:#F8FAFC,rx:5,ry:5
    classDef core fill:#0F172A,stroke:#EF4444,stroke-width:2px,color:#FFFFFF,rx:6,ry:6
    classDef output fill:#1E293B,stroke:#10B981,stroke-width:1px,color:#F8FAFC,rx:5,ry:5

    subgraph Inputs [" 📥 多态输入源 "]
        direction TB
        I1["🌐 远程订阅链接 (HTTP/HTTPS)"]
        I2["📦 Clash / Meta (YAML / JSON)"]
        I3["🔗 节点协议 URI (8大协议/AnyTLS)"]
        I4["🔒 Base64 订阅密文块"]
        I5["🛡️ WireGuard (.conf / 多 Peer)"]
    end

    subgraph Engine [" ⚡ ToSing 黑盒内核 "]
        direction TB
        E1["词法扫描与语法树解构"]
        E2["广告与失效节点拓扑清洗"]
        E3["FrozenDict 契约静态校验"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" 📤 标准化输出 "]
        direction TB
        O1["🚀 标准 Outbounds 数组"]
        O2["🛡️ 顶层 Endpoints 架构"]
        O3["📋 独立 JSON / 极速工作台"]
    end

    Inputs ==> Engine
    Engine ==> Outputs

    class I1,I2,I3,I4,I5 input
    class E1,E2,E3 core
    class O1,O2,O3 output
```

### 原理与设计
- **纯粹无状态管道**：无本地数据库与网络状态依赖，全内存执行幂等清洗与语义规范化。
- **语法树与方言中立**：无论来源是混乱的 Base64、非标 Clash 字段还是 URI 参数，均下沉为协议 AST 并重构映射至规范模型。
- **O(1) 契约极速校验**：利用 `FrozenDictionary` 预热官方 Schema，对 Curve25519 密钥、CIDR 掩码、传输层参数进行零分配静态判别。

### 技术栈
| 模块 | 核心技术 | 职责与特性 |
| :--- | :--- | :--- |
| **语言与运行时** | C# 15 / .NET 11 Preview | 前沿语法与极致内存控制 |
| **交付形态** | Native AOT 机器码编译 | 独立单文件可执行程序 (~26MB，无运行库依赖，毫秒级冷启动) |
| **桌面工作台** | Avalonia 12.1.2 | Windows 11 Fluent Mica 沉浸式 UI、后台并发执行与 64KB 极速视口 |
| **序列化引擎** | 源码生成 `System.Text.Json` | 彻底消除反射，100% 免疫 Native AOT 剪裁丢失 |

### 海量实战压测
在包含 36 个异构数据源的真实网络节点全景库（Clash Meta、v2ray Base64 订阅池、WireGuard 配置文件）中完成极限回放：
- **实测样本总量**：`301,513` 条记录
- **成功解析节点**：`245,717` 个
- **官方 sing-box 内核校验通过**：`245,708` 个
- **内核契约对齐率**：**`99.996%`**

### 内核对齐与维护承诺
完全对齐 **`sing-box 1.11+` 最新标准**（严格实现 WireGuard 顶层 `endpoints` 解构、IPv4/IPv6 双栈规范化与 AnyTLS），保持与官方内核规范的紧密同步与持续更新。
