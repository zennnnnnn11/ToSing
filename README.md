<p align="center">
  <img src="assets/logo.png" width="80" height="80" alt="ToSing" />
</p>

<h1 align="center">ToSing</h1>

<p align="center">
  <strong>Universal Ingestion. Strict Alignment. Native Speed.</strong><br/>
  面向下一代 <code>sing-box</code> 内核的高性能无状态通用订阅聚合器与规范化编译器。
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-11.0_Preview-0F172A?style=flat-square" alt=".NET 11" />
  <img src="https://img.shields.io/badge/C%23-15.0-0F172A?style=flat-square" alt="C# 15" />
  <img src="https://img.shields.io/badge/Binary-Native_AOT-0F172A?style=flat-square" alt="Native AOT" />
  <img src="https://img.shields.io/badge/GUI-Avalonia_12-0F172A?style=flat-square" alt="Avalonia 12" />
  <img src="https://img.shields.io/badge/sing--box-1.11%2B-0F172A?style=flat-square" alt="sing-box 1.11+" />
  <img src="https://img.shields.io/badge/Pass_Rate-99.996%25-0F172A?style=flat-square" alt="99.996% Pass" />
</p>

<p align="center">
  <a href="#english">English</a> &nbsp;|&nbsp; <a href="#中文">简体中文</a>
</p>

---

<div id="english"></div>

## English

### Pipeline

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#FFFFFF', 'edgeLabelBackground':'#FFFFFF', 'tertiaryColor': '#F8FAFC'}}}%%
flowchart LR
    classDef input fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#3F3F46,rx:6,ry:6
    classDef core fill:#FFFFFF,stroke:#18181B,stroke-width:2px,color:#18181B,rx:8,ry:8
    classDef step fill:#F4F4F5,stroke:#E4E4E7,stroke-width:1px,color:#27272A,rx:4,ry:4
    classDef output fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#18181B,rx:6,ry:6

    subgraph Inputs [" Ingestion "]
        direction TB
        I1["Remote Subscriptions (HTTP/S)"]
        I2["Clash / Meta (YAML / JSON)"]
        I3["Protocol URIs (8 Protocols / AnyTLS)"]
        I4["Base64 Cipher Blobs"]
        I5["WireGuard (.conf / Multi-Peer)"]
    end

    subgraph Engine [" ToSing Core "]
        direction TB
        E1["Token Scanner & AST Probe"]
        E2["Topology & Stale Node Sanitizer"]
        E3["Contract Validator (FrozenDict)"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" Egress "]
        direction TB
        O1["sing-box 1.11+ Outbounds"]
        O2["Top-Level Endpoints"]
        O3["Pure Canonical JSON"]
    end

    Inputs --> Engine
    Engine --> Outputs

    class I1,I2,I3,I4,I5 input
    class Engine core
    class E1,E2,E3 step
    class O1,O2,O3 output
```

### Architecture
- **Stateless Pipeline**: Zero runtime database or state leakage. Operates purely in-memory as an idempotent sanitizer and normalizer.
- **Dialect Deconstruction**: Normalizes heterogeneous and malformed URIs/YAML into dialect-agnostic syntax trees, mapping directly to sing-box schema definitions.
- **O(1) Contract Verification**: Uses schemas pre-indexed with `FrozenDictionary` to validate fields, Curve25519 keys, and CIDRs with zero heap linear scans.

### Tech Stack
| Component | Technology | Detail |
| :--- | :--- | :--- |
| **Runtime** | C# 15 / .NET 11 Preview | High-performance, zero-allocation memory layout |
| **Binary** | Native AOT | Single-file standalone executable (~10.6MB CLI, zero runtime dependencies) |
| **Desktop UI** | Avalonia 12.1.2 | Windows 11 Fluent Mica workbench with asynchronous background compute |
| **Data Engine** | Source-Gen `System.Text.Json` | Reflection-free, trim-safe JSON serialization |

### Empirical Validation
Tested against a stress-test corpus of **301,513 real-world network records** across 36 heterogeneous providers:
- **Parsed Outbounds**: `245,717`
- **Official Kernel Validation**: `245,708`
- **Contract Alignment Rate**: **`99.996%`**

### Upstream Commitment
Engineered strictly against the **`sing-box 1.11+` specification** (including top-level `endpoints` architecture and IPv4/IPv6 dual-stack CIDR normalization). Maintained and synchronized with upcoming upstream releases.

---

<div id="中文"></div>

## 中文

### 处理管线

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#FFFFFF', 'edgeLabelBackground':'#FFFFFF', 'tertiaryColor': '#F8FAFC'}}}%%
flowchart LR
    classDef input fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#3F3F46,rx:6,ry:6
    classDef core fill:#FFFFFF,stroke:#18181B,stroke-width:2px,color:#18181B,rx:8,ry:8
    classDef step fill:#F4F4F5,stroke:#E4E4E7,stroke-width:1px,color:#27272A,rx:4,ry:4
    classDef output fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#18181B,rx:6,ry:6

    subgraph Inputs [" 多态输入源 "]
        direction TB
        I1["远程订阅链接 (HTTP/HTTPS)"]
        I2["Clash / Meta (YAML / JSON)"]
        I3["节点协议 URI (8大协议/AnyTLS)"]
        I4["Base64 订阅密文块"]
        I5["WireGuard (.conf / 多 Peer)"]
    end

    subgraph Engine [" ToSing 核心 "]
        direction TB
        E1["词法扫描与语法树解构"]
        E2["广告与失效节点拓扑清洗"]
        E3["FrozenDict 契约静态校验"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" 标准化输出 "]
        direction TB
        O1["sing-box 1.11+ 标准出站"]
        O2["顶层 Endpoints 规范"]
        O3["规范化 JSON / 极速导出"]
    end

    Inputs --> Engine
    Engine --> Outputs

    class I1,I2,I3,I4,I5 input
    class Engine core
    class E1,E2,E3 step
    class O1,O2,O3 output
```

### 核心原理
- **无状态管道**：全内存运行，零状态残留，纯粹执行幂等数据清洗与拓扑规范化。
- **方言中立语法树**：不论源数据格式差异与畸变，统一解构为协议 AST 并映射至标准数据结构。
- **O(1) 契约静态校验**：通过 `FrozenDictionary` 索引官方 Schema，在纳秒级完成密钥合法性、CIDR 掩码及传输协议判别。

### 技术栈
| 模块 | 核心技术 | 说明 |
| :--- | :--- | :--- |
| **语言与运行时** | C# 15 / .NET 11 Preview | 前沿内存控制与现代语言特性 |
| **机器码交付** | Native AOT | 单文件原生执行档 (~10.6MB CLI，脱机免运行库，毫秒级启动) |
| **桌面工作台** | Avalonia 12.1.2 | Windows 11 Fluent Mica 沉浸卡片、全异步后台与 64KB 极速视口 |
| **序列化** | 源码生成 `System.Text.Json` | 彻底移除反射，全面保障 Native AOT 剪裁安全 |

### 海量实战压测
使用来自 36 个异构数据源的真实节点全景库（含复杂 Clash Meta、Base64 订阅池及多 Peer WireGuard）进行极限回放：
- **实测样本总量**：`301,513`
- **成功解析提取**：`245,717`
- **官方 sing-box 内核校验通过**：`245,708`
- **契约对齐率**：**`99.996%`**

### 上游对齐承诺
严格对齐 **`sing-box 1.11+` 最新规范**（支持顶层 `endpoints` 解构、IPv4/IPv6 双栈规范化与 AnyTLS），并持续跟进官方内核演进。
