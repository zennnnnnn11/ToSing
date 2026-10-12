<p align="center">
  <img src="assets/logo.png" width="72" height="72" alt="ToSing" />
</p>

<h1 align="center">ToSing</h1>

<p align="center">
  sing-box 订阅解析与节点聚合工具
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-11.0-0F172A?style=flat-square" alt=".NET 11" />
  <img src="https://img.shields.io/badge/C%23-15.0-0F172A?style=flat-square" alt="C# 15" />
  <img src="https://img.shields.io/badge/Native-AOT-0F172A?style=flat-square" alt="Native AOT" />
  <img src="https://img.shields.io/badge/Avalonia-12-0F172A?style=flat-square" alt="Avalonia 12" />
  <img src="https://img.shields.io/badge/sing--box-1.11%2B-0F172A?style=flat-square" alt="sing-box 1.11+" />
  <img src="https://img.shields.io/badge/Pass_Rate-99.996%25-0F172A?style=flat-square" alt="99.996% Pass" />
</p>

<p align="center">
  <a href="#中文">中文</a> &nbsp;|&nbsp; <a href="#english">English</a>
</p>

---

<div id="中文"></div>

## 中文

### 架构

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#FFFFFF', 'edgeLabelBackground':'#FFFFFF', 'tertiaryColor': '#F8FAFC'}}}%%
flowchart LR
    classDef input fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#3F3F46,rx:4,ry:4
    classDef core fill:#FFFFFF,stroke:#18181B,stroke-width:1.5px,color:#18181B,rx:6,ry:6
    classDef step fill:#F4F4F5,stroke:#E4E4E7,stroke-width:1px,color:#27272A,rx:4,ry:4
    classDef output fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#18181B,rx:4,ry:4

    subgraph Inputs [" 输入 "]
        direction TB
        I1["订阅链接 (HTTP/S)"]
        I2["Clash (YAML / JSON)"]
        I3["节点链接 (8 种协议 / AnyTLS)"]
        I4["Base64 密文"]
        I5["WireGuard (.conf)"]
    end

    subgraph Engine [" ToSing "]
        direction TB
        E1["词法解析与 AST 重构"]
        E2["广告与失效节点清洗"]
        E3["FrozenDict 契约校验"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" 输出 "]
        direction TB
        O1["sing-box 1.11+ 出站"]
        O2["顶层 Endpoints"]
        O3["标准 JSON / 文件导出"]
    end

    Inputs --> Engine
    Engine --> Outputs

    class I1,I2,I3,I4,I5 input
    class Engine core
    class E1,E2,E3 step
    class O1,O2,O3 output
```

### 原理
- **无状态**：全内存处理，无本地数据库与网络状态依赖。
- **AST 解构**：统一将各类格式映射为标准协议模型。
- **O(1) 校验**：基于 `FrozenDictionary` 索引官方 Schema 验证字段。

### 技术栈
| 模块 | 技术 | 说明 |
| :--- | :--- | :--- |
| **运行时** | C# 15 / .NET 11 | 纯内存流处理 |
| **二进制** | Native AOT | 单文件可执行程序 (~10.6MB，无运行库依赖) |
| **界面** | Avalonia 12.1.2 | Windows 11 Fluent 桌面端 |
| **序列化** | `System.Text.Json` | 源码生成模式（Source Generator） |

### 测试数据
基于 36 个异构数据源的回放验证：
- **测试样本**：`301,513`
- **解析成功**：`245,717`
- **sing-box 内核校验通过**：`245,708`
- **对齐通过率**：**`99.996%`**

### 内核对齐
严格对齐 **`sing-box 1.11+`**（含 WireGuard 顶层 `endpoints` 与双栈 CIDR），持续跟进官方内核更新。

---

<div id="english"></div>

## English

### Pipeline

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#FFFFFF', 'edgeLabelBackground':'#FFFFFF', 'tertiaryColor': '#F8FAFC'}}}%%
flowchart LR
    classDef input fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#3F3F46,rx:4,ry:4
    classDef core fill:#FFFFFF,stroke:#18181B,stroke-width:1.5px,color:#18181B,rx:6,ry:6
    classDef step fill:#F4F4F5,stroke:#E4E4E7,stroke-width:1px,color:#27272A,rx:4,ry:4
    classDef output fill:#FAFAFA,stroke:#E4E4E7,stroke-width:1px,color:#18181B,rx:4,ry:4

    subgraph Inputs [" Ingestion "]
        direction TB
        I1["Remote URLs (HTTP/S)"]
        I2["Clash (YAML / JSON)"]
        I3["Protocol URIs (8 Protocols / AnyTLS)"]
        I4["Base64 Blobs"]
        I5["WireGuard (.conf)"]
    end

    subgraph Engine [" ToSing "]
        direction TB
        E1["Lexer & AST Probe"]
        E2["Ad & Stale Node Sanitizer"]
        E3["FrozenDict Contract Validator"]
        E1 --> E2 --> E3
    end

    subgraph Outputs [" Egress "]
        direction TB
        O1["sing-box 1.11+ Outbounds"]
        O2["Top-Level Endpoints"]
        O3["Canonical JSON"]
    end

    Inputs --> Engine
    Engine --> Outputs

    class I1,I2,I3,I4,I5 input
    class Engine core
    class E1,E2,E3 step
    class O1,O2,O3 output
```

### Design
- **Stateless**: In-memory execution without external database or state leakage.
- **AST Mapping**: Deconstructs heterogeneous sources into uniform protocol models.
- **O(1) Validation**: `FrozenDictionary` indexed schemas for schema compliance checks.

### Tech Stack
| Component | Technology | Detail |
| :--- | :--- | :--- |
| **Runtime** | C# 15 / .NET 11 | In-memory stream processing |
| **Binary** | Native AOT | Single-file executable (~10.6MB, zero runtime dependencies) |
| **Desktop UI** | Avalonia 12.1.2 | Windows 11 Fluent desktop app |
| **Serialization** | `System.Text.Json` | Source generator mode |

### Test Corpus
Verified against a real-world corpus across 36 heterogeneous sources:
- **Total Records**: `301,513`
- **Parsed**: `245,717`
- **Kernel Verified**: `245,708`
- **Pass Rate**: **`99.996%`**

### Upstream
Built against **`sing-box 1.11+`** (including top-level `endpoints` & dual-stack CIDRs). Continuously synchronized with upstream releases.
