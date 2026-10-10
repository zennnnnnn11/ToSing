# sing-box 对齐检查

在仓库根目录运行一个命令：

```powershell
pwsh -NoProfile -File tools/check-singbox-alignment.ps1 -SingBoxSource 'C:\Users\zen\Downloads\nn\sing-box-testing'
```

参数指向 `go.mod` 所在的 sing-box 源码目录。也支持当前下载目录中多套一层 `sing-box-testing` 的结构。需要 PowerShell 7、项目所需的 .NET SDK、sing-box `go.mod` 要求的 Go 版本以及 `rg`。可通过 `-DotNet` 和 `-Go` 指定可执行文件路径；首次构建可能下载项目依赖。检查器使用提供源码的依赖版本，设置 `CGO_ENABLED=0`、`GOTOOLCHAIN=local`，不会修改内核源码。

每次检查都新建 `artifacts/alignment/run-时间-随机编号/`，保存完整的 `report.json`、源码 SHA256 清单、内核字段及源码行位置、转换前后的配置、逐用例结果和构建日志。编译失败、字段缺失、多出字段、契约过期、配置语义改变、非法输入被输出以及旧回归失败都会让命令返回非零退出码。

## 覆盖范围

当前覆盖 VMess、VLESS、Trojan、Shadowsocks、Hysteria2、TUIC、AnyTLS 七种出站，以及 Dialer、TLS/uTLS/Reality/ECH、多路复用/Brutal、UDP-over-TCP、五种 V2Ray transport、Realm/端口映射/HTTP client、域名解析选项，共 25 组类型。公共字段分别在各协议中验证，因而字段统计包含继承字段的重复覆盖。ECH 中被内核标为 `schema:"omit"` 的两个旧字段不作为必须支持的模型字段。

检查步骤：

1. 在指定 sing-box Go 模块内编译探针和内核，直接反射 `option` 类型，读取 Go 类型、JSON 名称、枚举及源码位置。
2. 核对 C# 模型字段和内嵌的 `Models/SingboxContract.json`。内嵌契约由该内核提取，用于解析后校验字段类型、枚举和数值范围，防止已知非法选项落入输出；它不是完整的内核运行时实现。
3. 逐字段调用项目真实的解析器，然后使用内核的 `UnmarshalContext` 和 `MarshalContext` 比较 Go 解码后的配置。布尔值覆盖 true/false，枚举来自 Go 标签，另测密码、网络列表、整数和字节数边界。
4. 对正常用例调用 `box.New` 并关闭实例，验证协议注册、引用和内核构造条件。负面用例同时要求解析器拒绝输入、内核拒绝原始配置；Go 标签声明的枚举也参与校验，因为部分内核构造器不检查其全部枚举值。
5. 使用构建出的 `sing-box check` 跑 CLI 回归，覆盖 URI、Base64、Clash YAML、HTTP 订阅输入及之前发现的缺陷。
6. 用自检确认检查器能发现未知字段及“JSON 有效但 TLS 丢失”的情况；结束时再核对源码指纹，拒绝源码在检查期间变化的结果。

`core_negative_cases` 是被内核或其声明枚举拒绝的用例；`core_constructor_cases` 是完成内核构造的正常用例；`schema_only` 逐项说明只做 Go 解码和值比较的原因。这些统计不可混称为已完成真实连接的节点数。

## 报告中的限制

Windows 上的 Linux socket 选项、需要另外构建的原生 TLS/HTTP 引擎，以及可能按参数分配巨大资源的整数边界，只核对字段与内核解码值。默认状态为 `passed_with_runtime_limits`，这些限制不会被写成失败或“全部运行时验证通过”。使用 `-RequireAllRuntime` 时，存在任意此类用例就返回非零退出码。

这份参考内核对 `HTTPClientOptions(version=1)` 的 JSON 回写有一个错误。检查器在双方都成功解码且 Go 结构完全相等时改用 `reflect.DeepEqual`，仍执行构造检查，并在逐用例结果记录 `core_marshal_error` 和比较方法。它不会把回写错误悄悄忽略。

内核的排除字段解码过程会经由 float64 处理数字，因此 `Int64.MaxValue` 会舍入成越界值。检查器测量此版本的实际行为；解析器相应拒绝这个边界。`MemoryBytes` 的数值分支读取 int64，再转换为 uint64；检查器也覆盖它接受负数的当前行为。字符串单位规则仍由内核探针验证，不自行假定单位名称。

这些检查验证已声明支持的配置转换和构造；不会连接远程代理进行 TLS/QUIC 握手，也不覆盖 sing-box 的其他出站、入站、路由、DNS 全套配置或所有字段组合。新增协议、内核字段变化或实际缺陷应补充相应用例。有限测试通过不能证明所有输入永远正确。

## 内核升级

先对新源码运行同一个检查器。字段或契约变化会集中报告，不要先更新契约来绕过失败。对照生成的 `core-schema.json` 及其源码位置，完成模型、读取路径、验证逻辑和用例的修改后，再同步 `Models/SingboxContract.json`：保留各字段的 `go_type`、`kind`、`enum`、`deprecated`，删除机器相关的 `source` 属性。

`fixtures/` 中的证书、私钥与 ECH 配置仅用于本地检查。回归和字段用例的节点、密码、服务器都是测试数据。
