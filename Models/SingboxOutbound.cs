namespace SubParser.Models;

using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Protocols;

/// <summary>
/// sing-box 出站节点基类 (对应 option/outbound.go 中的 ServerOptions 与多态 Outbound)
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(VlessOutbound), "vless")]
[JsonDerivedType(typeof(ShadowsocksOutbound), "shadowsocks")]
[JsonDerivedType(typeof(Hysteria2Outbound), "hysteria2")]
[JsonDerivedType(typeof(VmessOutbound), "vmess")]
[JsonDerivedType(typeof(TrojanOutbound), "trojan")]
[JsonDerivedType(typeof(TuicOutbound), "tuic")]
[JsonDerivedType(typeof(AnyTlsOutbound), "anytls")]
public abstract record class SingboxOutbound
{
    /// <summary>
    /// 节点名称 (全局唯一，sing-box 必填)
    /// </summary>
    [JsonPropertyName("tag")]
    public required string Tag { get; init; }

    /// <summary>
    /// 服务器地址 (域名或 IP，对齐 ServerOptions.Server)
    /// </summary>
    [JsonPropertyName("server")]
    public required string Server { get; init; }

    /// <summary>
    /// 服务器端口 (对齐 ServerOptions.ServerPort uint16，Hysteria2 使用 server_ports 时可缺省)
    /// </summary>
    [JsonPropertyName("server_port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ServerPort { get; init; }

    /// <summary>
    /// 前置代理 / 链式代理出站标签 (对齐 DialerOptions.Detour)
    /// </summary>
    [JsonPropertyName("detour")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detour { get; init; }

    /// <summary>
    /// 域名解析策略 (对齐 DialerOptions.DomainStrategy: prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only)
    /// </summary>
    [JsonPropertyName("domain_strategy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DomainStrategy { get; init; }

    /// <summary>
    /// TCP Fast Open (对齐 AbstractDialerOptions.TCPFastOpen)
    /// </summary>
    [JsonPropertyName("tcp_fast_open")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TcpFastOpen { get; init; }

    /// <summary>
    /// 连接超时时长 (对齐 AbstractDialerOptions.ConnectTimeout，例如 "5s")
    /// </summary>
    [JsonPropertyName("connect_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ConnectTimeout { get; init; }

    /// <summary>
    /// 未显式建模的顶层扩展字段无损保存在此，序列化时原样输出
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }

    /// <summary>
    /// 本地业务元数据口袋（仅在内存中使用，如测速延迟、原订阅行等，不输出到 JSON）
    /// </summary>
    [JsonIgnore]
    public IDictionary<string, object?> Extra { get; init; } = new Dictionary<string, object?>(StringComparer.Ordinal);
}
