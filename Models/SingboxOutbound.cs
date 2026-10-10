namespace SubParser.Models;

using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Protocols;

/// <summary>
/// sing-box 出站节点基类。
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
    /// 节点标识。
    /// </summary>
    [JsonPropertyName("tag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tag { get; init; }

    /// <summary>
    /// 服务器主机名或 IP 地址。
    /// </summary>
    [JsonPropertyName("server")]
    public required string Server { get; init; }

    /// <summary>
    /// 服务器端口。
    /// </summary>
    [JsonPropertyName("server_port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ServerPort { get; init; }

    /// <summary>
    /// 转发代理的出站标签。
    /// </summary>
    [JsonPropertyName("detour")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detour { get; init; }

    /// <summary>
    /// 域名解析策略（prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only）。
    /// </summary>
    [JsonPropertyName("domain_strategy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DomainStrategy { get; init; }

    /// <summary>
    /// 是否启用 TCP Fast Open。
    /// </summary>
    [JsonPropertyName("tcp_fast_open")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TcpFastOpen { get; init; }

    /// <summary>
    /// 连接超时时长（例如 "5s"）。
    /// </summary>
    [JsonPropertyName("connect_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ConnectTimeout { get; init; }

    /// <summary>
    /// 未显式映射的扩展 JSON 字段。
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }

    /// <summary>
    /// 运行时自定义数据存储，不参与 JSON 序列化。
    /// </summary>
    [JsonIgnore]
    public IDictionary<string, object?> Extra { get; init; } = new Dictionary<string, object?>(StringComparer.Ordinal);
}
