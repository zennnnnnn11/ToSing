namespace SubParser.Models.Common;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 对齐 sing-box 官方 option/v2ray_transport.go 中的 V2RayTransportOptions 定义
/// </summary>
public sealed record class V2RayTransportOptions
{
    [JsonPropertyName("type")]
    public required string Type { get; init; } // ws, grpc, httpupgrade, http, quic

    // WebSocket / HTTPUpgrade 常用参数
    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; init; }

    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    [JsonPropertyName("max_early_data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? MaxEarlyData { get; init; }

    [JsonPropertyName("early_data_header_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EarlyDataHeaderName { get; init; }

    // gRPC 常用参数
    [JsonPropertyName("service_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServiceName { get; init; }

    [JsonPropertyName("idle_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdleTimeout { get; init; }

    [JsonPropertyName("ping_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PingTimeout { get; init; }

    [JsonPropertyName("permit_without_stream")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool PermitWithoutStream { get; init; }

    // HTTP / HTTPUpgrade 专属 Host
    [JsonPropertyName("host")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Host { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}
