namespace SubParser.Models.Common;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 对齐 sing-box 官方 option/tls.go 中的 OutboundTLSOptions 定义
/// </summary>
public sealed record class OutboundTLSOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("server_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServerName { get; init; }

    [JsonPropertyName("insecure")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Insecure { get; init; }

    [JsonPropertyName("alpn")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Alpn { get; init; }

    [JsonPropertyName("min_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MinVersion { get; init; }

    [JsonPropertyName("max_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MaxVersion { get; init; }

    [JsonPropertyName("utls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundUTLSOptions? Utls { get; init; }

    [JsonPropertyName("reality")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundRealityOptions? Reality { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// 对齐 sing-box 官方 option/tls.go 中的 OutboundUTLSOptions 定义
/// </summary>
public sealed record class OutboundUTLSOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("fingerprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Fingerprint { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// 对齐 sing-box 官方 option/tls.go 中的 OutboundRealityOptions 定义
/// </summary>
public sealed record class OutboundRealityOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("public_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PublicKey { get; init; }

    [JsonPropertyName("short_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ShortId { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}
