namespace SubParser.Models.Common;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// V2Ray 传输层配置（ws, grpc, http, httpupgrade 等）。
/// </summary>
public sealed record class V2RayTransportOptions
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

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

    [JsonPropertyName("host")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Host { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}
