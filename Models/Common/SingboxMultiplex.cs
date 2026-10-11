namespace ToSing.Models.Common;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 出站多路复用配置。
/// </summary>
public sealed record class OutboundMultiplexOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Protocol { get; init; }

    [JsonPropertyName("max_connections")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MaxConnections { get; init; }

    [JsonPropertyName("min_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MinStreams { get; init; }

    [JsonPropertyName("max_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MaxStreams { get; init; }

    [JsonPropertyName("padding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Padding { get; init; }

    [JsonPropertyName("brutal")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public BrutalOptions? Brutal { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}

/// <summary>
/// TCP Brutal 拥塞控制配置。
/// </summary>
public sealed record class BrutalOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Enabled { get; init; }

    [JsonPropertyName("up_mbps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? UpMbps { get; init; }

    [JsonPropertyName("down_mbps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DownMbps { get; init; }
}
