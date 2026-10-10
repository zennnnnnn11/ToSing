namespace SubParser.Models.Common;

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
    public int? MaxConnections { get; init; }

    [JsonPropertyName("min_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MinStreams { get; init; }

    [JsonPropertyName("max_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxStreams { get; init; }

    [JsonPropertyName("padding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Padding { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }
}
