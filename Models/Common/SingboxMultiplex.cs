namespace SubParser.Models.Common;

using System.Text.Json.Serialization;

/// <summary>
/// 对齐 sing-box 官方 option/multiplex.go 中的 OutboundMultiplexOptions 定义
/// </summary>
public sealed record class OutboundMultiplexOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Protocol { get; init; } // h2mux, smux, yamux

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
}
