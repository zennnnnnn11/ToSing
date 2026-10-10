namespace SubParser.Models.Common;

using System.Text.Json.Serialization;

/// <summary>
/// UDP Over TCP 配置。
/// </summary>
public sealed record class UdpOverTcpOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Version { get; init; }
}
