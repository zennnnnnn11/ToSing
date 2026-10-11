namespace ToSing.Models.Common;

using System.Text.Json.Serialization;

/// <summary>
/// UDP Over TCP 配置。
/// </summary>
public sealed record class UdpOverTcpOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Version { get; init; }
}
