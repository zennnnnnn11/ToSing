namespace SubParser.Models.Common;

using System.Text.Json.Serialization;
using SubParser.Models.Converters;

/// <summary>
/// 对齐 sing-box 官方 option/udp_over_tcp.go 中的 UDPOverTCPOptions 定义
/// </summary>
[JsonConverter(typeof(UdpOverTcpConverter))]
public sealed record class UdpOverTcpOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Enabled { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Version { get; init; } // 1 或 2
}
