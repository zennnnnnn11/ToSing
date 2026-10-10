namespace SubParser.Models.Common;

using System.Text.Json.Serialization;

/// <summary>
/// 对齐 sing-box 官方 option/udp_over_tcp.go 中的 UDPOverTCPOptions 定义
/// </summary>
public sealed record class UdpOverTcpOptions
{
    [JsonPropertyName("enabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Version { get; init; } // 1 或 2
}
