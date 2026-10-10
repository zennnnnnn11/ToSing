namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;
using SubParser.Models.Converters;

/// <summary>
/// 对齐 sing-box 官方 option/trojan.go 中的 TrojanOutboundOptions 定义
/// </summary>
public sealed record class TrojanOutbound : SingboxOutbound
{
    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("network")]
    [JsonConverter(typeof(SingleOrListConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Network { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }

    [JsonPropertyName("transport")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public V2RayTransportOptions? Transport { get; init; }

    [JsonPropertyName("multiplex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundMultiplexOptions? Multiplex { get; init; }
}
