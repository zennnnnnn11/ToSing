namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// 对齐 sing-box 官方 option/vless.go 中的 VLESSOutboundOptions 定义
/// </summary>
public sealed record class VlessOutbound : SingboxOutbound
{
    [JsonPropertyName("uuid")]
    public required string Uuid { get; init; }

    [JsonPropertyName("flow")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Flow { get; init; } // e.g. "xtls-rprx-vision"

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Network { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }

    [JsonPropertyName("transport")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public V2RayTransportOptions? Transport { get; init; }

    [JsonPropertyName("packet_encoding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PacketEncoding { get; init; } // "xudp", "packetaddr"

    [JsonPropertyName("multiplex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundMultiplexOptions? Multiplex { get; init; }
}
