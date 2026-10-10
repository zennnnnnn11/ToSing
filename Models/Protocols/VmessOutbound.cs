namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;
using SubParser.Models.Converters;

/// <summary>
/// 对齐 sing-box 官方 option/vmess.go 中的 VMessOutboundOptions 定义
/// </summary>
public sealed record class VmessOutbound : SingboxOutbound
{
    [JsonPropertyName("uuid")]
    public required string Uuid { get; init; }

    [JsonPropertyName("security")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Security { get; init; } = "auto"; // "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"

    [JsonPropertyName("alter_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int AlterId { get; init; }

    [JsonPropertyName("global_padding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool GlobalPadding { get; init; }

    [JsonPropertyName("authenticated_length")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool AuthenticatedLength { get; init; }

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

    [JsonPropertyName("packet_encoding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PacketEncoding { get; init; }

    [JsonPropertyName("multiplex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundMultiplexOptions? Multiplex { get; init; }
}
