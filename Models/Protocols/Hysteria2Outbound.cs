namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// Hysteria 2 出站配置。
/// </summary>
public sealed record class Hysteria2Outbound : SingboxOutbound
{
    [JsonPropertyName("password")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Password { get; init; }

    [JsonPropertyName("server_ports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ServerPorts { get; init; }

    [JsonPropertyName("up_mbps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? UpMbps { get; init; }

    [JsonPropertyName("down_mbps")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? DownMbps { get; init; }

    [JsonPropertyName("obfs")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Hysteria2ObfsOptions? Obfs { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }
}

/// <summary>
/// Hysteria 2 混淆配置。
/// </summary>
public sealed record class Hysteria2ObfsOptions
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "salamander";

    [JsonPropertyName("password")]
    public required string Password { get; init; }
}
