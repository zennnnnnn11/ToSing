namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;
using SubParser.Models.Converters;

/// <summary>
/// 对齐 sing-box 官方 option/hysteria2.go 中的 Hysteria2OutboundOptions 定义
/// </summary>
public sealed record class Hysteria2Outbound : SingboxOutbound
{
    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("network")]
    [JsonConverter(typeof(SingleOrListConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Network { get; init; }

    [JsonPropertyName("server_ports")]
    [JsonConverter(typeof(SingleOrListConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ServerPorts { get; init; }

    [JsonPropertyName("hop_interval")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HopInterval { get; init; }

    [JsonPropertyName("hop_interval_max")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HopIntervalMax { get; init; }

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

    [JsonPropertyName("bbr_profile")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BbrProfile { get; init; } // "standard", "conservative", "aggressive"
}

public sealed record class Hysteria2ObfsOptions
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "salamander";

    [JsonPropertyName("password")]
    public required string Password { get; init; }
}
