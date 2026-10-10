namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// Shadowsocks 出站配置。
/// </summary>
public sealed record class ShadowsocksOutbound : SingboxOutbound
{
    [JsonPropertyName("method")]
    public required string Method { get; init; }

    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("plugin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Plugin { get; init; }

    [JsonPropertyName("plugin_opts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PluginOptions { get; init; }

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Network { get; init; }

    [JsonPropertyName("udp_over_tcp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UdpOverTcpOptions? UdpOverTcp { get; init; }

    [JsonPropertyName("multiplex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundMultiplexOptions? Multiplex { get; init; }
}
