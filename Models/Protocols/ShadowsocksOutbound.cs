namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// 对齐 sing-box 官方 option/shadowsocks.go 中的 ShadowsocksOutboundOptions 定义
/// </summary>
public sealed record class ShadowsocksOutbound : SingboxOutbound
{
    [JsonPropertyName("method")]
    public required string Method { get; init; } // e.g. "2022-blake3-aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"

    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("plugin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Plugin { get; init; } // e.g. "obfs-local", "v2ray-plugin"

    [JsonPropertyName("plugin_opts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PluginOptions { get; init; }

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Network { get; init; }

    [JsonPropertyName("multiplex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundMultiplexOptions? Multiplex { get; init; }
}
