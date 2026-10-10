namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// 对齐 sing-box 官方 option/anytls.go 中的 AnyTLSOutboundOptions 定义 (1.12.0+)
/// </summary>
public sealed record class AnyTlsOutbound : SingboxOutbound
{
    [JsonPropertyName("password")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Password { get; init; }

    [JsonPropertyName("idle_session_check_interval")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdleSessionCheckInterval { get; init; }

    [JsonPropertyName("idle_session_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdleSessionTimeout { get; init; }

    [JsonPropertyName("min_idle_session")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MinIdleSession { get; init; }

    [JsonPropertyName("client_metadata")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientMetadata { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }
}
