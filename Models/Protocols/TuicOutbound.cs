namespace SubParser.Models.Protocols;

using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// TUIC 出站配置。
/// </summary>
public sealed record class TuicOutbound : SingboxOutbound
{
    [JsonPropertyName("uuid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Uuid { get; init; }

    [JsonPropertyName("password")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Password { get; init; }

    [JsonPropertyName("congestion_control")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CongestionControl { get; init; }

    [JsonPropertyName("udp_relay_mode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UdpRelayMode { get; init; }

    [JsonPropertyName("udp_over_stream")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool UdpOverStream { get; init; }

    [JsonPropertyName("zero_rtt_handshake")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ZeroRttHandshake { get; init; }

    [JsonPropertyName("heartbeat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Heartbeat { get; init; }

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Network { get; init; }

    [JsonPropertyName("idle_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdleTimeout { get; init; }

    [JsonPropertyName("keep_alive_period")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeepAlivePeriod { get; init; }

    [JsonPropertyName("initial_packet_size")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? InitialPacketSize { get; init; }

    [JsonPropertyName("disable_path_mtu_discovery")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisablePathMtuDiscovery { get; init; }

    [JsonPropertyName("max_concurrent_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxConcurrentStreams { get; init; }

    [JsonPropertyName("stream_receive_window")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StreamReceiveWindow { get; init; }

    [JsonPropertyName("connection_receive_window")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ConnectionReceiveWindow { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }
}
