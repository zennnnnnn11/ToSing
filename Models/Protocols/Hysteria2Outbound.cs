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

    [JsonPropertyName("bbr_profile")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BbrProfile { get; init; }

    [JsonPropertyName("brutal_debug")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BrutalDebug { get; init; }

    [JsonPropertyName("disable_chrome_parrot")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableChromeParrot { get; init; }

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

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Network { get; init; }

    [JsonPropertyName("obfs")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Hysteria2ObfsOptions? Obfs { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }

    [JsonPropertyName("realm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Hysteria2RealmOptions? Realm { get; init; }
}

/// <summary>
/// Hysteria 2 Realm 认证域配置。
/// </summary>
public sealed record class Hysteria2RealmOptions
{
    [JsonPropertyName("server_url")]
    public required string ServerUrl { get; init; }

    [JsonPropertyName("token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Token { get; init; }

    [JsonPropertyName("realm_id")]
    public required string RealmId { get; init; }

    [JsonPropertyName("stun_servers")]
    public required IReadOnlyList<string> StunServers { get; init; }

    [JsonPropertyName("ip_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? IpVersion { get; init; }
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
