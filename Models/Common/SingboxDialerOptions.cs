namespace ToSing.Models.Common;

using System.Text.Json.Serialization;

/// <summary>与内核 option.DialerOptions 对应的通用出站拨号字段。</summary>
public abstract record class SingboxDialerOptions
{
    [JsonPropertyName("detour")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detour { get; init; }

    [JsonPropertyName("domain_strategy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DomainStrategy { get; init; }

    [JsonPropertyName("tcp_fast_open")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TcpFastOpen { get; init; }

    [JsonPropertyName("connect_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ConnectTimeout { get; init; }

    [JsonPropertyName("bind_interface")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BindInterface { get; init; }

    [JsonPropertyName("inet4_bind_address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Inet4BindAddress { get; init; }

    [JsonPropertyName("inet6_bind_address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Inet6BindAddress { get; init; }

    [JsonPropertyName("routing_mark")]
    [JsonConverter(typeof(ToSing.Parsers.FwMarkConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? RoutingMark { get; init; }

    [JsonPropertyName("reuse_addr")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ReuseAddr { get; init; }

    [JsonPropertyName("tcp_multi_path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TcpMultiPath { get; init; }

    [JsonPropertyName("udp_fragment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UdpFragment { get; init; }

    [JsonPropertyName("domain_resolver")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? DomainResolver { get; init; }

    [JsonPropertyName("bind_address_no_port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BindAddressNoPort { get; init; }

    [JsonPropertyName("protect_path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProtectPath { get; init; }

    [JsonPropertyName("netns")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetNs { get; init; }

    [JsonPropertyName("disable_tcp_keep_alive")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableTcpKeepAlive { get; init; }

    [JsonPropertyName("tcp_keep_alive")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpKeepAlive { get; init; }

    [JsonPropertyName("tcp_keep_alive_interval")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpKeepAliveInterval { get; init; }

    [JsonPropertyName("network_strategy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetworkStrategy { get; init; }

    [JsonPropertyName("network_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? NetworkType { get; init; }

    [JsonPropertyName("fallback_network_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? FallbackNetworkType { get; init; }

    [JsonPropertyName("fallback_delay")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FallbackDelay { get; init; }
}
