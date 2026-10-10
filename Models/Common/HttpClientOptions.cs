namespace SubParser.Models.Common;

using System.Text.Json.Serialization;

public sealed record class HttpClientOptions : SingboxDialerOptions
{
    [JsonPropertyName("tag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tag { get; init; }

    [JsonPropertyName("engine")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Engine { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Version { get; init; }

    [JsonPropertyName("disable_version_fallback")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableVersionFallback { get; init; }

    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, object>? Headers { get; init; }

    [JsonPropertyName("tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OutboundTLSOptions? Tls { get; init; }

    [JsonPropertyName("idle_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdleTimeout { get; init; }

    [JsonPropertyName("keep_alive_period")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeepAlivePeriod { get; init; }

    [JsonPropertyName("stream_receive_window")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonConverter(typeof(SubParser.Parsers.MemoryBytesConverter))]
    public object? StreamReceiveWindow { get; init; }

    [JsonPropertyName("connection_receive_window")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonConverter(typeof(SubParser.Parsers.MemoryBytesConverter))]
    public object? ConnectionReceiveWindow { get; init; }

    [JsonPropertyName("max_concurrent_streams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MaxConcurrentStreams { get; init; }

    [JsonPropertyName("initial_packet_size")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? InitialPacketSize { get; init; }

    [JsonPropertyName("disable_path_mtu_discovery")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisablePathMtuDiscovery { get; init; }
}
