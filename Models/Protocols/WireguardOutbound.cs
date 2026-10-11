namespace ToSing.Models.Protocols;

using System.Collections.Generic;
using System.Text.Json.Serialization;
using ToSing.Models;

/// <summary>
/// sing-box 1.11+ 标准 WireGuard 端点/出站模型。
/// </summary>
public sealed record class WireguardOutbound : SingboxOutbound
{
    [JsonPropertyName("system")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool System { get; init; }

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }

    [JsonPropertyName("mtu")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Mtu { get; init; }

    [JsonPropertyName("address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Address { get; init; }

    [JsonPropertyName("private_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PrivateKey { get; init; }

    [JsonPropertyName("listen_port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ListenPort { get; init; }

    [JsonPropertyName("peers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<WireguardPeer>? Peers { get; init; }

    [JsonPropertyName("workers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Workers { get; init; }
}

/// <summary>
/// WireGuard 对等方配置项。
/// </summary>
public sealed record class WireguardPeer
{
    [JsonPropertyName("address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Address { get; init; }

    [JsonPropertyName("port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Port { get; init; }

    [JsonPropertyName("public_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PublicKey { get; init; }

    [JsonPropertyName("pre_shared_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PreSharedKey { get; init; }

    [JsonPropertyName("allowed_ips")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? AllowedIps { get; init; }

    [JsonPropertyName("persistent_keepalive_interval")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? PersistentKeepaliveInterval { get; init; }

    [JsonPropertyName("reserved")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<int>? Reserved { get; init; }
}
