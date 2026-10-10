namespace SubParser.Models;

using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(VlessOutbound), "vless")]
[JsonDerivedType(typeof(ShadowsocksOutbound), "shadowsocks")]
[JsonDerivedType(typeof(Hysteria2Outbound), "hysteria2")]
[JsonDerivedType(typeof(VmessOutbound), "vmess")]
[JsonDerivedType(typeof(TrojanOutbound), "trojan")]
[JsonDerivedType(typeof(TuicOutbound), "tuic")]
[JsonDerivedType(typeof(AnyTlsOutbound), "anytls")]
public abstract record class SingboxOutbound : SingboxDialerOptions
{
    [JsonPropertyName("tag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tag { get; init; }

    [JsonPropertyName("server")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Server { get; init; }

    [JsonPropertyName("server_port")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ServerPort { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? ExtensionData { get; set; }

    [JsonIgnore]
    public IDictionary<string, object?> Extra { get; init; } =
        new Dictionary<string, object?>(StringComparer.Ordinal);
}
