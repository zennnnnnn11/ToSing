namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SubParser.Models;
using SubParser.Models.Protocols;

/// <summary>
/// 支持 "type" 鉴别器出现在 JSON 任意位置（开头、中间或末尾）的多态转换器
/// </summary>
public sealed class SingboxOutboundConverter : JsonConverter<SingboxOutbound>
{
    public override SingboxOutbound? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject token, got {reader.TokenType}");
        }

        using var doc = JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;

        if (!root.TryGetProperty("type", out var typeProp) || typeProp.ValueKind != JsonValueKind.String)
        {
            throw new JsonException("Missing or invalid 'type' property in outbound configuration.");
        }

        string type = typeProp.GetString()!;
        string rawJson = root.GetRawText();

        return type switch
        {
            "vless" => JsonSerializer.Deserialize<VlessOutbound>(rawJson, options),
            "shadowsocks" => JsonSerializer.Deserialize<ShadowsocksOutbound>(rawJson, options),
            "hysteria2" => JsonSerializer.Deserialize<Hysteria2Outbound>(rawJson, options),
            "vmess" => JsonSerializer.Deserialize<VmessOutbound>(rawJson, options),
            "trojan" => JsonSerializer.Deserialize<TrojanOutbound>(rawJson, options),
            "tuic" => JsonSerializer.Deserialize<TuicOutbound>(rawJson, options),
            "anytls" => JsonSerializer.Deserialize<AnyTlsOutbound>(rawJson, options),
            _ => throw new JsonException($"Unsupported outbound type: '{type}'")
        };
    }

    public override void Write(Utf8JsonWriter writer, SingboxOutbound value, JsonSerializerOptions options)
    {
        // 按照具体运行时子类型直接序列化
        JsonSerializer.Serialize(writer, (object)value, value.GetType(), options);
    }
}
