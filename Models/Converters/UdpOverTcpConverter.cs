namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// 1:1 对齐 Go 的 option/udp_over_tcp.go：
/// - 支持布尔值与对象形式
/// - 遇到未知属性严格报错 (DisallowUnknownFields)
/// - 未显式指定 enabled 时默认为 false (对齐 Go 零值)
/// - Version 缺省或为 2 时按布尔值序列化，Version 为 1 时按对象序列化
/// </summary>
public sealed class UdpOverTcpConverter : JsonConverter<UdpOverTcpOptions>
{
    public override UdpOverTcpOptions Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.True or JsonTokenType.False)
        {
            return new UdpOverTcpOptions
            {
                Enabled = reader.GetBoolean(),
                Version = null
            };
        }

        if (reader.TokenType == JsonTokenType.StartObject)
        {
            bool? enabled = null;
            int? version = null;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    string prop = reader.GetString() ?? string.Empty;
                    reader.Read();

                    if (string.Equals(prop, "enabled", StringComparison.OrdinalIgnoreCase))
                    {
                        enabled = reader.GetBoolean();
                    }
                    else if (string.Equals(prop, "version", StringComparison.OrdinalIgnoreCase))
                    {
                        version = reader.GetInt32();
                    }
                    else
                    {
                        // 对齐 Go 的 json.UnmarshalDisallowUnknownFields
                        throw new JsonException($"Unknown field '{prop}' in udp_over_tcp is not allowed.");
                    }
                }
            }

            return new UdpOverTcpOptions
            {
                // Go 的默认零值为 false
                Enabled = enabled ?? false,
                Version = version
            };
        }

        throw new JsonException($"Expected boolean or object for udp_over_tcp, got {reader.TokenType}");
    }

    public override void Write(Utf8JsonWriter writer, UdpOverTcpOptions value, JsonSerializerOptions options)
    {
        int version = value.Version ?? 0;
        // 对齐 Go: case 0, uot.Version (2): return json.Marshal(o.Enabled)
        if (version is 0 or 2)
        {
            writer.WriteBooleanValue(value.Enabled ?? false);
        }
        else
        {
            writer.WriteStartObject();
            if (value.Enabled.HasValue)
            {
                writer.WriteBoolean("enabled", value.Enabled.Value);
            }
            else
            {
                writer.WriteBoolean("enabled", false);
            }

            writer.WriteNumber("version", version);
            writer.WriteEndObject();
        }
    }
}
