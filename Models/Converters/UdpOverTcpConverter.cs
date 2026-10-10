namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Common;

/// <summary>
/// 对齐 Go 的 option/udp_over_tcp.go，既支持布尔值 true/false，也支持对象 { "enabled": true, "version": 2 }
/// </summary>
public sealed class UdpOverTcpConverter : JsonConverter<UdpOverTcpOptions>
{
    public override UdpOverTcpOptions Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.True or JsonTokenType.False)
        {
            return new UdpOverTcpOptions
            {
                Enabled = reader.GetBoolean()
            };
        }

        if (reader.TokenType == JsonTokenType.StartObject)
        {
            bool enabled = true;
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
                }
            }

            return new UdpOverTcpOptions
            {
                Enabled = enabled,
                Version = version
            };
        }

        return new UdpOverTcpOptions { Enabled = false };
    }

    public override void Write(Utf8JsonWriter writer, UdpOverTcpOptions value, JsonSerializerOptions options)
    {
        // 如果没有指定 version，官方默认直接序列化为布尔值
        if (value.Version is null or 0)
        {
            writer.WriteBooleanValue(value.Enabled ?? true);
        }
        else
        {
            writer.WriteStartObject();
            if (value.Enabled.HasValue)
            {
                writer.WriteBoolean("enabled", value.Enabled.Value);
            }

            writer.WriteNumber("version", value.Version.Value);
            writer.WriteEndObject();
        }
    }
}
