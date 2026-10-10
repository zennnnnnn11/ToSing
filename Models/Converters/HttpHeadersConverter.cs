namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 对齐 Go 的 badoption.HTTPHeader，Value 既支持单个字符串，也支持字符串数组
/// </summary>
public sealed class HttpHeadersConverter : JsonConverter<IReadOnlyDictionary<string, string>>
{
    public override IReadOnlyDictionary<string, string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            return result;
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string headerName = reader.GetString() ?? string.Empty;
                reader.Read();

                if (reader.TokenType == JsonTokenType.String)
                {
                    result[headerName] = reader.GetString() ?? string.Empty;
                }
                else if (reader.TokenType == JsonTokenType.StartArray)
                {
                    string firstValue = string.Empty;
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray)
                        {
                            break;
                        }

                        if (reader.TokenType == JsonTokenType.String && string.IsNullOrEmpty(firstValue))
                        {
                            firstValue = reader.GetString() ?? string.Empty;
                        }
                    }

                    result[headerName] = firstValue;
                }
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyDictionary<string, string> value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        foreach (KeyValuePair<string, string> pair in value)
        {
            writer.WriteString(pair.Key, pair.Value);
        }

        writer.WriteEndObject();
    }
}
