namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 对齐 Go 的 badoption.HTTPHeader (map[string]badoption.Listable[string])
/// 单值和多值数组全兼容，写出时 1 个值写成字符串，多个值写成数组
/// </summary>
public sealed class HttpHeadersConverter : JsonConverter<IReadOnlyDictionary<string, IReadOnlyList<string>>>
{
    public override IReadOnlyDictionary<string, IReadOnlyList<string>> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for HTTP headers, got {reader.TokenType}");
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
                    string val = reader.GetString() ?? string.Empty;
                    result[headerName] = new[] { val };
                }
                else if (reader.TokenType == JsonTokenType.StartArray)
                {
                    var values = new List<string>();
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray)
                        {
                            break;
                        }

                        if (reader.TokenType == JsonTokenType.String)
                        {
                            values.Add(reader.GetString() ?? string.Empty);
                        }
                        else
                        {
                            throw new JsonException($"Expected string in header values array, got {reader.TokenType}");
                        }
                    }

                    result[headerName] = values;
                }
                else
                {
                    throw new JsonException($"Expected string or array for header '{headerName}', got {reader.TokenType}");
                }
            }
        }

        return result;
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyDictionary<string, IReadOnlyList<string>> value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        foreach (KeyValuePair<string, IReadOnlyList<string>> pair in value)
        {
            writer.WritePropertyName(pair.Key);
            if (pair.Value.Count == 1)
            {
                writer.WriteStringValue(pair.Value[0]);
            }
            else
            {
                writer.WriteStartArray();
                foreach (string val in pair.Value)
                {
                    writer.WriteStringValue(val);
                }

                writer.WriteEndArray();
            }
        }

        writer.WriteEndObject();
    }
}
