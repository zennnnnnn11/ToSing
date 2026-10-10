namespace SubParser.Models.Converters;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// 对齐 Go 的 badoption.Listable[string]，既支持单个字符串，也支持字符串数组
/// </summary>
public sealed class SingleOrListConverter : JsonConverter<IReadOnlyList<string>>
{
    public override IReadOnlyList<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            string? single = reader.GetString();
            return single is not null ? new[] { single } : Array.Empty<string>();
        }

        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var list = new List<string>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    break;
                }

                if (reader.TokenType == JsonTokenType.String)
                {
                    string? item = reader.GetString();
                    if (item is not null)
                    {
                        list.Add(item);
                    }
                }
            }

            return list;
        }

        return Array.Empty<string>();
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyList<string> value, JsonSerializerOptions options)
    {
        if (value.Count == 1)
        {
            writer.WriteStringValue(value[0]);
        }
        else
        {
            writer.WriteStartArray();
            foreach (string item in value)
            {
                writer.WriteStringValue(item);
            }

            writer.WriteEndArray();
        }
    }
}
