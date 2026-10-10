namespace SubParser.Parsers;

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models;
using SubParser.Models.Common;

/// <summary>读取内核原生字段；YAML 标量只按目标类型转换，不丢弃未知字段。</summary>
internal static class NativeOptionsParser
{
    internal static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            TypeInfoResolver = SubParserJsonContext.Default,
        };
        options.Converters.Add(new ScalarBooleanConverter());
        options.Converters.Add(new ListableStringConverter());
        return options;
    }

    public static T Deserialize<
        [DynamicallyAccessedMembers(
            DynamicallyAccessedMemberTypes.PublicProperties
                | DynamicallyAccessedMemberTypes.PublicConstructors
        )]
            T
    >(object raw)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(raw, Options), Options)
            ?? throw new FormatException($"Empty {typeof(T).Name} options");
    }

    public static T Read<
        [DynamicallyAccessedMembers(
            DynamicallyAccessedMemberTypes.PublicProperties
                | DynamicallyAccessedMemberTypes.PublicConstructors
        )]
            T
    >(NodeContext ctx, params (string Alias, string Field)[] aliases)
    {
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in typeof(T).GetProperties())
        {
            string? name = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name;
            if (name == null)
                continue;
            object? value = ctx.GetRaw(name) ?? ctx.GetRaw(name.Replace('_', '-'));
            // 订阅中的 ech 标量由 TlsParser.ParseEch 解释；不是原生 ECH 对象。
            if (
                typeof(T) == typeof(OutboundTLSOptions)
                && string.Equals(name, "ech", StringComparison.Ordinal)
                && !IsObject(value)
            )
                continue;
            if (value != null)
                fields[name] = value;
        }
        foreach (var (alias, field) in aliases)
        {
            if (!fields.ContainsKey(field) && ctx.GetRaw(alias) is { } value)
                fields[field] = value;
        }
        if (
            fields.TryGetValue("domain_resolver", out object? resolver)
            && resolver is not string
            && resolver != null
        )
        {
            fields["domain_resolver"] = Deserialize<DomainResolveOptions>(resolver);
        }
        return Deserialize<T>(fields);
    }

    public static bool IsObject(object? value) =>
        value is System.Collections.IDictionary
        || value is JsonElement { ValueKind: JsonValueKind.Object };
}

internal sealed record class ParsedDialerOptions : SingboxDialerOptions;

internal sealed class ScalarBooleanConverter : JsonConverter<bool>
{
    public override bool Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        if (reader.TokenType is JsonTokenType.True or JsonTokenType.False)
            return reader.GetBoolean();
        if (reader.TokenType == JsonTokenType.String)
        {
            string value = reader.GetString()?.Trim() ?? string.Empty;
            if (bool.TryParse(value, out bool parsed))
                return parsed;
            if (string.Equals(value, "1", StringComparison.Ordinal))
                return true;
            if (string.Equals(value, "0", StringComparison.Ordinal))
                return false;
        }
        throw new JsonException("Expected a boolean scalar");
    }

    public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options) =>
        writer.WriteBooleanValue(value);
}

internal sealed class ListableStringConverter : JsonConverter<IReadOnlyList<string>>
{
    public override IReadOnlyList<string> Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        if (reader.TokenType == JsonTokenType.String)
            return [reader.GetString()!];
        if (reader.TokenType != JsonTokenType.StartArray)
            throw new JsonException("Expected a string or string list");
        var result = new List<string>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException("Expected a string list item");
            result.Add(reader.GetString()!);
        }
        return result;
    }

    public override void Write(
        Utf8JsonWriter writer,
        IReadOnlyList<string> value,
        JsonSerializerOptions options
    )
    {
        writer.WriteStartArray();
        foreach (string item in value)
            writer.WriteStringValue(item);
        writer.WriteEndArray();
    }
}

public sealed class FwMarkConverter : JsonConverter<uint>
{
    public static bool TryParse(string value, out uint result)
    {
        try
        {
            string text = value.Trim();
            int numberBase = 10;
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                numberBase = 16;
                text = text[2..];
            }
            else if (text.StartsWith("0b", StringComparison.OrdinalIgnoreCase))
            {
                numberBase = 2;
                text = text[2..];
            }
            else if (text.StartsWith("0o", StringComparison.OrdinalIgnoreCase))
            {
                numberBase = 8;
                text = text[2..];
            }
            else if (text.Length > 1 && text[0] == '0')
            {
                numberBase = 8;
                text = text[1..];
            }
            if (text.Length == 0 || text[0] == '-')
            {
                result = 0;
                return false;
            }
            result =
                numberBase == 10
                    ? uint.Parse(text, CultureInfo.InvariantCulture)
                    : Convert.ToUInt32(text, numberBase);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        {
            result = 0;
            return false;
        }
    }

    public override uint Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        if (reader.TokenType == JsonTokenType.Number)
            return reader.GetUInt32();
        if (
            reader.TokenType == JsonTokenType.String
            && TryParse(reader.GetString()!, out uint result)
        )
            return result;
        throw new JsonException("Expected a uint32 routing mark");
    }

    public override void Write(Utf8JsonWriter writer, uint value, JsonSerializerOptions options) =>
        writer.WriteNumberValue(value);
}

public sealed class HttpClientReferenceConverter : JsonConverter<object>
{
    public override object? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        if (reader.TokenType == JsonTokenType.String)
            return reader.GetString();
        return JsonSerializer.Deserialize<HttpClientOptions>(ref reader, options);
    }

    public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}

/// <summary>MemoryBytes 的数值读取使用 int64，字符串支持内核的单位格式。</summary>
public sealed class MemoryBytesConverter : JsonConverter<object>
{
    public override object Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        if (reader.TokenType == JsonTokenType.String)
            return reader.GetString()!;
        if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt64(out long value))
            return value;
        throw new JsonException("Expected int64 bytes or a size string");
    }

    public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}
