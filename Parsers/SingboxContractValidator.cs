namespace SubParser.Parsers;

using System.Text.Json;
using SubParser.Models;

/// <summary>按检查器核对过的内核字段契约校验输出，阻止错误类型和未知枚举落入配置。</summary>
internal static class SingboxContractValidator
{
    private static readonly JsonDocument Contract = ReadContract();

    private static JsonDocument ReadContract()
    {
        using var stream = typeof(SingboxOutbound).Assembly.GetManifestResourceStream("SubParser.Models.SingboxContract.json")
            ?? throw new InvalidOperationException("Missing sing-box field contract");
        return JsonDocument.Parse(stream);
    }

    internal static void Validate(SingboxOutbound outbound)
    {
        var json = JsonSerializer.SerializeToElement<SingboxOutbound>(outbound);
        string protocol = json.GetProperty("type").GetString()!;
        ValidateObject(json, protocol, protocol);
        if (protocol is "hysteria2" or "tuic" or "anytls")
        {
            if (!json.TryGetProperty("tls", out var tls) || !tls.TryGetProperty("enabled", out var enabled) || enabled.ValueKind != JsonValueKind.True)
                throw new FormatException($"sing-box {protocol} requires enabled TLS");
        }
        if (string.Equals(protocol, "anytls", StringComparison.Ordinal) && outbound.TcpFastOpen)
            throw new FormatException("sing-box AnyTLS does not support tcp_fast_open");
    }

    private static void ValidateObject(JsonElement value, string group, string path)
    {
        JsonElement rules = Contract.RootElement.GetProperty(group);
        bool outboundGroup = group is "vmess" or "vless" or "trojan" or "shadowsocks" or "hysteria2" or "tuic" or "anytls";
        bool transportGroup = group is "ws" or "http" or "httpupgrade" or "quic" or "grpc";
        foreach (JsonProperty field in value.EnumerateObject())
        {
            if (string.Equals(field.Name, "type", StringComparison.Ordinal) && (outboundGroup || transportGroup)) continue;
            if (string.Equals(field.Name, "tag", StringComparison.Ordinal) && outboundGroup) continue;
            if (!rules.TryGetProperty(field.Name, out JsonElement rule)) throw new FormatException($"Unknown sing-box field: {path}.{field.Name}");
            if (field.Value.ValueKind == JsonValueKind.Null) continue;
            string location = $"{path}.{field.Name}";
            string goType = rule.GetProperty("go_type").GetString()!;
            string kind = rule.GetProperty("kind").GetString()!;
            if (rule.TryGetProperty("enum", out JsonElement choices)) ValidateEnum(field.Value, choices, location);
            if (string.Equals(kind, "string", StringComparison.Ordinal) && !string.Equals(goType, "option.NetworkList", StringComparison.Ordinal) && field.Value.ValueKind != JsonValueKind.String)
                throw new FormatException($"Expected string for {location}");
            if (string.Equals(goType, "int", StringComparison.Ordinal) || goType.Contains("MemoryBytes", StringComparison.Ordinal))
            {
                if (field.Value.ValueKind == JsonValueKind.Number)
                {
                    // The reference core's excluded-object decoder rounds through float64.
                    if (!field.Value.TryGetInt64(out long number) || number > 9223372036854775295L)
                        throw new FormatException($"Integer exceeds sing-box JSON decoder range: {location}");
                }
            }
            if ((goType is "uint8" or "uint16" or "uint32" or "*uint32") &&
                (!field.Value.TryGetUInt64(out ulong unsigned) || unsigned > (kind switch { "uint8" => byte.MaxValue, "uint16" => ushort.MaxValue, _ => uint.MaxValue })))
                throw new FormatException($"Unsigned integer exceeds sing-box field range: {location}");

            if (field.Value.ValueKind != JsonValueKind.Object) continue;
            string? child = field.Name switch
            {
                "tls" => "tls", "ech" => "ech", "utls" => "utls", "reality" => "reality",
                "multiplex" => "multiplex", "brutal" => "brutal", "udp_over_tcp" => "uot",
                "obfs" => "hy2_obfs", "realm" => "realm", "port_mapping" => "realm_port_mapping",
                "http_client" => "http_client", "domain_resolver" => "domain_resolver",
                "transport" => field.Value.GetProperty("type").GetString(), _ => null
            };
            if (child != null)
            {
                if (!Contract.RootElement.TryGetProperty(child, out _)) throw new FormatException($"Unknown sing-box option group: {child}");
                ValidateObject(field.Value, child, location);
            }
        }
    }

    private static void ValidateEnum(JsonElement value, JsonElement choices, string path)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray()) ValidateEnum(item, choices, path);
            return;
        }
        string text = value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();
        if (text.Length == 0) return; // Empty values select the core default.
        foreach (JsonElement choice in choices.EnumerateArray())
            if (string.Equals(text, choice.GetString(), StringComparison.Ordinal)) return;
        throw new FormatException($"Value is outside sing-box enum: {path}={text}");
    }
}
