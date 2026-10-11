namespace SubParser.Parsers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Web;
using SubParser.Utils;

/// <summary>
/// 节点属性查询上下文，为 URI 链接和 Clash 字典提供统一的别名读取接口。
/// </summary>
public sealed class NodeContext
{
    private readonly Dictionary<string, object?> _properties = new(
        StringComparer.OrdinalIgnoreCase
    );

    public string Protocol { get; set; } = string.Empty;
    public string Tag { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public int ServerPort { get; set; }

    public IReadOnlyDictionary<string, object?> Properties => _properties;

    public void SetProperty(string key, object? value)
    {
        _properties[key] = value;
    }

    public bool HasProperty(string key)
    {
        return _properties.ContainsKey(key);
    }

    internal bool IsNativeConfig { get; private set; }

    public object? GetRaw(string key)
    {
        return ResolveValue(key);
    }

    /// <summary>
    /// 从标准 URI 字符串解析上下文。
    /// </summary>
    public static NodeContext FromUri(string uriString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uriString);

        var ctx = new NodeContext();
        string trimmed = ExtractFragment(uriString.Trim(), ctx);

        int schemeEnd = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            throw new FormatException($"无效的协议链接前缀: {uriString}");
        }

        ctx.Protocol = trimmed[..schemeEnd].ToLowerInvariant();
        string rest = trimmed[(schemeEnd + 3)..];

        if (string.Equals(ctx.Protocol, "ss", StringComparison.OrdinalIgnoreCase))
        {
            ParseShadowsocksUri(rest, ctx);
        }
        else
        {
            ParseStandardUriRest(rest, ctx);
        }

        if (string.IsNullOrWhiteSpace(ctx.Tag))
        {
            ctx.Tag = ctx.GetString("remarks", "remark");
            if (string.IsNullOrWhiteSpace(ctx.Tag))
            {
                ctx.Tag =
                    $"{ctx.Protocol.ToUpperInvariant()} {ctx.Server}:{ctx.ServerPort.ToString(CultureInfo.InvariantCulture)}";
            }
        }

        return ctx;
    }

    /// <summary>
    /// 从 Clash 节点字典解析上下文。
    /// </summary>
    public static NodeContext FromClash(IReadOnlyDictionary<string, object?> proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var ctx = new NodeContext();
        foreach (var kv in proxy)
        {
            ctx._properties[kv.Key] = kv.Value;
        }
        ctx.IsNativeConfig =
            proxy.ContainsKey("server_port")
            || (proxy.ContainsKey("tag") && !proxy.ContainsKey("name"));

        ctx.Protocol = ctx.GetString("type");
        ctx.Tag = ctx.GetString("name", "tag");
        ctx.Server = ctx.GetString("server");
        ctx.ServerPort = ctx.GetInt("port", "server_port");

        return ctx;
    }

    /// <summary>
    /// 依次按别名获取字符串值。
    /// </summary>
    public string GetString(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val != null)
            {
                if (val is string strVal)
                {
                    string s = strVal.Trim();
                    if (!string.IsNullOrEmpty(s))
                        return s;
                }
                else if (
                    val is not (System.Collections.IDictionary or System.Collections.IEnumerable)
                )
                {
                    string s = val.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(s))
                        return s;
                }
                else
                {
                    throw new FormatException($"Expected scalar string for {alias}");
                }
            }
        }
        return string.Empty;
    }

    /// <summary>
    /// 依次按别名获取整数值。
    /// </summary>
    public int GetInt(params string[] aliases) => GetIntWithDefault(0, aliases);

    public string GetSecretString(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? raw = ResolveValue(alias);
            if (raw is string value)
                return value;
            if (raw != null)
                throw new FormatException($"Expected string credential for {alias}");
        }
        return string.Empty;
    }

    public object? GetPacketNetwork()
    {
        object? raw = GetRaw("packet_network") ?? GetRaw("packet-network");
        if (raw == null && IsNativeConfig)
        {
            raw = GetRaw("network");
        }
        if (raw is string text)
        {
            if (text is "tcp" or "udp")
                return text;
            if (
                text
                is "ws"
                    or "websocket"
                    or "http"
                    or "h2"
                    or "grpc"
                    or "quic"
                    or "httpupgrade"
                    or "raw"
                    or "none"
            )
                return null;
            if (text.Length == 0)
                return null;
            throw new FormatException($"Unknown network: {text}");
        }
        if (raw is IEnumerable<object> list)
        {
            var values = list.Select(item => item.ToString() ?? string.Empty).ToArray();
            if (values.Any(value => value is not ("tcp" or "udp")))
                throw new FormatException("Unknown packet network");
            return values;
        }
        if (raw != null)
            throw new FormatException("Expected a packet network string or list");
        return null;
    }

    public int GetIntWithDefault(int defaultValue, params string[] aliases) =>
        GetIntNullable(aliases) ?? defaultValue;

    public long GetLong(params string[] aliases) => GetLongNullable(aliases) ?? 0;

    public long? GetLongNullable(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? value = ResolveValue(alias);
            if (value == null)
                continue;
            if (value is long number)
                return number;
            if (value is int small)
                return small;
            if (
                value is string text
                && long.TryParse(
                    text,
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out long parsed
                )
            )
                return parsed;
            throw new FormatException($"Expected int64 for {alias}");
        }
        return null;
    }

    public object? GetMemoryBytes(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? value = ResolveValue(alias);
            if (value == null)
                continue;
            if (value is string text)
                return text;
            if (value is long number)
                return number;
            if (value is int small)
                return (long)small;
            if (value is uint integer)
                return (long)integer;
            if (value is ulong unsigned && unsigned <= long.MaxValue)
                return (long)unsigned;
            throw new FormatException($"Expected int64 bytes or a size string for {alias}");
        }
        return null;
    }

    public int? GetIntNullable(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val == null)
                continue;
            if (val is int i)
                return i;
            if (val is long l && l is >= int.MinValue and <= int.MaxValue)
                return (int)l;
            if (
                int.TryParse(
                    val.ToString(),
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out int parsed
                )
            )
                return parsed;
            throw new FormatException($"Expected int32 for {alias}");
        }
        return null;
    }

    public uint? GetUIntNullable(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val == null)
                continue;

            if (val is uint u)
                return u;
            if (val is int i && i >= 0)
                return (uint)i;
            if (val is long l && l is >= 0 and <= uint.MaxValue)
                return (uint)l;

            string strVal = val.ToString()?.Trim() ?? string.Empty;
            if (
                strVal.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                && uint.TryParse(
                    strVal[2..],
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out uint hexParsed
                )
            )
            {
                return hexParsed;
            }

            if (uint.TryParse(strVal, CultureInfo.InvariantCulture, out uint parsed))
            {
                return parsed;
            }
        }
        return null;
    }

    /// <summary>
    /// 依次按别名获取布尔值。
    /// </summary>
    public bool GetBool(params string[] aliases) => GetBoolWithDefault(false, aliases);

    public bool? GetBoolNullable(params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val == null)
                continue;
            if (val is bool b)
                return b;
            string s = val.ToString()?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(s))
                continue;
            if (
                string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.Ordinal)
                || string.Equals(s, "yes", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "on", StringComparison.OrdinalIgnoreCase)
            )
                return true;
            if (
                string.Equals(s, "false", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "0", StringComparison.Ordinal)
                || string.Equals(s, "no", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "off", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "none", StringComparison.OrdinalIgnoreCase)
            )
                return false;
            if (
                string.Equals(alias, "tls", StringComparison.Ordinal)
                && string.Equals(s, "tls", StringComparison.OrdinalIgnoreCase)
            )
                return true;
            throw new FormatException($"Expected boolean for {alias}");
        }
        return null;
    }

    public bool GetBoolWithDefault(bool defaultValue, params string[] aliases) =>
        GetBoolNullable(aliases) ?? defaultValue;

    /// <summary>
    /// 依次按别名获取去重后的非空字符串列表。
    /// </summary>
    public IReadOnlyList<string> GetStringList(params string[] aliases)
    {
        var result = new List<string>();
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val == null)
                continue;

            if (val is IEnumerable<object> list)
            {
                foreach (object item in list)
                {
                    string s = item?.ToString()?.Trim() ?? string.Empty;
                    if (
                        !string.IsNullOrEmpty(s)
                        && !result.Contains(s, StringComparer.OrdinalIgnoreCase)
                    )
                        result.Add(s);
                }
                if (result.Count > 0)
                    return result;
            }
            else if (val is string str)
            {
                foreach (
                    string part in str.Split(
                        [',', ';'],
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
                    )
                )
                {
                    string s = part.Trim();
                    if (
                        !string.IsNullOrEmpty(s)
                        && !result.Contains(s, StringComparer.OrdinalIgnoreCase)
                    )
                        result.Add(s);
                }
                if (result.Count > 0)
                    return result;
            }
        }
        return result;
    }

    /// <summary>
    /// 获取子字典映射。
    /// </summary>
    public IReadOnlyDictionary<string, string> GetStringDictionary(params string[] aliases)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val is IReadOnlyDictionary<string, object?> roMap)
            {
                foreach (var kv in roMap)
                {
                    dict[kv.Key] = kv.Value?.ToString() ?? string.Empty;
                }
                if (dict.Count > 0)
                    return dict;
            }
            else if (val is IDictionary<string, object?> strMap)
            {
                foreach (var kv in strMap)
                {
                    dict[kv.Key] = kv.Value?.ToString() ?? string.Empty;
                }
                if (dict.Count > 0)
                    return dict;
            }
            else if (val is IDictionary<object, object> objMap)
            {
                foreach (var kv in objMap)
                {
                    dict[kv.Key?.ToString() ?? string.Empty] = kv.Value?.ToString() ?? string.Empty;
                }
                if (dict.Count > 0)
                    return dict;
            }
        }
        return dict;
    }

    private static string ExtractFragment(string raw, NodeContext ctx)
    {
        int fragmentIndex = raw.IndexOf('#', StringComparison.Ordinal);
        if (fragmentIndex >= 0)
        {
            ctx.Tag = SafeUrlDecode(raw[(fragmentIndex + 1)..]);
            return raw[..fragmentIndex];
        }
        return raw;
    }

    public static string SafeUrlDecode(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        string decoded = HttpUtility.UrlDecode(text);
        if (decoded.Contains('%', StringComparison.Ordinal))
        {
            try
            {
                string doubleDecoded = HttpUtility.UrlDecode(decoded);
                if (!string.Equals(doubleDecoded, decoded, StringComparison.Ordinal))
                {
                    return doubleDecoded;
                }
            }
            catch
            {
                // 忽略异常
            }
        }
        return decoded;
    }

    private static void ParseStandardUriRest(string rest, NodeContext ctx)
    {
        int queryIndex = rest.IndexOf('?', StringComparison.Ordinal);
        string hostPart = queryIndex >= 0 ? rest[..queryIndex] : rest;
        string queryPart = queryIndex >= 0 ? rest[(queryIndex + 1)..] : string.Empty;

        ParseQueryParams(queryPart, ctx);

        int atIndex = hostPart.LastIndexOf('@', StringComparison.Ordinal);
        string authPart = atIndex >= 0 ? hostPart[..atIndex] : string.Empty;
        string endpointPart = atIndex >= 0 ? hostPart[(atIndex + 1)..] : hostPart;

        if (!string.IsNullOrEmpty(authPart))
        {
            string decodedAuth = Uri.UnescapeDataString(authPart);

            // Hysteria 2、Trojan、AnyTLS 的 UserInfo 整体作为 password (避免密码含冒号被截断)
            if (
                string.Equals(ctx.Protocol, "hy2", StringComparison.OrdinalIgnoreCase)
                || string.Equals(ctx.Protocol, "hysteria2", StringComparison.OrdinalIgnoreCase)
                || string.Equals(ctx.Protocol, "trojan", StringComparison.OrdinalIgnoreCase)
                || string.Equals(ctx.Protocol, "anytls", StringComparison.OrdinalIgnoreCase)
            )
            {
                ctx._properties["password"] = decodedAuth;
                ctx._properties["auth"] = decodedAuth;
            }
            else if (string.Equals(ctx.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
            {
                ctx._properties["uuid"] = decodedAuth;
                ctx._properties["auth"] = decodedAuth;
            }
            else
            {
                int authColon = decodedAuth.IndexOf(':', StringComparison.Ordinal);
                if (authColon >= 0)
                {
                    ctx._properties["uuid"] = decodedAuth[..authColon];
                    ctx._properties["username"] = decodedAuth[..authColon];
                    ctx._properties["password"] = decodedAuth[(authColon + 1)..];
                    ctx._properties["auth"] = decodedAuth;
                }
                else
                {
                    ctx._properties["uuid"] = decodedAuth;
                    ctx._properties["password"] = decodedAuth;
                    ctx._properties["auth"] = decodedAuth;
                }
            }
        }

        ParseHostAndPort(endpointPart, ctx);
    }

    private static void ParseQueryParams(string queryPart, NodeContext ctx)
    {
        if (string.IsNullOrEmpty(queryPart))
            return;

        foreach (string pair in queryPart.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if (eq >= 0)
            {
                string key = pair[..eq].Trim();
                string val = HttpUtility.UrlDecode(pair[(eq + 1)..].Trim());
                ctx._properties[key] = val;
            }
            else
            {
                ctx._properties[pair.Trim()] = string.Empty;
            }
        }
    }

    private object? ResolveValue(string path)
    {
        if (_properties.TryGetValue(path, out object? direct))
            return direct;
        if (!path.Contains('.', StringComparison.Ordinal))
            return null;

        string[] segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
        object? current = _properties;

        foreach (string seg in segments)
        {
            if (current is IReadOnlyDictionary<string, object?> roMap)
            {
                if (!roMap.TryGetValue(seg, out current))
                    return null;
            }
            else if (current is IDictionary<string, object?> strMap)
            {
                if (!strMap.TryGetValue(seg, out current))
                    return null;
            }
            else if (current is IDictionary<object, object> objMap)
            {
                object? found = null;
                foreach (var kv in objMap)
                {
                    if (string.Equals(kv.Key?.ToString(), seg, StringComparison.OrdinalIgnoreCase))
                    {
                        found = kv.Value;
                        break;
                    }
                }
                if (found == null)
                    return null;
                current = found;
            }
            else
            {
                return null;
            }
        }

        return current;
    }

    private static void ParseShadowsocksUri(string rest, NodeContext ctx)
    {
        // 先切出 query 参数部分
        int queryIndex = rest.IndexOf('?', StringComparison.Ordinal);
        string mainPart = queryIndex >= 0 ? rest[..queryIndex] : rest;
        string queryPart = queryIndex >= 0 ? rest[(queryIndex + 1)..] : string.Empty;

        ParseQueryParams(queryPart, ctx);
        HandleSsPluginParam(ctx);

        int atIndex = mainPart.IndexOf('@', StringComparison.Ordinal);
        if (atIndex < 0)
        {
            string decoded = Base64Utils.Decode(mainPart);
            atIndex = decoded.IndexOf('@', StringComparison.Ordinal);
            if (atIndex >= 0)
            {
                ApplySsCredentials(decoded[..atIndex], ctx);
                ParseHostAndPort(decoded[(atIndex + 1)..], ctx);
            }
            return;
        }

        string userInfo = mainPart[..atIndex];
        string remainder = mainPart[(atIndex + 1)..];
        string plainUserInfo = Base64Utils.Decode(userInfo);

        ApplySsCredentials(
            plainUserInfo.Contains(':', StringComparison.Ordinal)
                ? plainUserInfo
                : Uri.UnescapeDataString(userInfo),
            ctx
        );
        ParseHostAndPort(remainder, ctx);
    }

    private static void HandleSsPluginParam(NodeContext ctx)
    {
        if (
            ctx._properties.TryGetValue("plugin", out object? pluginObj)
            && pluginObj is string pluginStr
        )
        {
            // 注意：query 解析时已经解码过一次，严禁二次解码，否则会破坏诸如 /a+b 或 /a%2Fb 等合法路径参数
            string rawPlugin = pluginStr.Trim();
            int semicolon = rawPlugin.IndexOf(';', StringComparison.Ordinal);
            if (semicolon >= 0)
            {
                ctx._properties["plugin"] = rawPlugin[..semicolon].Trim();
                ctx._properties["plugin_opts"] = rawPlugin[(semicolon + 1)..].Trim();
            }
            else
            {
                ctx._properties["plugin"] = rawPlugin;
            }
        }
    }

    private static void ApplySsCredentials(string creds, NodeContext ctx)
    {
        int colon = creds.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            ctx._properties["method"] = creds[..colon].Trim();
            ctx._properties["password"] = creds[(colon + 1)..];
        }
    }

    private static void ParseHostAndPort(string endpoint, NodeContext ctx)
    {
        // 清理末尾可能的 /?query 或 ?query（如果之前未被剥离）
        int qIdx = endpoint.IndexOf('?', StringComparison.Ordinal);
        if (qIdx >= 0)
        {
            string q = endpoint[(qIdx + 1)..];
            endpoint = endpoint[..qIdx];
            ParseQueryParams(q, ctx);
            HandleSsPluginParam(ctx);
        }

        int slash = endpoint.IndexOf('/', StringComparison.Ordinal);
        string cleaned = slash >= 0 ? endpoint[..slash] : endpoint;

        if (cleaned.StartsWith('[', StringComparison.Ordinal))
        {
            int closeBracket = cleaned.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket > 0)
            {
                ctx.Server = cleaned[1..closeBracket];
                if (closeBracket + 1 < cleaned.Length && cleaned[closeBracket + 1] == ':')
                {
                    string portStr = cleaned[(closeBracket + 2)..];
                    if (int.TryParse(portStr, CultureInfo.InvariantCulture, out int p))
                        ctx.ServerPort = p;
                }
                return;
            }
        }

        int colon = cleaned.LastIndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            ctx.Server = cleaned[..colon];
            string portStr = cleaned[(colon + 1)..];
            if (int.TryParse(portStr, CultureInfo.InvariantCulture, out int p))
            {
                ctx.ServerPort = p;
            }
            else if (
                portStr.Contains(',', StringComparison.Ordinal)
                || portStr.Contains('-', StringComparison.Ordinal)
            )
            {
                ctx.ServerPort = 0;
                ctx._properties["server_ports"] = portStr;
            }
            else
            {
                ctx.ServerPort = -1;
            }
        }
        else
        {
            ctx.Server = cleaned;
            ctx.ServerPort = 443;
        }
    }
}
