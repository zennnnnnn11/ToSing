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
    private readonly Dictionary<string, object?> _properties = new(StringComparer.OrdinalIgnoreCase);

    public string Protocol { get; set; } = string.Empty;
    public string Tag { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public int ServerPort { get; set; }

    public IReadOnlyDictionary<string, object?> Properties => _properties;

    public void SetProperty(string key, object? value)
    {
        _properties[key] = value;
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
            return ctx;
        }

        ParseStandardUriRest(rest, ctx);

        if (string.IsNullOrWhiteSpace(ctx.Tag))
        {
            ctx.Tag = ctx.GetString("remarks", "remark");
            if (string.IsNullOrWhiteSpace(ctx.Tag))
            {
                ctx.Tag = $"{ctx.Protocol.ToUpperInvariant()} {ctx.Server}:{ctx.ServerPort.ToString(CultureInfo.InvariantCulture)}";
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

        ctx.Protocol = ctx.GetString("type");
        ctx.Tag = ctx.GetString("name");
        ctx.Server = ctx.GetString("server");
        ctx.ServerPort = ctx.GetInt("port");

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
                    if (!string.IsNullOrEmpty(s)) return s;
                }
                else if (val is not (System.Collections.IDictionary or System.Collections.IEnumerable))
                {
                    string s = val.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(s)) return s;
                }
            }
        }
        return string.Empty;
    }

    /// <summary>
    /// 依次按别名获取整数值。
    /// </summary>
    public int GetInt(params string[] aliases) => GetIntWithDefault(0, aliases);

    public int GetIntWithDefault(int defaultValue, params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val != null)
            {
                if (val is int i) return i;
                if (val is long l) return (int)l;
                if (int.TryParse(val.ToString(), CultureInfo.InvariantCulture, out int parsed))
                {
                    return parsed;
                }
                string strVal = val.ToString()?.Trim() ?? string.Empty;
                if (double.TryParse(strVal, CultureInfo.InvariantCulture, out double d) && !double.IsNaN(d) && !double.IsInfinity(d))
                {
                    return (int)d;
                }
            }
        }
        return defaultValue;
    }

    /// <summary>
    /// 依次按别名获取布尔值。
    /// </summary>
    public bool GetBool(params string[] aliases) => GetBoolWithDefault(false, aliases);

    public bool GetBoolWithDefault(bool defaultValue, params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val != null)
            {
                if (val is bool b) return b;
                string s = val.ToString()?.Trim() ?? string.Empty;
                if (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(s, "1", StringComparison.Ordinal))
                {
                    return true;
                }
                if (string.Equals(s, "false", StringComparison.OrdinalIgnoreCase) || string.Equals(s, "0", StringComparison.Ordinal))
                {
                    return false;
                }
            }
        }
        return defaultValue;
    }

    /// <summary>
    /// 依次按别名获取去重后的非空字符串列表。
    /// </summary>
    public IReadOnlyList<string> GetStringList(params string[] aliases)
    {
        var result = new List<string>();
        foreach (string alias in aliases)
        {
            object? val = ResolveValue(alias);
            if (val == null) continue;

            if (val is IEnumerable<object> list)
            {
                foreach (object item in list)
                {
                    string s = item?.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(s) && !result.Contains(s, StringComparer.OrdinalIgnoreCase)) result.Add(s);
                }
                if (result.Count > 0) return result;
            }
            else if (val is string str)
            {
                foreach (string part in str.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    string s = part.Trim();
                    if (!string.IsNullOrEmpty(s) && !result.Contains(s, StringComparer.OrdinalIgnoreCase)) result.Add(s);
                }
                if (result.Count > 0) return result;
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
                if (dict.Count > 0) return dict;
            }
            else if (val is IDictionary<object, object> objMap)
            {
                foreach (var kv in objMap)
                {
                    dict[kv.Key?.ToString() ?? string.Empty] = kv.Value?.ToString() ?? string.Empty;
                }
                if (dict.Count > 0) return dict;
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
        if (string.IsNullOrEmpty(text)) return string.Empty;
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

        if (!string.IsNullOrEmpty(queryPart))
        {
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

        int atIndex = hostPart.LastIndexOf('@', StringComparison.Ordinal);
        string authPart = atIndex >= 0 ? hostPart[..atIndex] : string.Empty;
        string endpointPart = atIndex >= 0 ? hostPart[(atIndex + 1)..] : hostPart;

        if (!string.IsNullOrEmpty(authPart))
        {
            string decodedAuth = HttpUtility.UrlDecode(authPart);
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

        ParseHostAndPort(endpointPart, ctx);
    }

    private object? ResolveValue(string path)
    {
        if (_properties.TryGetValue(path, out object? direct)) return direct;
        if (!path.Contains('.', StringComparison.Ordinal)) return null;

        string[] segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
        object? current = _properties;

        foreach (string seg in segments)
        {
            if (current is IReadOnlyDictionary<string, object?> roMap)
            {
                if (!roMap.TryGetValue(seg, out current)) return null;
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
                if (found == null) return null;
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
        int atIndex = rest.IndexOf('@', StringComparison.Ordinal);
        if (atIndex < 0)
        {
            string decoded = Base64Utils.Decode(rest);
            atIndex = decoded.IndexOf('@', StringComparison.Ordinal);
            if (atIndex >= 0)
            {
                ApplySsCredentials(decoded[..atIndex], ctx);
                ParseHostAndPort(decoded[(atIndex + 1)..], ctx);
            }
            return;
        }

        string userInfo = rest[..atIndex];
        string remainder = rest[(atIndex + 1)..];
        string plainUserInfo = Base64Utils.Decode(userInfo);

        ApplySsCredentials(plainUserInfo.Contains(':', StringComparison.Ordinal) ? plainUserInfo : userInfo, ctx);
        ParseHostAndPort(remainder, ctx);
    }

    private static void ApplySsCredentials(string creds, NodeContext ctx)
    {
        int colon = creds.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            ctx._properties["method"] = creds[..colon].Trim();
            ctx._properties["password"] = creds[(colon + 1)..].Trim();
        }
    }

    private static void ParseHostAndPort(string endpoint, NodeContext ctx)
    {
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
                    if (int.TryParse(portStr, CultureInfo.InvariantCulture, out int p)) ctx.ServerPort = p;
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
