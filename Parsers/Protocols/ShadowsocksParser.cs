namespace SubParser.Parsers.Protocols;

using System;
using System.Collections.Generic;
using System.Text;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// Shadowsocks 协议解析器。
/// </summary>
public static class ShadowsocksParser
{
    public static ShadowsocksOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"SS {server}:{port}";

        string method = ctx.GetString("method", "cipher");
        if (string.IsNullOrEmpty(method)) method = "aes-256-gcm";

        string password = ctx.GetString("password");
        string plugin = ctx.GetString("plugin");
        string? pluginOpts = ParsePluginOptions(ctx);

        UdpOverTcpOptions? uot = null;
        if (ctx.GetBool("udp_over_tcp", "udp-over-tcp", "uot"))
        {
            int ver = ctx.GetInt("uot_version", "uot-version");
            uot = new UdpOverTcpOptions
            {
                Enabled = true,
                Version = ver > 0 ? ver : 2
            };
        }

        OutboundMultiplexOptions? multiplex = null;
        if (ctx.GetBool("mux", "smux.enabled"))
        {
            multiplex = new OutboundMultiplexOptions
            {
                Enabled = true,
                Protocol = "smux"
            };
        }

        return new ShadowsocksOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Method = method,
            Password = password,
            Plugin = !string.IsNullOrEmpty(plugin) ? plugin : null,
            PluginOptions = pluginOpts,
            UdpOverTcp = uot,
            Multiplex = multiplex
        };
    }

    private static string? ParsePluginOptions(NodeContext ctx)
    {
        object? raw = ctx.GetRaw("plugin_opts") ?? ctx.GetRaw("plugin-opts");
        if (raw == null) return null;

        if (raw is string rawStr && !string.IsNullOrWhiteSpace(rawStr))
        {
            return rawStr.Trim();
        }

        if (raw is IReadOnlyDictionary<string, object?> roDict)
        {
            return SerializeSip003Options(roDict);
        }

        if (raw is IDictionary<string, object?> strDict)
        {
            return SerializeSip003Options(strDict);
        }

        if (raw is IDictionary<object, object> objDict)
        {
            var converted = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in objDict)
            {
                if (kv.Key != null)
                {
                    converted[kv.Key.ToString()!] = kv.Value;
                }
            }
            return SerializeSip003Options(converted);
        }

        return null;
    }

    private static string? SerializeSip003Options(IEnumerable<KeyValuePair<string, object?>> dict)
    {
        var parts = new List<string>();
        foreach (var kv in dict)
        {
            string key = kv.Key;
            object? val = kv.Value;

            if (val is null) continue;

            if (val is bool b)
            {
                if (b)
                {
                    parts.Add(EscapeSip003Key(key));
                }
                // 布尔 false 时绝对不输出该 key
                continue;
            }

            string strVal = val.ToString() ?? string.Empty;

            // 特殊的 Flag 开关属性（如 tls），其值为 false 时必须抑制，为 true 时输出裸 key
            if (string.Equals(key, "tls", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(strVal, "false", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (string.Equals(strVal, "true", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(EscapeSip003Key(key));
                    continue;
                }
            }

            string escapedKey = EscapeSip003Key(key);
            string escapedVal = EscapeSip003Value(strVal);
            parts.Add($"{escapedKey}={escapedVal}");
        }

        return parts.Count > 0 ? string.Join(";", parts) : null;
    }

    private static string EscapeSip003Key(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var sb = new StringBuilder(text.Length + 4);
        foreach (char c in text)
        {
            if (c is ';' or '=' or '\\')
            {
                sb.Append('\\');
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static string EscapeSip003Value(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var sb = new StringBuilder(text.Length + 4);
        foreach (char c in text)
        {
            // 内核 sip003/args.go: value 的终止符仅有 ';'，因此只需转义 ';' 和 '\'
            if (c is ';' or '\\')
            {
                sb.Append('\\');
            }
            sb.Append(c);
        }
        return sb.ToString();
    }
}
