namespace ToSing.Parsers.Protocols;

using System;
using System.Collections.Generic;
using System.Text;
using ToSing.Models.Common;
using ToSing.Models.Protocols;

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
        if (port < 1 || port > 65535)
            return null;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"SS {server}:{port}";

        string method = ctx.GetString("method", "cipher");
        if (string.IsNullOrEmpty(method))
            method = "aes-256-gcm";

        string password = ctx.GetSecretString("password");
        if (
            !string.Equals(method, "none", StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(password)
        )
        {
            return null;
        }
        string plugin = ctx.GetString("plugin");
        if (
            string.Equals(plugin, "obfs", StringComparison.OrdinalIgnoreCase)
            || string.Equals(plugin, "simple-obfs", StringComparison.OrdinalIgnoreCase)
        )
        {
            plugin = "obfs-local";
        }

        string? pluginOpts = ParsePluginOptions(ctx, plugin);

        UdpOverTcpOptions? uot = null;
        if (ctx.GetRaw("udp_over_tcp") is { } nativeUot && NativeOptionsParser.IsObject(nativeUot))
        {
            uot = NativeOptionsParser.Deserialize<UdpOverTcpOptions>(nativeUot);
        }
        else if (ctx.IsNativeConfig && ctx.GetRaw("udp_over_tcp") is bool enabled)
        {
            uot = new UdpOverTcpOptions { Enabled = enabled };
        }
        else if (ctx.GetBool("udp_over_tcp", "udp-over-tcp", "uot"))
        {
            int ver = ctx.GetInt("uot_version", "uot-version");
            uot = new UdpOverTcpOptions { Enabled = true, Version = ver > 0 ? ver : 2 };
        }

        OutboundMultiplexOptions? multiplex = MultiplexParser.ParseMultiplex(ctx);

        return new ShadowsocksOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Network = ctx.GetPacketNetwork(),
            Method = method,
            Password = password,
            Plugin = !string.IsNullOrEmpty(plugin) ? plugin : null,
            PluginOptions = pluginOpts,
            UdpOverTcp = uot,
            Multiplex = multiplex,
        };
    }

    private static string? ParsePluginOptions(NodeContext ctx, string plugin)
    {
        object? raw = ctx.GetRaw("plugin_opts") ?? ctx.GetRaw("plugin-opts");
        if (raw == null)
            return null;

        if (raw is string rawStr && !string.IsNullOrWhiteSpace(rawStr))
        {
            return rawStr.Trim();
        }

        if (ctx.HasProperty("server_port") && raw is not string)
            throw new FormatException("Native plugin_opts must be a SIP003 string");

        bool isObfs = string.Equals(plugin, "obfs-local", StringComparison.OrdinalIgnoreCase);

        if (raw is IReadOnlyDictionary<string, object?> roDict)
        {
            return SerializeSip003Options(roDict, isObfs);
        }

        if (raw is IDictionary<string, object?> strDict)
        {
            return SerializeSip003Options(strDict, isObfs);
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
            return SerializeSip003Options(converted, isObfs);
        }

        return null;
    }

    private static string? SerializeSip003Options(
        IEnumerable<KeyValuePair<string, object?>> dict,
        bool isObfs
    )
    {
        var parts = new List<string>();
        foreach (var kv in dict)
        {
            string key = kv.Key;
            object? val = kv.Value;

            if (val is null)
                continue;

            if (isObfs)
            {
                if (string.Equals(key, "mode", StringComparison.OrdinalIgnoreCase))
                    key = "obfs";
                else if (string.Equals(key, "host", StringComparison.OrdinalIgnoreCase))
                    key = "obfs-host";
            }

            if (string.Equals(key, "mux", StringComparison.OrdinalIgnoreCase))
            {
                if (val is bool bMux)
                {
                    if (bMux)
                    {
                        parts.Add("mux=1");
                    }
                    continue;
                }
                string sMux = val.ToString()?.Trim() ?? string.Empty;
                if (string.Equals(sMux, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(sMux, "1", StringComparison.Ordinal))
                {
                    parts.Add("mux=1");
                    continue;
                }
                if (string.Equals(sMux, "false", StringComparison.OrdinalIgnoreCase) || string.Equals(sMux, "0", StringComparison.Ordinal))
                {
                    continue;
                }
            }

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
        if (string.IsNullOrEmpty(text))
            return string.Empty;
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
        if (string.IsNullOrEmpty(text))
            return string.Empty;
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
