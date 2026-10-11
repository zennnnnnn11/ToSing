namespace SubParser.Parsers;

using System;
using System.Collections.Generic;
using System.Linq;
using SubParser.Models.Common;

internal static class TransportParser
{
    public static V2RayTransportOptions? ParseTransport(NodeContext ctx)
    {
        if (ctx.GetRaw("transport") is { } native && NativeOptionsParser.IsObject(native))
        {
            return NativeOptionsParser.Deserialize<V2RayTransportOptions>(native);
        }
        string netType = GetTransportNetType(ctx);
        if (string.IsNullOrEmpty(netType))
            return null;

        return netType switch
        {
            "ws" or "websocket" => ParseWebsocket(ctx),
            "http" or "h2" => ParseHttp(ctx),
            "httpupgrade" => ParseHttpUpgrade(ctx),
            "grpc" => ParseGrpc(ctx),
            "quic" => new V2RayTransportOptions { Type = "quic" },
            _ => null,
        };
    }

    private static V2RayTransportOptions ParseWebsocket(NodeContext ctx)
    {
        string rawPath = GetPathString(ctx, "path", "ws-opts.path", "ws-path", "wspath");
        var (path, earlyDataFromPath) = ParseWebsocketPath(rawPath);
        var headers = ParseHeaders(ctx, "ws-opts.headers", "ws-headers");
        string host = ctx.GetString("host", "ws-opts.headers.Host", "ws-headers.Host");
        if (!string.IsNullOrEmpty(host) && !headers.ContainsKey("Host"))
        {
            headers["Host"] = host;
        }

        uint? med =
            ctx.GetUIntNullable(
                "max_early_data",
                "ws-opts.max-early-data",
                "max-early-data",
                "early_data",
                "ed"
            ) ?? earlyDataFromPath;
        string edhn = ctx.GetString(
            "early_data_header_name",
            "ws-opts.early-data-header-name",
            "early-data-header-name",
            "eh"
        );
        if (med > 0 && string.IsNullOrEmpty(edhn))
        {
            edhn = "Sec-WebSocket-Protocol";
        }

        return new V2RayTransportOptions
        {
            Type = "ws",
            Path = path,
            Headers = headers.Count > 0 ? headers : null,
            MaxEarlyData = med > 0 ? med : null,
            EarlyDataHeaderName = !string.IsNullOrEmpty(edhn) ? edhn : null,
        };
    }

    private static V2RayTransportOptions ParseHttp(NodeContext ctx)
    {
        string path = ParsePath(GetPathString(ctx, "path", "http-opts.path", "h2-opts.path"));
        string method = ctx.GetString("method", "http-opts.method");
        var headers = ParseHeaders(ctx, "http-opts.headers");
        object? hostVal =
            ctx.GetRaw("http-opts.headers.Host")
            ?? ctx.GetRaw("http-opts.host")
            ?? ctx.GetRaw("h2-opts.headers.Host")
            ?? ctx.GetRaw("h2-opts.host")
            ?? ctx.GetRaw("host");

        if (hostVal != null)
        {
            headers.Remove("Host");
        }

        string idleTimeout = ctx.GetString(
            "idle_timeout",
            "idle-timeout",
            "http-opts.idle_timeout",
            "http-opts.idle-timeout"
        );
        string pingTimeout = ctx.GetString(
            "ping_timeout",
            "ping-timeout",
            "http-opts.ping_timeout",
            "http-opts.ping-timeout"
        );

        return new V2RayTransportOptions
        {
            Type = "http",
            Path = !string.IsNullOrEmpty(path) ? path : null,
            Method = !string.IsNullOrEmpty(method) ? method : null,
            Host = hostVal,
            Headers = headers.Count > 0 ? headers : null,
            IdleTimeout = !string.IsNullOrEmpty(idleTimeout) ? idleTimeout : null,
            PingTimeout = !string.IsNullOrEmpty(pingTimeout) ? pingTimeout : null,
        };
    }

    private static V2RayTransportOptions ParseHttpUpgrade(NodeContext ctx)
    {
        string path = ParsePath(GetPathString(ctx, "path", "httpupgrade-opts.path"));
        string host = ctx.GetString("host", "httpupgrade-opts.host");
        var headers = ParseHeaders(ctx, "httpupgrade-opts.headers");

        return new V2RayTransportOptions
        {
            Type = "httpupgrade",
            Path = !string.IsNullOrEmpty(path) ? path : null,
            Host = !string.IsNullOrEmpty(host) ? host : null,
            Headers = headers.Count > 0 ? headers : null,
        };
    }

    private static V2RayTransportOptions ParseGrpc(NodeContext ctx)
    {
        string serviceName = ctx.GetString(
            "serviceName",
            "service-name",
            "grpc-opts.grpc-service-name",
            "grpc-opts.service_name",
            "grpc-opts.service-name",
            "path"
        );
        string idleTimeout = ctx.GetString(
            "idle_timeout",
            "idle-timeout",
            "grpc-opts.idle_timeout",
            "grpc-opts.idle-timeout"
        );
        string pingTimeout = ctx.GetString(
            "ping_timeout",
            "ping-timeout",
            "grpc-opts.ping_timeout",
            "grpc-opts.ping-timeout"
        );
        bool permitWithoutStream = ctx.GetBool(
            "permit_without_stream",
            "permit-without-stream",
            "grpc-opts.permit_without_stream",
            "grpc-opts.permit-without-stream"
        );

        return new V2RayTransportOptions
        {
            Type = "grpc",
            ServiceName = !string.IsNullOrEmpty(serviceName) ? serviceName : null,
            IdleTimeout = !string.IsNullOrEmpty(idleTimeout) ? idleTimeout : null,
            PingTimeout = !string.IsNullOrEmpty(pingTimeout) ? pingTimeout : null,
            PermitWithoutStream = permitWithoutStream,
        };
    }

    private static string GetPathString(NodeContext ctx, params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ctx.GetRaw(alias);
            if (val == null)
                continue;

            if (val is IEnumerable<object> list)
            {
                foreach (object item in list)
                {
                    string s = item?.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(s))
                        return s;
                }
            }
            else if (val is string str && !string.IsNullOrWhiteSpace(str))
            {
                return str.Trim();
            }
        }
        return string.Empty;
    }

    private static Dictionary<string, object> ParseHeaders(NodeContext ctx, params string[] paths)
    {
        var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (string p in paths)
        {
            object? raw = ctx.GetRaw(p);
            if (raw is IReadOnlyDictionary<string, object?> roDict)
            {
                foreach (var kv in roDict)
                {
                    if (string.IsNullOrEmpty(kv.Key) || kv.Value == null)
                        continue;
                    dict[kv.Key] = NormalizeHeaderValue(kv.Value);
                }
            }
            else if (raw is IDictionary<string, object?> sDict)
            {
                foreach (var kv in sDict)
                {
                    if (string.IsNullOrEmpty(kv.Key) || kv.Value == null)
                        continue;
                    dict[kv.Key] = NormalizeHeaderValue(kv.Value);
                }
            }
            else
            {
                var d = ctx.GetStringDictionary(p);
                foreach (var kv in d)
                {
                    if (!string.IsNullOrEmpty(kv.Key) && !string.IsNullOrEmpty(kv.Value))
                        dict[kv.Key] = kv.Value;
                }
            }
        }
        return dict;
    }

    private static object NormalizeHeaderValue(object val)
    {
        if (val is IEnumerable<object> list && val is not string)
        {
            var strList = new List<string>();
            foreach (object item in list)
            {
                string s = item?.ToString()?.Trim() ?? string.Empty;
                if (!string.IsNullOrEmpty(s))
                    strList.Add(s);
            }
            return strList.ToArray();
        }

        return val.ToString()?.Trim() ?? string.Empty;
    }

    private static (string Path, uint? EarlyData) ParseWebsocketPath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
            return ("/", null);

        string p = rawPath.Trim();

        // 1. 如果路径以 URL 转义的斜杠开头 (例如 %2F 或 %2f)，先还原为 /
        if (p.StartsWith("%2F", StringComparison.OrdinalIgnoreCase))
        {
            p = "/" + p[3..];
        }

        // 剔除 URL 中的 #fragment
        int hashIdx = p.IndexOf('#', StringComparison.Ordinal);
        if (hashIdx >= 0)
        {
            p = p[..hashIdx];
        }

        uint? earlyData = null;

        int qIdx = p.IndexOf('?', StringComparison.Ordinal);
        if (qIdx >= 0)
        {
            string pathBase = p[..qIdx];
            string queryString = p[(qIdx + 1)..];

            string[] queryPairs = queryString.Split('&', StringSplitOptions.RemoveEmptyEntries);
            var retainedPairs = new List<string>(queryPairs.Length);

            foreach (string pair in queryPairs)
            {
                if (pair.StartsWith("ed=", StringComparison.OrdinalIgnoreCase))
                {
                    string edVal = pair[3..];
                    int endIdx = edVal.IndexOfAny([';', '&', '?', '#']);
                    if (endIdx >= 0)
                    {
                        edVal = edVal[..endIdx];
                    }

                    if (
                        uint.TryParse(
                            edVal,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out uint parsed
                        )
                    )
                    {
                        earlyData = parsed;
                    }
                    else
                    {
                        // 如果 ed 参数无法解析为数字 (如 ed=oops)，原样保留在 query 中
                        retainedPairs.Add(pair);
                    }
                }
                else
                {
                    retainedPairs.Add(pair);
                }
            }

            p =
                retainedPairs.Count > 0
                    ? $"{pathBase}?{string.Join("&", retainedPairs)}"
                    : pathBase;
        }

        if (p.Length == 0 || p[0] != '/')
        {
            p = "/" + p;
        }

        return (string.IsNullOrWhiteSpace(p) ? "/" : p, earlyData);
    }

    private static string ParsePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
            return "/";
        string path = rawPath.Trim();
        if (path.StartsWith("%2F", StringComparison.OrdinalIgnoreCase))
        {
            path = "/" + path[3..];
        }
        int hashIdx = path.IndexOf('#', StringComparison.Ordinal);
        if (hashIdx >= 0)
        {
            path = path[..hashIdx];
        }
        if (path.Length == 0 || path[0] != '/')
        {
            path = "/" + path;
        }
        return string.IsNullOrWhiteSpace(path) ? "/" : path;
    }

    private static string GetTransportNetType(NodeContext ctx)
    {
        string net =
            ctx.GetRaw("network") is string
                ? ctx.GetString("network", "net")
                : ctx.GetString("net");
        if (!string.IsNullOrEmpty(net))
            return net.ToLowerInvariant();

        if (ctx.GetString("ws") is "1" or "true" || !string.IsNullOrEmpty(ctx.GetString("wspath")))
        {
            return "ws";
        }

        string type = ctx.GetString("type");
        if (
            string.Equals(type, "ws", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "websocket", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "grpc", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "http", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "h2", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "httpupgrade", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "quic", StringComparison.OrdinalIgnoreCase)
        )
        {
            return type.ToLowerInvariant();
        }
        return string.Empty;
    }
}
