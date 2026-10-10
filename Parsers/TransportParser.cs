namespace SubParser.Parsers;

using System;
using System.Collections.Generic;
using System.Linq;
using SubParser.Models.Common;

internal static class TransportParser
{
    public static V2RayTransportOptions? ParseTransport(NodeContext ctx)
    {
        string netType = GetTransportNetType(ctx);
        if (string.IsNullOrEmpty(netType)) return null;

        return netType switch
        {
            "ws" or "websocket" => ParseWebsocket(ctx),
            "http" or "h2" => ParseHttp(ctx),
            "httpupgrade" => ParseHttpUpgrade(ctx),
            "grpc" => ParseGrpc(ctx),
            "quic" => new V2RayTransportOptions { Type = "quic" },
            _ => null
        };
    }

    private static V2RayTransportOptions ParseWebsocket(NodeContext ctx)
    {
        string path = ParsePath(GetPathString(ctx, "path", "ws-opts.path", "ws-path"));
        var headers = ParseHeaders(ctx, "ws-opts.headers", "ws-headers");
        string host = ctx.GetString("host", "ws-opts.headers.Host", "ws-headers.Host");
        if (!string.IsNullOrEmpty(host) && !headers.ContainsKey("Host"))
        {
            headers["Host"] = host;
        }

        int med = ctx.GetInt("max_early_data", "ws-opts.max-early-data", "max-early-data");
        string edhn = ctx.GetString("early_data_header_name", "ws-opts.early-data-header-name", "early-data-header-name");

        return new V2RayTransportOptions
        {
            Type = "ws",
            Path = path,
            Headers = headers.Count > 0 ? headers : null,
            MaxEarlyData = med > 0 ? (uint)med : null,
            EarlyDataHeaderName = !string.IsNullOrEmpty(edhn) ? edhn : null
        };
    }

    private static V2RayTransportOptions ParseHttp(NodeContext ctx)
    {
        string path = ParsePath(GetPathString(ctx, "path", "http-opts.path"));
        string method = ctx.GetString("method", "http-opts.method");
        var headers = ParseHeaders(ctx, "http-opts.headers");
        object? hostVal = ctx.GetRaw("http-opts.headers.Host") ?? ctx.GetRaw("http-opts.host") ?? ctx.GetRaw("host");

        if (hostVal != null)
        {
            headers.Remove("Host");
        }

        return new V2RayTransportOptions
        {
            Type = "http",
            Path = !string.IsNullOrEmpty(path) ? path : null,
            Method = !string.IsNullOrEmpty(method) ? method : null,
            Host = hostVal,
            Headers = headers.Count > 0 ? headers : null
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
            Headers = headers.Count > 0 ? headers : null
        };
    }

    private static V2RayTransportOptions ParseGrpc(NodeContext ctx)
    {
        string serviceName = ctx.GetString("serviceName", "service-name", "grpc-opts.grpc-service-name");
        return new V2RayTransportOptions
        {
            Type = "grpc",
            ServiceName = !string.IsNullOrEmpty(serviceName) ? serviceName : null
        };
    }

    private static string GetPathString(NodeContext ctx, params string[] aliases)
    {
        foreach (string alias in aliases)
        {
            object? val = ctx.GetRaw(alias);
            if (val == null) continue;

            if (val is IEnumerable<object> list)
            {
                foreach (object item in list)
                {
                    string s = item?.ToString()?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(s)) return s;
                }
            }
            else if (val is string str && !string.IsNullOrWhiteSpace(str))
            {
                return str.Trim();
            }
        }
        return string.Empty;
    }

    private static Dictionary<string, string> ParseHeaders(NodeContext ctx, params string[] paths)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string p in paths)
        {
            object? raw = ctx.GetRaw(p);
            if (raw is IReadOnlyDictionary<string, object?> roDict)
            {
                foreach (var kv in roDict)
                {
                    if (string.IsNullOrEmpty(kv.Key) || kv.Value == null) continue;
                    if (kv.Value is IEnumerable<object> list)
                    {
                        var first = list.FirstOrDefault(x => x != null)?.ToString()?.Trim();
                        if (!string.IsNullOrEmpty(first)) dict[kv.Key] = first;
                    }
                    else
                    {
                        string s = kv.Value.ToString()?.Trim() ?? string.Empty;
                        if (!string.IsNullOrEmpty(s)) dict[kv.Key] = s;
                    }
                }
            }
            else
            {
                var d = ctx.GetStringDictionary(p);
                foreach (var kv in d)
                {
                    if (!string.IsNullOrEmpty(kv.Key) && !string.IsNullOrEmpty(kv.Value)) dict[kv.Key] = kv.Value;
                }
            }
        }
        return dict;
    }

    private static string ParsePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return "/";
        string path = rawPath.Trim();

        if (path.Contains("?ed=", StringComparison.OrdinalIgnoreCase))
        {
            int edIndex = path.IndexOf("?ed=", StringComparison.OrdinalIgnoreCase);
            path = path[..edIndex];
        }

        if (path.Length == 0 || path[0] != '/')
        {
            path = "/" + path;
        }
        return string.IsNullOrWhiteSpace(path) ? "/" : path;
    }

    private static string GetTransportNetType(NodeContext ctx)
    {
        string net = ctx.GetString("network", "net");
        if (!string.IsNullOrEmpty(net)) return net.ToLowerInvariant();

        string type = ctx.GetString("type");
        if (string.Equals(type, "ws", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "websocket", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "grpc", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "http", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "h2", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "httpupgrade", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(type, "quic", StringComparison.OrdinalIgnoreCase))
        {
            return type.ToLowerInvariant();
        }
        return string.Empty;
    }
}
