namespace SubParser.Parsers.Protocols;

using System;
using System.Collections.Generic;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// Trojan 协议节点解析与装配器
/// </summary>
public static class TrojanParser
{
    public static TrojanOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"Trojan {server}:{port}";
        string password = ctx.GetString("password", "auth");

        var transport = ParseTransport(ctx);
        var tls = ParseTls(ctx, server);
        var multiplex = ParseMultiplex(ctx);

        return new TrojanOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            Tls = tls,
            Transport = transport,
            Multiplex = multiplex
        };
    }

    private static V2RayTransportOptions? ParseTransport(NodeContext ctx)
    {
        string netType = GetTransportNetType(ctx);
        if (string.Equals(netType, "ws", StringComparison.Ordinal) || string.Equals(netType, "websocket", StringComparison.Ordinal))
        {
            string path = SanitizeWsPath(ctx.GetString("path", "ws-opts.path", "ws-path"));
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string host = ctx.GetString("host", "ws-opts.headers.Host", "ws-headers.Host");
            if (!string.IsNullOrEmpty(host)) headers["Host"] = host;

            return new V2RayTransportOptions
            {
                Type = "ws",
                Path = path,
                Headers = headers.Count > 0 ? headers : null
            };
        }
        if (string.Equals(netType, "grpc", StringComparison.Ordinal))
        {
            string serviceName = ctx.GetString("serviceName", "service-name", "grpc-opts.grpc-service-name");
            return new V2RayTransportOptions
            {
                Type = "grpc",
                ServiceName = !string.IsNullOrEmpty(serviceName) ? serviceName : null
            };
        }
        return null;
    }

    private static OutboundTLSOptions ParseTls(NodeContext ctx, string server)
    {
        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SubParser.Utils.SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
        };
    }

    private static OutboundMultiplexOptions? ParseMultiplex(NodeContext ctx)
    {
        if (!ctx.GetBool("mux", "smux.enabled")) return null;
        return new OutboundMultiplexOptions
        {
            Enabled = true,
            Protocol = "smux"
        };
    }

    private static string SanitizeWsPath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return "/";
        string path = rawPath.Trim();
        int qIndex = path.IndexOf('?', StringComparison.Ordinal);
        if (qIndex >= 0)
        {
            path = path[..qIndex];
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
            string.Equals(type, "httpupgrade", StringComparison.OrdinalIgnoreCase))
        {
            return type.ToLowerInvariant();
        }
        return string.Empty;
    }
}
