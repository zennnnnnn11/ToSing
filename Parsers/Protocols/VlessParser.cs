namespace SubParser.Parsers.Protocols;

using System;
using System.Collections.Generic;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// VLESS 协议解析器。
/// </summary>
public static class VlessParser
{
    public static VlessOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;

        string uuid = ctx.GetString("uuid", "password");
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"VLESS {server}:{port}";
        string flow = ctx.GetString("flow");

        var transport = ParseTransport(ctx);
        if (transport != null && !string.IsNullOrEmpty(flow))
        {
            flow = string.Empty;
        }

        var tls = ParseTls(ctx, server);
        string packetEncoding = ParsePacketEncoding(ctx);
        var multiplex = ParseMultiplex(ctx);

        return new VlessOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Uuid = uuid,
            Flow = !string.IsNullOrEmpty(flow) ? flow : null,
            Tls = tls,
            Transport = transport,
            PacketEncoding = !string.IsNullOrEmpty(packetEncoding) ? packetEncoding : null,
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
        if (string.Equals(netType, "http", StringComparison.Ordinal) ||
            string.Equals(netType, "h2", StringComparison.Ordinal) ||
            string.Equals(netType, "httpupgrade", StringComparison.Ordinal))
        {
            string path = ctx.GetString("path", "http-opts.path");
            return new V2RayTransportOptions
            {
                Type = netType,
                Path = !string.IsNullOrEmpty(path) ? path : null
            };
        }
        return null;
    }

    private static OutboundTLSOptions? ParseTls(NodeContext ctx, string server)
    {
        string security = ctx.GetString("security").ToLowerInvariant();
        string pbk = ctx.GetString("pbk", "public-key", "reality-opts.public-key");
        bool hasTls = ctx.GetBool("tls") ||
                      string.Equals(security, "tls", StringComparison.Ordinal) ||
                      string.Equals(security, "reality", StringComparison.Ordinal) ||
                      !string.IsNullOrEmpty(pbk);

        if (!hasTls) return null;

        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        OutboundRealityOptions? reality = null;
        if (string.Equals(security, "reality", StringComparison.Ordinal) || !string.IsNullOrEmpty(pbk))
        {
            string sid = ctx.GetString("sid", "short-id", "reality-opts.short-id");
            reality = new OutboundRealityOptions
            {
                Enabled = true,
                PublicKey = pbk,
                ShortId = !string.IsNullOrEmpty(sid) ? sid : null
            };
        }

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null,
            Reality = reality
        };
    }

    private static string ParsePacketEncoding(NodeContext ctx)
    {
        string pe = ctx.GetString("packet_encoding", "packet-encoding");
        if (!string.IsNullOrEmpty(pe)) return pe;
        if (ctx.GetBool("xudp")) return "xudp";
        if (ctx.GetBool("packet-addr")) return "packetaddr";
        return string.Empty;
    }

    private static OutboundMultiplexOptions? ParseMultiplex(NodeContext ctx)
    {
        if (!ctx.GetBool("mux", "smux.enabled")) return null;
        int mc = ctx.GetInt("smux.max-connections", "mux.max-connections");
        return new OutboundMultiplexOptions
        {
            Enabled = true,
            Protocol = "smux",
            MaxConnections = mc > 0 ? mc : null
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
