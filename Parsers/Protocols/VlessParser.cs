namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// VLESS 协议解析器。
/// </summary>
public static class VlessParser
{
    public static VlessOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string uuid = ctx.GetString("uuid", "password");
        if (string.IsNullOrWhiteSpace(uuid)) return null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"VLESS {server}:{port}";
        string rawFlow = ctx.GetString("flow").Trim();
        string flow = string.Empty;

        if (!string.IsNullOrEmpty(rawFlow))
        {
            string lowerFlow = rawFlow.ToLowerInvariant();
            if (string.Equals(lowerFlow, "xtls-rprx-vision", StringComparison.Ordinal) ||
                string.Equals(lowerFlow, "xtls-rprx-vision-udp443", StringComparison.Ordinal))
            {
                // 内核只支持小写标准 xtls-rprx-vision
                flow = "xtls-rprx-vision";
            }
            else
            {
                // 未知 flow 直接拦截丢弃
                return null;
            }
        }

        var transport = TransportParser.ParseTransport(ctx);
        if (transport != null && !string.IsNullOrEmpty(flow))
        {
            flow = string.Empty;
        }

        var (packetEncoding, peValid) = ParsePacketEncoding(ctx);
        if (!peValid)
        {
            return null;
        }

        var tls = ParseTls(ctx, server);
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
            PacketEncoding = packetEncoding,
            Multiplex = multiplex
        };
    }

    private static (string? pe, bool isValid) ParsePacketEncoding(NodeContext ctx)
    {
        if (ctx.HasProperty("packet_encoding") || ctx.HasProperty("packet-encoding"))
        {
            string pe = ctx.GetString("packet_encoding", "packet-encoding");
            if (string.IsNullOrEmpty(pe))
            {
                // 显式提供空字符串 packet_encoding=""
                return ("", true);
            }
            if (string.Equals(pe, "xudp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pe, "packetaddr", StringComparison.OrdinalIgnoreCase))
            {
                return (pe.ToLowerInvariant(), true);
            }
            // 未知值非法
            return (null, false);
        }

        if (ctx.GetBool("xudp")) return ("xudp", true);
        if (ctx.GetBool("packet-addr")) return ("packetaddr", true);

        // 未提供时为 null（sing-box 默认行为）
        return (null, true);
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
        bool disableSni = ctx.GetBool("disable_sni", "disable-sni");
        string minVersion = ctx.GetString("min_version", "min-version");
        string maxVersion = ctx.GetString("max_version", "max-version");

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
            DisableSNI = disableSni,
            MinVersion = !string.IsNullOrEmpty(minVersion) ? minVersion : null,
            MaxVersion = !string.IsNullOrEmpty(maxVersion) ? maxVersion : null,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null,
            Reality = reality
        };
    }

    private static OutboundMultiplexOptions? ParseMultiplex(NodeContext ctx)
    {
        if (!ctx.GetBool("mux", "smux.enabled")) return null;

        string proto = ctx.GetString("smux.protocol", "mux.protocol");
        if (string.IsNullOrEmpty(proto)) proto = "smux";

        int mc = ctx.GetInt("smux.max-connections", "mux.max-connections", "smux.max_connections");
        int minStreams = ctx.GetInt("smux.min-streams", "mux.min-streams", "smux.min_streams");
        int maxStreams = ctx.GetInt("smux.max-streams", "mux.max-streams", "smux.max_streams");
        bool padding = ctx.GetBool("smux.padding", "mux.padding");

        return new OutboundMultiplexOptions
        {
            Enabled = true,
            Protocol = proto,
            MaxConnections = mc > 0 ? mc : null,
            MinStreams = minStreams > 0 ? minStreams : null,
            MaxStreams = maxStreams > 0 ? maxStreams : null,
            Padding = padding
        };
    }
}
