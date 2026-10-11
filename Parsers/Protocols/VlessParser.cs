namespace ToSing.Parsers.Protocols;

using System;
using ToSing.Models.Common;
using ToSing.Models.Protocols;
using ToSing.Utils;

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
        if (port < 1 || port > 65535)
            return null;

        string uuid = ctx.GetString("uuid", "password");
        if (string.IsNullOrWhiteSpace(uuid))
            return null;

        string enc = ctx.GetString("encryption");
        if (
            !string.IsNullOrEmpty(enc)
            && !string.Equals(enc, "none", StringComparison.OrdinalIgnoreCase)
        )
        {
            return null;
        }

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"VLESS {server}:{port}";
        string rawFlow = ctx.GetString("flow").Trim();
        string flow = string.Empty;

        if (!string.IsNullOrEmpty(rawFlow))
        {
            string lowerFlow = rawFlow.ToLowerInvariant();
            if (
                string.Equals(lowerFlow, "xtls-rprx-vision", StringComparison.Ordinal)
                || string.Equals(lowerFlow, "xtls-rprx-vision-udp443", StringComparison.Ordinal)
            )
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

        string netType = ctx.GetString("type", "network", "net").Trim().ToLowerInvariant();
        if (netType is "kcp" or "mkcp")
        {
            return null;
        }

        string security = ctx.GetString("security").Trim().ToLowerInvariant();
        string pbk = ctx.GetString("pbk", "public-key", "reality-opts.public-key", "amp;pbk");
        bool isReality =
            string.Equals(security, "reality", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(pbk);
        if (isReality && !TlsParser.IsValidRealityPublicKey(pbk))
        {
            return null;
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

        var tls = TlsParser.Parse(ctx, server);
        var multiplex = MultiplexParser.ParseMultiplex(ctx);

        return new VlessOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Network = ctx.GetPacketNetwork(),
            Uuid = uuid,
            Flow = !string.IsNullOrEmpty(flow) ? flow : null,
            Tls = tls,
            Transport = transport,
            PacketEncoding = packetEncoding,
            Multiplex = multiplex,
        };
    }

    private static (string? pe, bool isValid) ParsePacketEncoding(NodeContext ctx)
    {
        if (
            ctx.HasProperty("packet_encoding")
            || ctx.HasProperty("packet-encoding")
            || ctx.HasProperty("packetEncoding")
        )
        {
            string pe = ctx.GetString("packet_encoding", "packet-encoding", "packetEncoding");
            if (string.IsNullOrEmpty(pe))
            {
                // 显式提供空字符串 packet_encoding=""
                return ("", true);
            }
            if (
                string.Equals(pe, "xudp", StringComparison.OrdinalIgnoreCase)
                || string.Equals(pe, "packetaddr", StringComparison.OrdinalIgnoreCase)
            )
            {
                return (pe.ToLowerInvariant(), true);
            }
            // 未知值非法
            return (null, false);
        }

        if (ctx.GetBool("xudp"))
            return ("xudp", true);
        if (ctx.GetBool("packet-addr"))
            return ("packetaddr", true);

        // 未提供时为 null（sing-box 默认行为）
        return (null, true);
    }
}
