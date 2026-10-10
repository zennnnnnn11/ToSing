namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// Trojan 协议解析器。
/// </summary>
public static class TrojanParser
{
    public static TrojanOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string password = ctx.GetString("password");
        if (string.IsNullOrWhiteSpace(password)) return null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"Trojan {server}:{port}";

        var transport = TransportParser.ParseTransport(ctx);
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

    private static OutboundTLSOptions ParseTls(NodeContext ctx, string server)
    {
        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        bool disableSni = ctx.GetBool("disable_sni", "disable-sni");
        string minVersion = ctx.GetString("min_version", "min-version");
        string maxVersion = ctx.GetString("max_version", "max-version");

        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            DisableSNI = disableSni,
            MinVersion = !string.IsNullOrEmpty(minVersion) ? minVersion : null,
            MaxVersion = !string.IsNullOrEmpty(maxVersion) ? maxVersion : null,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
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
