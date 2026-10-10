namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// TUIC (v5) 协议解析器。
/// </summary>
public static class TuicParser
{
    public static TuicOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"TUIC {server}:{port}";
        string uuid = ctx.GetString("uuid", "username");
        string password = ctx.GetString("password");
        string cc = ctx.GetString("congestion_control", "congestion-control");
        string udpRelayMode = ctx.GetString("udp_relay_mode", "udp-relay-mode");
        bool zeroRtt = ctx.GetBool("zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt");

        var tls = ParseTls(ctx, server);

        return new TuicOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Uuid = uuid,
            Password = password,
            CongestionControl = !string.IsNullOrEmpty(cc) ? cc : null,
            UdpRelayMode = !string.IsNullOrEmpty(udpRelayMode) ? udpRelayMode : null,
            ZeroRttHandshake = zeroRtt,
            Tls = tls
        };
    }

    private static OutboundTLSOptions ParseTls(NodeContext ctx, string server)
    {
        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
        };
    }
}
