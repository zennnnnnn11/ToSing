namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// TUIC (v5) 协议节点解析与装配器
/// </summary>
public static class TuicParser
{
    public static TuicOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort > 0 ? ctx.ServerPort : 443;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"TUIC {server}:{port}";

        string uuid = ctx.GetString("uuid");
        string password = ctx.GetString("password", "token");
        string cc = ctx.GetString("congestion_control", "congestion-control", "cc");
        string udpRelay = ctx.GetString("udp_relay_mode", "udp-relay-mode");
        bool zeroRtt = ctx.GetBool("zero_rtt_handshake", "zero-rtt-handshake", "reduce_rtt");

        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");
        string fp = ctx.GetString("fp", "client-fingerprint", "fingerprint");

        var tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = !string.IsNullOrEmpty(fp) ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
        };

        return new TuicOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Uuid = uuid,
            Password = password,
            CongestionControl = !string.IsNullOrEmpty(cc) ? cc : null,
            UdpRelayMode = !string.IsNullOrEmpty(udpRelay) ? udpRelay : null,
            ZeroRttHandshake = zeroRtt,
            Tls = tls
        };
    }
}
