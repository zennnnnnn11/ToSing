namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// TUIC (v5) 协议解析器。
/// </summary>
public static class TuicParser
{
    public static TuicOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string rawUuid = ctx.GetString("uuid", "username");
        if (string.IsNullOrWhiteSpace(rawUuid) || !Guid.TryParse(rawUuid, out Guid parsedGuid))
        {
            // 内核强制要求合法的 UUID
            return null;
        }
        // 规整为内核要求的标准 36 位连字符格式，剥离圆括号/大括号
        string uuid = parsedGuid.ToString("D");

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"TUIC {server}:{port}";
        string password = ctx.GetString("password");
        string cc = ctx.GetString("congestion_control", "congestion-control");
        string udpRelayMode = ctx.GetString("udp_relay_mode", "udp-relay-mode");
        bool udpOverStream = ctx.GetBool("udp_over_stream", "udp-over-stream");

        // 内核互斥规则: udp_over_stream is conflict with udp_relay_mode
        if (udpOverStream)
        {
            udpRelayMode = string.Empty;
        }

        string heartbeat = ctx.GetString("heartbeat");
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
            UdpOverStream = udpOverStream,
            Heartbeat = !string.IsNullOrEmpty(heartbeat) ? heartbeat : null,
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

        // 注意：QUIC 协议栈不支持 uTLS，严禁输出 tls.utls

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = null
        };
    }
}
