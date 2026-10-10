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
            return null;
        }
        string uuid = parsedGuid.ToString("D");

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"TUIC {server}:{port}";
        string password = ctx.GetString("password");
        string cc = ctx.GetString("congestion_control", "congestion-control");
        string udpRelayMode = ctx.GetString("udp_relay_mode", "udp-relay-mode");
        bool udpOverStream = ctx.GetBool("udp_over_stream", "udp-over-stream");

        if (udpOverStream)
        {
            udpRelayMode = string.Empty;
        }

        string heartbeat = ctx.GetString("heartbeat");
        bool zeroRtt = ctx.GetBool("zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt");
        var tls = ParseTls(ctx, server);
        var q = ReadQuicParams(ctx);

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
            IdleTimeout = q.IdleTimeout,
            KeepAlivePeriod = q.KeepAlivePeriod,
            DisablePathMtuDiscovery = q.DisablePathMtuDiscovery,
            InitialPacketSize = q.InitialPacketSize,
            MaxConcurrentStreams = q.MaxConcurrentStreams,
            StreamReceiveWindow = q.StreamReceiveWindow,
            ConnectionReceiveWindow = q.ConnectionReceiveWindow,
            Network = q.Network,
            Tls = tls
        };
    }

    private static (string? IdleTimeout, string? KeepAlivePeriod, bool DisablePathMtuDiscovery, int? InitialPacketSize, int? MaxConcurrentStreams, string? StreamReceiveWindow, string? ConnectionReceiveWindow, string? Network) ReadQuicParams(NodeContext ctx)
    {
        string idle = ctx.GetString("idle_timeout", "idle-timeout");
        string keepAlive = ctx.GetString("keep_alive_period", "keep-alive-period");
        bool disablePmtu = ctx.GetBool("disable_path_mtu_discovery", "disable-path-mtu-discovery");
        int initPkt = ctx.GetInt("initial_packet_size", "initial-packet-size");
        int maxStreams = ctx.GetInt("max_concurrent_streams", "max-concurrent-streams");
        string streamRw = ctx.GetString("stream_receive_window", "stream-receive-window");
        string connRw = ctx.GetString("connection_receive_window", "connection-receive-window");
        string network = ctx.GetString("network");

        return (
            !string.IsNullOrEmpty(idle) ? idle : null,
            !string.IsNullOrEmpty(keepAlive) ? keepAlive : null,
            disablePmtu,
            initPkt > 0 ? initPkt : null,
            maxStreams > 0 ? maxStreams : null,
            !string.IsNullOrEmpty(streamRw) ? streamRw : null,
            !string.IsNullOrEmpty(connRw) ? connRw : null,
            !string.IsNullOrEmpty(network) ? network : null
        );
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
