namespace ToSing.Parsers.Protocols;

using System;
using ToSing.Models.Common;
using ToSing.Models.Protocols;

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
        if (port < 1 || port > 65535)
            return null;

        string rawUuid = ctx.GetString("uuid", "username");
        if (string.IsNullOrWhiteSpace(rawUuid) || !Guid.TryParse(rawUuid, out Guid parsedGuid))
        {
            return null;
        }
        string uuid = parsedGuid.ToString("D");

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"TUIC {server}:{port}";
        string password = ctx.GetSecretString("password");
        string cc = ctx.GetString(
            "congestion_control",
            "congestion-control",
            "congestion-controller",
            "congestion_controller"
        );
        string udpRelayMode = ctx.GetString("udp_relay_mode", "udp-relay-mode");
        if (!string.IsNullOrEmpty(udpRelayMode) && udpRelayMode is not ("native" or "quic"))
            throw new FormatException($"Unknown TUIC udp_relay_mode: {udpRelayMode}");
        bool udpOverStream = ctx.GetBool("udp_over_stream", "udp-over-stream");

        if (udpOverStream)
        {
            if (ctx.IsNativeConfig && !string.IsNullOrEmpty(udpRelayMode))
                throw new FormatException("udp_over_stream conflicts with udp_relay_mode");
            udpRelayMode = string.Empty;
        }

        string heartbeat = ctx.GetString("heartbeat");
        bool zeroRtt = ctx.GetBool("zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt");
        var tls = TlsParser.Parse(ctx, server, allowUtls: false, forceTls: true);
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
            Network = ctx.GetPacketNetwork(),
            Tls = tls,
        };
    }

    private static (
        string? IdleTimeout,
        string? KeepAlivePeriod,
        bool DisablePathMtuDiscovery,
        long? InitialPacketSize,
        long? MaxConcurrentStreams,
        object? StreamReceiveWindow,
        object? ConnectionReceiveWindow
    ) ReadQuicParams(NodeContext ctx)
    {
        string idle = ctx.GetString("idle_timeout", "idle-timeout");
        string keepAlive = ctx.GetString("keep_alive_period", "keep-alive-period");
        bool disablePmtu = ctx.GetBool("disable_path_mtu_discovery", "disable-path-mtu-discovery");
        long initPkt = ctx.GetLong("initial_packet_size", "initial-packet-size");
        long maxStreams = ctx.GetLong("max_concurrent_streams", "max-concurrent-streams");
        object? streamRw = ctx.GetMemoryBytes("stream_receive_window", "stream-receive-window");
        object? connRw = ctx.GetMemoryBytes(
            "connection_receive_window",
            "connection-receive-window"
        );

        long? finalInitPkt = null;
        if (ctx.IsNativeConfig)
        {
            finalInitPkt = ctx.GetLongNullable("initial_packet_size");
        }
        else if (initPkt > 0)
        {
            finalInitPkt = initPkt;
        }

        long? finalMaxStreams = null;
        if (ctx.IsNativeConfig)
        {
            finalMaxStreams = ctx.GetLongNullable("max_concurrent_streams");
        }
        else if (maxStreams > 0)
        {
            finalMaxStreams = maxStreams;
        }

        return (
            !string.IsNullOrEmpty(idle) ? idle : null,
            !string.IsNullOrEmpty(keepAlive) ? keepAlive : null,
            disablePmtu,
            finalInitPkt,
            finalMaxStreams,
            streamRw,
            connRw
        );
    }
}
