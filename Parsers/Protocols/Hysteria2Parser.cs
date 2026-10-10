namespace SubParser.Parsers.Protocols;

using System;
using System.Collections.Generic;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// Hysteria 2 协议解析器。
/// </summary>
public static class Hysteria2Parser
{
    public static Hysteria2Outbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"HY2 {server}:{port}";
        string password = ctx.GetString("password", "auth");

        var rawPorts = ctx.GetStringList("server_ports", "ports", "mport");
        var serverPorts = NormalizeServerPorts(rawPorts);

        string hopInterval = ctx.GetString("hop_interval", "hop-interval");
        string hopIntervalMax = ctx.GetString("hop_interval_max", "hop-interval-max");

        int upMbps = ctx.GetInt("up_mbps", "upmbps", "up");
        int downMbps = ctx.GetInt("down_mbps", "downmbps", "down");

        string bbrProfile = ctx.GetString("bbr_profile", "bbr-profile");
        bool brutalDebug = ctx.GetBool("brutal_debug", "brutal-debug");
        bool disableChromeParrot = ctx.GetBool("disable_chrome_parrot", "disable-chrome-parrot");

        var (obfs, obfsValid) = ParseObfs(ctx);
        if (!obfsValid)
        {
            return null;
        }

        var tls = ParseTls(ctx, server);
        var q = ReadQuicParams(ctx);

        return new Hysteria2Outbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            ServerPorts = serverPorts.Count > 0 ? serverPorts : null,
            HopInterval = !string.IsNullOrEmpty(hopInterval) ? hopInterval : null,
            HopIntervalMax = !string.IsNullOrEmpty(hopIntervalMax) ? hopIntervalMax : null,
            UpMbps = upMbps > 0 ? upMbps : null,
            DownMbps = downMbps > 0 ? downMbps : null,
            BbrProfile = !string.IsNullOrEmpty(bbrProfile) ? bbrProfile : null,
            BrutalDebug = brutalDebug,
            DisableChromeParrot = disableChromeParrot,
            IdleTimeout = q.IdleTimeout,
            KeepAlivePeriod = q.KeepAlivePeriod,
            DisablePathMtuDiscovery = q.DisablePathMtuDiscovery,
            InitialPacketSize = q.InitialPacketSize,
            MaxConcurrentStreams = q.MaxConcurrentStreams,
            StreamReceiveWindow = q.StreamReceiveWindow,
            ConnectionReceiveWindow = q.ConnectionReceiveWindow,
            Network = q.Network,
            Obfs = obfs,
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

    private static (Hysteria2ObfsOptions? obfs, bool isValid) ParseObfs(NodeContext ctx)
    {
        string obfsType = ctx.GetString("obfs", "obfs-type");
        string obfsPassword = ctx.GetString("obfs-password", "obfs_password");

        if (string.IsNullOrEmpty(obfsType) && string.IsNullOrEmpty(obfsPassword))
        {
            return (null, true);
        }

        // 内核要求: 只要启用了混淆，password 不能为空
        if (string.IsNullOrEmpty(obfsPassword))
        {
            return (null, false);
        }

        return (new Hysteria2ObfsOptions
        {
            Type = !string.IsNullOrEmpty(obfsType) ? obfsType : "salamander",
            Password = obfsPassword
        }, true);
    }

    private static List<string> NormalizeServerPorts(IReadOnlyList<string> ports)
    {
        var result = new List<string>(ports.Count);
        foreach (string p in ports)
        {
            string s = p.Trim();
            if (s.Contains('-', StringComparison.Ordinal) && !s.Contains(':', StringComparison.Ordinal))
            {
                s = s.Replace('-', ':');
            }
            if (!string.IsNullOrEmpty(s))
            {
                result.Add(s);
            }
        }
        return result;
    }

    private static OutboundTLSOptions ParseTls(NodeContext ctx, string server)
    {
        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");

        // 注意：QUIC 协议栈不支持 uTLS，因此严禁输出 tls.utls

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
