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

        var realm = ParseRealm(ctx);
        string server = ctx.Server;
        int port = ctx.ServerPort;

        if (realm == null && (port < 1 || port > 65535))
        {
            return null;
        }

        string defaultSni = server;
        if (realm != null)
        {
            if (Uri.TryCreate(realm.ServerUrl, UriKind.Absolute, out Uri? realmUri))
            {
                defaultSni = realmUri.Host;
            }
            server = null!;
            port = 0;
        }

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : (realm != null ? $"HY2 {realm.RealmId}" : $"HY2 {server}:{port}");
        string password = ctx.GetString("password", "auth");

        var rawPorts = ctx.GetStringList("server_ports", "ports", "mport");
        var serverPorts = realm != null ? [] : NormalizeServerPorts(rawPorts);

        var (obfs, obfsValid) = ParseObfs(ctx);
        if (!obfsValid) return null;

        var tls = TlsParser.Parse(ctx, defaultSni, allowUtls: false, forceTls: true);
        var q = ReadQuicParams(ctx);

        return CreateOutbound(ctx, tag, server, port, password, serverPorts, obfs, tls, q, realm);
    }

    private static Hysteria2Outbound CreateOutbound(
        NodeContext ctx,
        string tag,
        string server,
        int port,
        string password,
        List<string> serverPorts,
        Hysteria2ObfsOptions? obfs,
        OutboundTLSOptions? tls,
        (string? IdleTimeout, string? KeepAlivePeriod, bool DisablePathMtuDiscovery, int? InitialPacketSize, int? MaxConcurrentStreams, string? StreamReceiveWindow, string? ConnectionReceiveWindow, string? Network) q,
        Hysteria2RealmOptions? realm)
    {
        string hopInterval = ctx.GetString("hop_interval", "hop-interval");
        string hopIntervalMax = ctx.GetString("hop_interval_max", "hop-interval-max");
        int upMbps = ctx.GetInt("up_mbps", "upmbps", "up");
        int downMbps = ctx.GetInt("down_mbps", "downmbps", "down");
        string bbrProfile = ctx.GetString("bbr_profile", "bbr-profile");
        bool brutalDebug = ctx.GetBool("brutal_debug", "brutal-debug");
        bool disableChromeParrot = ctx.GetBool("disable_chrome_parrot", "disable-chrome-parrot");

        return new Hysteria2Outbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port > 0 ? port : null,
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
            Tls = tls,
            Realm = realm
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

    private static Hysteria2RealmOptions? ParseRealm(NodeContext ctx)
    {
        string serverUrl = ctx.GetString("realm.server_url", "realm.server-url", "realm-server-url");
        string realmId = ctx.GetString("realm.realm_id", "realm.realm-id", "realm-id");
        var stunServers = ctx.GetStringList("realm.stun_servers", "realm.stun-servers", "realm-stun-servers");

        if (string.IsNullOrEmpty(serverUrl) || string.IsNullOrEmpty(realmId) || stunServers.Count == 0)
        {
            return null;
        }

        string token = ctx.GetString("realm.token", "realm-token");
        int? ipVersion = ctx.GetIntNullable("realm.ip_version", "realm.ip-version", "realm-ip-version");

        return new Hysteria2RealmOptions
        {
            ServerUrl = serverUrl,
            RealmId = realmId,
            StunServers = stunServers,
            Token = !string.IsNullOrEmpty(token) ? token : null,
            IpVersion = ipVersion
        };
    }
}
