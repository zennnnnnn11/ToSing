namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// Hysteria 2 协议解析器。
/// </summary>
public static class Hysteria2Parser
{
    public static Hysteria2Outbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"HY2 {server}:{port}";
        string password = ctx.GetString("password", "auth");

        var serverPorts = ctx.GetStringList("server_ports", "ports", "mport");
        int upMbps = ctx.GetInt("up_mbps", "upmbps", "up");
        int downMbps = ctx.GetInt("down_mbps", "downmbps", "down");

        var obfs = ParseObfs(ctx);
        var tls = ParseTls(ctx, server);

        return new Hysteria2Outbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            ServerPorts = serverPorts.Count > 0 ? serverPorts : null,
            UpMbps = upMbps > 0 ? upMbps : null,
            DownMbps = downMbps > 0 ? downMbps : null,
            Obfs = obfs,
            Tls = tls
        };
    }

    private static Hysteria2ObfsOptions? ParseObfs(NodeContext ctx)
    {
        string obfsType = ctx.GetString("obfs", "obfs-type");
        string obfsPassword = ctx.GetString("obfs-password", "obfs_password");

        if (string.IsNullOrEmpty(obfsPassword) && string.IsNullOrEmpty(obfsType))
        {
            return null;
        }

        return new Hysteria2ObfsOptions
        {
            Type = !string.IsNullOrEmpty(obfsType) ? obfsType : "salamander",
            Password = obfsPassword
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
