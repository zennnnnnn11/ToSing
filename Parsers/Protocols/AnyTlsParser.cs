namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// AnyTLS 协议节点解析与装配器
/// </summary>
public static class AnyTlsParser
{
    public static AnyTlsOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"AnyTLS {server}:{port}";
        string password = ctx.GetString("password", "auth");

        int minIdle = ctx.GetInt("min_idle_session", "min-idle-session");

        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SubParser.Utils.SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        var tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
        };

        return new AnyTlsOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            MinIdleSession = minIdle > 0 ? minIdle : null,
            Tls = tls
        };
    }
}
