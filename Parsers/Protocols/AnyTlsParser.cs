namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// AnyTLS 协议解析器。
/// </summary>
public static class AnyTlsParser
{
    public static AnyTlsOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;

        string password = ctx.GetString("password");
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"AnyTLS {server}:{port}";

        string idleTimeout = ctx.GetString("idle_session_check_interval", "idle-session-check-interval");
        string maxIdleTime = ctx.GetString("idle_session_timeout", "idle-session-timeout");
        int minIdleSession = ctx.GetInt("min_idle_session", "min-idle-session");

        var tls = ParseTls(ctx, server);

        return new AnyTlsOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            IdleSessionCheckInterval = !string.IsNullOrEmpty(idleTimeout) ? idleTimeout : null,
            IdleSessionTimeout = !string.IsNullOrEmpty(maxIdleTime) ? maxIdleTime : null,
            MinIdleSession = minIdleSession > 0 ? minIdleSession : null,
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
