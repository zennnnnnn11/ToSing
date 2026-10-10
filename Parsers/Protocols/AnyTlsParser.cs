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
    public static AnyTlsOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string password = ctx.GetString("password");
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"AnyTLS {server}:{port}";
        string clientMetadata = ctx.GetString("client_metadata", "client-metadata");

        string idleTimeout = ctx.GetString("idle_session_check_interval", "idle-session-check-interval");
        string maxIdleTime = ctx.GetString("idle_session_timeout", "idle-session-timeout");
        int minIdleSession = ctx.GetInt("min_idle_session", "min-idle-session");

        var tls = TlsParser.Parse(ctx, server, allowUtls: true, forceTls: true);

        return new AnyTlsOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Password = password,
            ClientMetadata = !string.IsNullOrEmpty(clientMetadata) ? clientMetadata : null,
            IdleSessionCheckInterval = !string.IsNullOrEmpty(idleTimeout) ? idleTimeout : null,
            IdleSessionTimeout = !string.IsNullOrEmpty(maxIdleTime) ? maxIdleTime : null,
            MinIdleSession = minIdleSession > 0 ? minIdleSession : null,
            Tls = tls
        };
    }


}
