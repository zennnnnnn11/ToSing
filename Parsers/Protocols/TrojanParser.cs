namespace ToSing.Parsers.Protocols;

using System;
using ToSing.Models.Common;
using ToSing.Models.Protocols;
using ToSing.Utils;

/// <summary>
/// Trojan 协议解析器。
/// </summary>
public static class TrojanParser
{
    public static TrojanOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535)
            return null;

        string password = ctx.GetSecretString("password");
        if (string.IsNullOrWhiteSpace(password))
            return null;

        string netType = ctx.GetString("type", "network", "net").Trim().ToLowerInvariant();
        if (netType is "kcp" or "mkcp")
        {
            return null;
        }

        string security = ctx.GetString("security").Trim().ToLowerInvariant();
        string pbk = ctx.GetString("pbk", "public-key", "reality-opts.public-key", "amp;pbk");
        bool isReality =
            string.Equals(security, "reality", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(pbk);
        if (isReality && !TlsParser.IsValidRealityPublicKey(pbk))
        {
            return null;
        }

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"Trojan {server}:{port}";

        var transport = TransportParser.ParseTransport(ctx);
        var tls = TlsParser.Parse(ctx, server, allowUtls: true, forceTls: !ctx.IsNativeConfig);
        var multiplex = MultiplexParser.ParseMultiplex(ctx);

        return new TrojanOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Network = ctx.GetPacketNetwork(),
            Password = password,
            Tls = tls,
            Transport = transport,
            Multiplex = multiplex,
        };
    }
}
