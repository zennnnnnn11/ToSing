namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

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
        if (port < 1 || port > 65535) return null;

        string password = ctx.GetSecretString("password");
        if (string.IsNullOrWhiteSpace(password)) return null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"Trojan {server}:{port}";

        var transport = TransportParser.ParseTransport(ctx);
        var tls = TlsParser.Parse(ctx, server, allowUtls: true, forceTls: true);
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
            Multiplex = multiplex
        };
    }



}
