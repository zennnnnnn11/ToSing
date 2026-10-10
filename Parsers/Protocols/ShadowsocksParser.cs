namespace SubParser.Parsers.Protocols;

using System;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

/// <summary>
/// Shadowsocks 协议节点解析与装配器
/// </summary>
public static class ShadowsocksParser
{
    public static ShadowsocksOutbound Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null!;
        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"SS {server}:{port}";

        string method = ctx.GetString("method", "cipher");
        if (string.IsNullOrEmpty(method)) method = "aes-256-gcm";

        string password = ctx.GetString("password");
        string plugin = ctx.GetString("plugin");
        string pluginOpts = ctx.GetString("plugin_opts", "plugin-opts");

        UdpOverTcpOptions? uot = null;
        if (ctx.GetBool("udp_over_tcp", "udp-over-tcp", "uot"))
        {
            int ver = ctx.GetInt("uot_version", "uot-version");
            uot = new UdpOverTcpOptions
            {
                Enabled = true,
                Version = ver > 0 ? ver : 2
            };
        }

        OutboundMultiplexOptions? multiplex = null;
        if (ctx.GetBool("mux", "smux.enabled"))
        {
            multiplex = new OutboundMultiplexOptions
            {
                Enabled = true,
                Protocol = "smux"
            };
        }

        return new ShadowsocksOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Method = method,
            Password = password,
            Plugin = !string.IsNullOrEmpty(plugin) ? plugin : null,
            PluginOptions = !string.IsNullOrEmpty(pluginOpts) ? pluginOpts : null,
            UdpOverTcp = uot,
            Multiplex = multiplex
        };
    }
}
