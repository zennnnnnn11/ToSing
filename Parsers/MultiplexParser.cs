namespace SubParser.Parsers;

using System;
using SubParser.Models.Common;

internal static class MultiplexParser
{
    public static OutboundMultiplexOptions? ParseMultiplex(NodeContext ctx)
    {
        if (!ctx.GetBool("mux", "smux.enabled")) return null;

        string proto = ctx.GetString("smux.protocol", "mux.protocol");
        if (string.IsNullOrEmpty(proto)) proto = "smux";

        int mc = ctx.GetInt("smux.max-connections", "mux.max-connections", "smux.max_connections");
        int minStreams = ctx.GetInt("smux.min-streams", "mux.min-streams", "smux.min_streams");
        int maxStreams = ctx.GetInt("smux.max-streams", "mux.max-streams", "smux.max_streams");
        bool padding = ctx.GetBool("smux.padding", "mux.padding");

        BrutalOptions? brutal = ParseBrutal(ctx);

        return new OutboundMultiplexOptions
        {
            Enabled = true,
            Protocol = proto,
            MaxConnections = mc > 0 ? mc : null,
            MinStreams = minStreams > 0 ? minStreams : null,
            MaxStreams = maxStreams > 0 ? maxStreams : null,
            Padding = padding,
            Brutal = brutal
        };
    }

    private static BrutalOptions? ParseBrutal(NodeContext ctx)
    {
        bool hasBrutalSection = ctx.HasProperty("smux.brutal") ||
                                ctx.HasProperty("mux.brutal") ||
                                ctx.GetRaw("smux.brutal") != null ||
                                ctx.GetRaw("mux.brutal") != null;

        bool brutalEnabled = ctx.GetBool("smux.brutal.enabled", "mux.brutal.enabled");
        int up = ctx.GetInt("smux.brutal.up_mbps", "mux.brutal.up_mbps", "smux.brutal.up-mbps", "mux.brutal.up-mbps");
        int down = ctx.GetInt("smux.brutal.down_mbps", "mux.brutal.down_mbps", "smux.brutal.down-mbps", "mux.brutal.down-mbps");

        if (hasBrutalSection || brutalEnabled || up > 0 || down > 0)
        {
            bool enabled = ctx.GetBoolWithDefault(true, "smux.brutal.enabled", "mux.brutal.enabled");
            return new BrutalOptions
            {
                Enabled = enabled,
                UpMbps = up > 0 ? up : null,
                DownMbps = down > 0 ? down : null
            };
        }

        return null;
    }
}
