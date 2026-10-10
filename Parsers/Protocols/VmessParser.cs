namespace SubParser.Parsers.Protocols;

using System;
using System.Globalization;
using System.Text.Json;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

/// <summary>
/// VMess 协议解析器。
/// </summary>
public static class VmessParser
{
    public static VmessOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string server = ctx.Server;
        int port = ctx.ServerPort;
        if (port < 1 || port > 65535) return null;

        string uuid = ctx.GetString("uuid", "id");
        if (string.IsNullOrWhiteSpace(uuid)) return null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag) ? ctx.Tag : $"VMess {server}:{port}";
        string security = NormalizeVmessSecurity(ctx.GetString("security", "cipher"));

        long alterId = ctx.GetLong("alter_id", "alterId", "aid");
        bool globalPadding = ctx.GetBool("global_padding", "global-padding");
        bool authenticatedLength = ctx.GetBool("authenticated_length", "authenticated-length");

        var transport = TransportParser.ParseTransport(ctx);
        var tls = TlsParser.Parse(ctx, server);
        string packetEncoding = ParsePacketEncoding(ctx);
        var multiplex = MultiplexParser.ParseMultiplex(ctx);

        return new VmessOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Network = ctx.GetPacketNetwork(),
            Uuid = uuid,
            Security = security,
            AlterId = alterId,
            GlobalPadding = globalPadding,
            AuthenticatedLength = authenticatedLength,
            Tls = tls,
            Transport = transport,
            PacketEncoding = !string.IsNullOrEmpty(packetEncoding) ? packetEncoding : null,
            Multiplex = multiplex
        };
    }



    private static string ParsePacketEncoding(NodeContext ctx)
    {
        string pe = ctx.GetString("packet_encoding", "packet-encoding");
        if (!string.IsNullOrEmpty(pe)) return pe;
        if (ctx.GetBool("xudp")) return "xudp";
        if (ctx.GetBool("packet-addr")) return "packetaddr";
        return string.Empty;
    }


    public static NodeContext ParseVmessJsonUri(string vmessUri)
    {
        string raw = vmessUri.Trim();
        if (raw.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            raw = raw[8..];
        }

        string json = Base64Utils.Decode(raw);
        var ctx = new NodeContext { Protocol = "vmess" };

        try
        {
            using var doc = JsonDocument.Parse(json);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                ApplyJsonProp(ctx, prop.Name, prop.Value);
            }
        }
        catch
        {
            return NodeContext.FromUri(vmessUri);
        }

        return ctx;
    }

    private static void ApplyJsonProp(NodeContext ctx, string key, JsonElement valElem)
    {
        string val = valElem.ValueKind switch
        {
            JsonValueKind.String => valElem.GetString() ?? string.Empty,
            JsonValueKind.Number => valElem.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => valElem.GetRawText()
        };

        switch (key.ToLowerInvariant())
        {
            case "ps": ctx.Tag = val; break;
            case "add": ctx.Server = val; break;
            case "port":
                if (int.TryParse(val, CultureInfo.InvariantCulture, out int p)) ctx.ServerPort = p;
                break;
            case "id": ctx.SetProperty("uuid", val); break;
            case "aid": ctx.SetProperty("alter_id", val); break;
            case "scy": ctx.SetProperty("security", val); break;
            case "net": ctx.SetProperty("network", val); break;
            case "type": ctx.SetProperty("header_type", val); break;
            case "host": ctx.SetProperty("host", val); break;
            case "path": ctx.SetProperty("path", val); break;
            case "tls": ctx.SetProperty("tls", val); break;
            case "sni": ctx.SetProperty("sni", val); break;
            case "alpn": ctx.SetProperty("alpn", val); break;
            case "fp": ctx.SetProperty("fp", val); break;
            default: ctx.SetProperty(key, val); break;
        }
    }

    private static string NormalizeVmessSecurity(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "auto";
        string s = raw.Trim().ToLowerInvariant();
        return s switch
        {
            "chacha20-ietf-poly1305" or "chacha20-poly1305" => "chacha20-poly1305",
            "aes-128-gcm" or "gcm" => "aes-128-gcm",
            "none" => "none",
            "zero" => "zero",
            "aes-128-cfb" => "aes-128-cfb",
            "auto" => "auto",
            _ => throw new FormatException($"Unknown VMess security: {raw}")
        };
    }
}
