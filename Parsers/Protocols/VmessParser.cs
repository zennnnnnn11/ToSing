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

        int alterId = ctx.GetInt("alter_id", "alterId", "aid");
        var transport = TransportParser.ParseTransport(ctx);
        var tls = ParseTls(ctx, server);
        string packetEncoding = ParsePacketEncoding(ctx);
        var multiplex = ParseMultiplex(ctx);

        return new VmessOutbound
        {
            Tag = tag,
            Server = server,
            ServerPort = port,
            Uuid = uuid,
            Security = security,
            AlterId = alterId,
            Tls = tls,
            Transport = transport,
            PacketEncoding = !string.IsNullOrEmpty(packetEncoding) ? packetEncoding : null,
            Multiplex = multiplex
        };
    }

    private static OutboundTLSOptions? ParseTls(NodeContext ctx, string server)
    {
        string tlsStr = ctx.GetString("tls").ToLowerInvariant();
        bool hasTls = ctx.GetBool("tls") ||
                      string.Equals(tlsStr, "tls", StringComparison.Ordinal) ||
                      string.Equals(tlsStr, "1", StringComparison.Ordinal) ||
                      string.Equals(tlsStr, "true", StringComparison.Ordinal);

        if (!hasTls) return null;

        string serverName = ctx.GetString("sni", "servername", "peer");
        if (string.IsNullOrEmpty(serverName)) serverName = server;

        bool insecure = ctx.GetBool("insecure", "skip-cert-verify", "allowInsecure");
        bool disableSni = ctx.GetBool("disable_sni", "disable-sni");
        string minVersion = ctx.GetString("min_version", "min-version");
        string maxVersion = ctx.GetString("max_version", "max-version");

        var alpnList = ctx.GetStringList("alpn");
        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint");
        string? fp = SingboxUtlsUtils.NormalizeFingerprint(fpRaw);

        return new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = insecure,
            DisableSNI = disableSni,
            MinVersion = !string.IsNullOrEmpty(minVersion) ? minVersion : null,
            MaxVersion = !string.IsNullOrEmpty(maxVersion) ? maxVersion : null,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null
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

    private static OutboundMultiplexOptions? ParseMultiplex(NodeContext ctx)
    {
        if (!ctx.GetBool("mux", "smux.enabled")) return null;

        string proto = ctx.GetString("smux.protocol", "mux.protocol");
        if (string.IsNullOrEmpty(proto)) proto = "smux";

        int mc = ctx.GetInt("smux.max-connections", "mux.max-connections", "smux.max_connections");
        int minStreams = ctx.GetInt("smux.min-streams", "mux.min-streams", "smux.min_streams");
        int maxStreams = ctx.GetInt("smux.max-streams", "mux.max-streams", "smux.max_streams");
        bool padding = ctx.GetBool("smux.padding", "mux.padding");

        return new OutboundMultiplexOptions
        {
            Enabled = true,
            Protocol = proto,
            MaxConnections = mc > 0 ? mc : null,
            MinStreams = minStreams > 0 ? minStreams : null,
            MaxStreams = maxStreams > 0 ? maxStreams : null,
            Padding = padding
        };
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
            _ => "auto"
        };
    }
}
