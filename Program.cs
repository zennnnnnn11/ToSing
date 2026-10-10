using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

Console.WriteLine("正在以最纯粹的领域模型构建 7 种协议节点...");

var nodes = new SingboxOutbound[]
{
    // 1. VLESS (Reality + uTLS)
    new VlessOutbound
    {
        Tag = "vless-reality-node",
        Server = "127.0.0.1",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9661",
        Flow = "xtls-rprx-vision",
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "www.apple.com",
            Alpn = new[] { "h2", "http/1.1" },
            Utls = new OutboundUTLSOptions
            {
                Enabled = true,
                Fingerprint = "chrome"
            },
            Reality = new OutboundRealityOptions
            {
                Enabled = true,
                PublicKey = "m58x9uUu6sH2Q_f2t3A3Wv3N3I7x6d2v_a5E_r8L-1A",
                ShortId = "0123456789abcdef"
            }
        }
    },

    // 2. Shadowsocks
    new ShadowsocksOutbound
    {
        Tag = "ss-node",
        Server = "1.2.3.4",
        ServerPort = 8388,
        Method = "aes-256-gcm",
        Password = "examplepassword"
    },

    // 3. Hysteria 2 (支持单端口与多端口跳跃)
    new Hysteria2Outbound
    {
        Tag = "hy2-node",
        Server = "1.2.3.5",
        ServerPorts = new[] { "10000:20000" },
        Password = "hy2password",
        UpMbps = 100,
        DownMbps = 500,
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "hy2.example.com"
        }
    },

    // 4. VMess (WebSocket + TLS)
    new VmessOutbound
    {
        Tag = "vmess-ws-node",
        Server = "1.2.3.6",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9662",
        Security = "auto",
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "vmess.example.com"
        },
        Transport = new V2RayTransportOptions
        {
            Type = "ws",
            Path = "/ray",
            Headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Host"] = "vmess.example.com"
            }
        }
    },

    // 5. Trojan (gRPC)
    new TrojanOutbound
    {
        Tag = "trojan-grpc-node",
        Server = "1.2.3.7",
        ServerPort = 443,
        Password = "trojanpassword",
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "trojan.example.com"
        },
        Transport = new V2RayTransportOptions
        {
            Type = "grpc",
            ServiceName = "trojan-service"
        }
    },

    // 6. TUIC (QUIC)
    new TuicOutbound
    {
        Tag = "tuic-node",
        Server = "1.2.3.8",
        ServerPort = 8443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9663",
        Password = "tuicpassword",
        CongestionControl = "bbr",
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "tuic.example.com"
        }
    },

    // 7. AnyTLS (sing-box 1.12.0+)
    new AnyTlsOutbound
    {
        Tag = "anytls-node",
        Server = "1.2.3.9",
        ServerPort = 1080,
        Password = "anytlspassword",
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "anytls.example.com"
        }
    }
};

// 组装成纯净、合法的完整 sing-box 配置文件
var fullConfig = new
{
    log = new { level = "warn" },
    inbounds = new[]
    {
        new
        {
            type = "mixed",
            tag = "mixed-in",
            listen = "127.0.0.1",
            listen_port = 20808
        }
    },
    outbounds = nodes.Concat<object>(new object[]
    {
        new { type = "direct", tag = "direct" },
        new
        {
            type = "selector",
            tag = "select",
            outbounds = nodes.Select(n => n.Tag).Append("direct").ToArray()
        }
    }).ToArray()
};

var jsonOptions = new JsonSerializerOptions
{
    WriteIndented = true
};

string json = JsonSerializer.Serialize(fullConfig, jsonOptions);
string outputPath = Path.Combine(AppContext.BaseDirectory, "pure_config.json");
File.WriteAllText(outputPath, json);

Console.WriteLine($"[成功] 纯净配置已生成到: {outputPath}");
