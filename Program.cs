using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

Console.WriteLine("正在构建 7 种协议的测试节点...");

var nodes = new List<SingboxOutbound>
{
    // 1. VLESS (Reality)
    new VlessOutbound
    {
        Tag = "vless-reality-node",
        Server = "127.0.0.1",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9661",
        Flow = "xtls-rprx-vision",
        Tls = new OutboundTLSOptions
        {
            ServerName = "www.apple.com",
            Utls = new OutboundUTLSOptions
            {
                Fingerprint = "chrome"
            },
            Reality = new OutboundRealityOptions
            {
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

    // 3. Hysteria 2
    new Hysteria2Outbound
    {
        Tag = "hy2-node",
        Server = "1.2.3.5",
        ServerPort = 443,
        Password = "hy2password",
        UpMbps = 100,
        DownMbps = 500,
        Tls = new OutboundTLSOptions
        {
            ServerName = "hy2.example.com",
            Insecure = false
        }
    },

    // 4. VMess (WS + TLS)
    new VmessOutbound
    {
        Tag = "vmess-ws-node",
        Server = "1.2.3.6",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9662",
        Security = "auto",
        Tls = new OutboundTLSOptions
        {
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
            ServerName = "trojan.example.com"
        },
        Transport = new V2RayTransportOptions
        {
            Type = "grpc",
            ServiceName = "trojan-service"
        }
    },

    // 6. TUIC
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
            ServerName = "tuic.example.com"
        }
    },

    // 7. AnyTLS
    new AnyTlsOutbound
    {
        Tag = "anytls-node",
        Server = "1.2.3.9",
        ServerPort = 1080,
        Password = "anytlspassword",
        Tls = new OutboundTLSOptions
        {
            ServerName = "anytls.example.com"
        }
    }
};

// 组装成完整的 sing-box 配置文件（加入 direct 和 selector）
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

var options = new JsonSerializerOptions
{
    WriteIndented = true
};

string json = JsonSerializer.Serialize(fullConfig, options);
string outputPath = Path.Combine(AppContext.BaseDirectory, "test_config.json");
File.WriteAllText(outputPath, json);

Console.WriteLine($"配置已成功生成到: {outputPath}");
