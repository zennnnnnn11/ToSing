using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Common;
using SubParser.Models.Protocols;

Console.WriteLine("=================================================");
Console.WriteLine("开始运行全量审查回归测试 (针对 8 个深层边界场景)...");
Console.WriteLine("=================================================");

int passed = 0;
int total = 0;

void Assert(string caseName, bool condition, string detail = "")
{
    total++;
    if (condition)
    {
        Console.WriteLine($"[PASS] {caseName}");
        passed++;
    }
    else
    {
        Console.WriteLine($"[FAIL] {caseName}: {detail}");
    }
}

// 场景 1: udp_over_tcp 支持布尔值与对象
{
    string json1 = """{"type":"shadowsocks","tag":"ss1","server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"pass","udp_over_tcp":true}""";
    var node1 = JsonSerializer.Deserialize<SingboxOutbound>(json1) as ShadowsocksOutbound;
    Assert("1.1 udp_over_tcp: true 反序列化", node1?.UdpOverTcp?.Enabled == true);

    string json2 = """{"type":"shadowsocks","tag":"ss2","server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"pass","udp_over_tcp":{"enabled":true,"version":2}}""";
    var node2 = JsonSerializer.Deserialize<SingboxOutbound>(json2) as ShadowsocksOutbound;
    Assert("1.2 udp_over_tcp: {enabled: true, version: 2} 反序列化", node2?.UdpOverTcp?.Enabled == true && node2?.UdpOverTcp?.Version == 2);
}

// 场景 2: network 支持单个字符串与数组
{
    string json1 = """{"type":"vless","tag":"v1","server":"1.1.1.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","network":"tcp"}""";
    var node1 = JsonSerializer.Deserialize<SingboxOutbound>(json1) as VlessOutbound;
    Assert("2.1 network: \"tcp\" (单字符串)", node1?.Network?.Count == 1 && string.Equals(node1.Network[0], "tcp", StringComparison.Ordinal));

    string json2 = """{"type":"vless","tag":"v2","server":"1.1.1.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","network":["tcp","udp"]}""";
    var node2 = JsonSerializer.Deserialize<SingboxOutbound>(json2) as VlessOutbound;
    Assert("2.2 network: [\"tcp\", \"udp\"] (数组)", node2?.Network?.Count == 2 && string.Equals(node2.Network[1], "udp", StringComparison.Ordinal));
}

// 场景 3: alpn 支持单个字符串与数组
{
    string json1 = """{"type":"trojan","tag":"t1","server":"1.1.1.1","server_port":443,"password":"pass","tls":{"enabled":true,"alpn":"h2"}}""";
    var node1 = JsonSerializer.Deserialize<SingboxOutbound>(json1) as TrojanOutbound;
    Assert("3.1 alpn: \"h2\" (单字符串)", node1?.Tls?.Alpn?.Count == 1 && string.Equals(node1.Tls.Alpn[0], "h2", StringComparison.Ordinal));

    string json2 = """{"type":"trojan","tag":"t2","server":"1.1.1.1","server_port":443,"password":"pass","tls":{"enabled":true,"alpn":["h2","http/1.1"]}}""";
    var node2 = JsonSerializer.Deserialize<SingboxOutbound>(json2) as TrojanOutbound;
    Assert("3.2 alpn: [\"h2\", \"http/1.1\"] (数组)", node2?.Tls?.Alpn?.Count == 2);
}

// 场景 4: headers Value 支持字符串和数组
{
    string json1 = """{"type":"vmess","tag":"vm1","server":"1.1.1.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","transport":{"type":"ws","path":"/","headers":{"Host":"example.com"}}}""";
    var node1 = JsonSerializer.Deserialize<SingboxOutbound>(json1) as VmessOutbound;
    Assert("4.1 headers: {\"Host\": \"example.com\"}", string.Equals(node1?.Transport?.Headers?["Host"][0], "example.com", StringComparison.Ordinal));

    string json2 = """{"type":"vmess","tag":"vm2","server":"1.1.1.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","transport":{"type":"ws","path":"/","headers":{"Host":["example.com"]}}}""";
    var node2 = JsonSerializer.Deserialize<SingboxOutbound>(json2) as VmessOutbound;
    Assert("4.2 headers: {\"Host\": [\"example.com\"]}", string.Equals(node2?.Transport?.Headers?["Host"][0], "example.com", StringComparison.Ordinal));
}

// 场景 5: HTTP transport 的 host 支持单字符串或数组
{
    string json = """{"type":"vmess","tag":"vm3","server":"1.1.1.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","transport":{"type":"http","host":["a.example","b.example"]}}""";
    var node = JsonSerializer.Deserialize<SingboxOutbound>(json) as VmessOutbound;
    Assert("5.1 host: [\"a.example\", \"b.example\"]", node?.Transport?.Host?.Count == 2 && string.Equals(node.Transport.Host[0], "a.example", StringComparison.Ordinal));
}

// 场景 6: Hysteria 2 省略 server_port，仅提供 server_ports
{
    string json = """{"type":"hysteria2","tag":"hy1","server":"1.1.1.1","server_ports":"10000:20000","password":"pass"}""";
    var node = JsonSerializer.Deserialize<SingboxOutbound>(json) as Hysteria2Outbound;
    Assert("6.1 Hysteria2 缺省 server_port (仅 server_ports)", node is not null && node.ServerPort is null && node.ServerPorts?.Count == 1);
}

// 场景 7: Enabled 开关状态往返一致性 (绝不反转)
{
    var originalTls = new OutboundTLSOptions { Enabled = false, ServerName = "test.com" };
    string serialized = JsonSerializer.Serialize(originalTls);
    var deserialized = JsonSerializer.Deserialize<OutboundTLSOptions>(serialized);
    Assert("7.1 Enabled=false 往返必须保持 false", deserialized?.Enabled == false, $"当前反序列化结果: {deserialized?.Enabled}");

    // 当输入为 {} 时，官方语义为未启用 (null 或 false)
    var emptyTls = JsonSerializer.Deserialize<OutboundTLSOptions>("{}");
    Assert("7.2 输入空对象 {} 时 Enabled 绝不变为 true", emptyTls?.Enabled != true, $"当前结果: {emptyTls?.Enabled}");
}

// 场景 8: 证书指纹 (未知扩展字段) 无损保全测试
{
    string trojanWithSha256 = """{"type":"trojan","tag":"t-sha","server":"1.1.1.1","server_port":443,"password":"pass","tls":{"enabled":true,"certificate_sha256":["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}}""";
    var node = JsonSerializer.Deserialize<SingboxOutbound>(trojanWithSha256) as TrojanOutbound;
    string reSerialized = JsonSerializer.Serialize<SingboxOutbound>(node!);
    Assert("8.1 未建模字段 certificate_sha256 往返无损保全", reSerialized.Contains("certificate_sha256", StringComparison.Ordinal) && reSerialized.Contains("e3b0c442", StringComparison.Ordinal));
}

Console.WriteLine("=================================================");
Console.WriteLine($"测试完成: {passed} / {total} 通过!");
Console.WriteLine("=================================================");

if (passed != total)
{
    Environment.Exit(1);
}

// 导出带有各种边界形态的综合配置并给 sing-box.exe 做终极 check
var allNodes = new SingboxOutbound[]
{
    new VlessOutbound
    {
        Tag = "vless-reality",
        Server = "127.0.0.1",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9661",
        Flow = "xtls-rprx-vision",
        Network = new[] { "tcp" },
        Tls = new OutboundTLSOptions
        {
            Enabled = true,
            ServerName = "www.apple.com",
            Alpn = new[] { "h2", "http/1.1" },
            Utls = new OutboundUTLSOptions { Enabled = true, Fingerprint = "chrome" },
            Reality = new OutboundRealityOptions
            {
                Enabled = true,
                PublicKey = "m58x9uUu6sH2Q_f2t3A3Wv3N3I7x6d2v_a5E_r8L-1A",
                ShortId = "0123456789abcdef"
            }
        }
    },
    new ShadowsocksOutbound
    {
        Tag = "ss-uot",
        Server = "1.2.3.4",
        ServerPort = 8388,
        Method = "aes-256-gcm",
        Password = "examplepassword",
        UdpOverTcp = new UdpOverTcpOptions { Enabled = true, Version = 2 }
    },
    new Hysteria2Outbound
    {
        Tag = "hy2-multiports",
        Server = "1.2.3.5",
        ServerPorts = new[] { "10000:20000" },
        Password = "hy2password",
        Tls = new OutboundTLSOptions { Enabled = true, ServerName = "hy2.example.com" }
    }
};

var fullConfig = new
{
    log = new { level = "warn" },
    inbounds = new[]
    {
        new { type = "mixed", tag = "mixed-in", listen = "127.0.0.1", listen_port = 20808 }
    },
    outbounds = allNodes.Concat<object>(new object[]
    {
        new { type = "direct", tag = "direct" },
        new { type = "selector", tag = "select", outbounds = allNodes.Select(n => n.Tag).Append("direct").ToArray() }
    }).ToArray()
};

string configJson = JsonSerializer.Serialize(fullConfig, new JsonSerializerOptions { WriteIndented = true });
string finalConfigPath = Path.Combine(AppContext.BaseDirectory, "reviewed_config.json");
File.WriteAllText(finalConfigPath, configJson);
Console.WriteLine($"终极配置已保存至: {finalConfigPath}");
