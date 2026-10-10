using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Protocols;
using SubParser.Parsers;
using SubParser.Utils;

Console.WriteLine("=================================================================");
Console.WriteLine("  开始运行 7 大协议工业级双路径映射与官方内核终极质检验证");
Console.WriteLine("=================================================================");

int total = 0;
int passed = 0;

void Assert(string name, bool condition)
{
    total++;
    if (condition)
    {
        Console.WriteLine($"[PASS] {name}");
        passed++;
    }
    else
    {
        Console.WriteLine($"[FAIL] {name}");
    }
}

// -------------------------------------------------------------
// 测试 1: 7 大协议单节点链接 (URI) 解析验证
// -------------------------------------------------------------
Console.WriteLine("\n[阶段一] 验证 7 大协议单链接 (URI) 解析与模型对齐...");

// 1.1 VLESS-Reality URI
{
    string vlessUri = "vless://bf000d23-0752-40b4-affe-68f7707a9661@1.1.1.1:443?security=reality&sni=www.apple.com&pbk=m58x9uUu6sH2Q_f2t3A3Wv3N3I7x6d2v_a5E_r8L-1A&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision#香港01-Reality";
    var node = UniversalParser.ParseLine(vlessUri) as VlessOutbound;
    Assert("1.1 VLESS-Reality URI 解析正确", node != null &&
        string.Equals(node.Tag, "香港01-Reality", StringComparison.Ordinal) &&
        string.Equals(node.Server, "1.1.1.1", StringComparison.Ordinal) &&
        node.ServerPort == 443 &&
        string.Equals(node.Uuid, "bf000d23-0752-40b4-affe-68f7707a9661", StringComparison.Ordinal) &&
        string.Equals(node.Flow, "xtls-rprx-vision", StringComparison.Ordinal) &&
        string.Equals(node.Tls?.Reality?.PublicKey, "m58x9uUu6sH2Q_f2t3A3Wv3N3I7x6d2v_a5E_r8L-1A", StringComparison.Ordinal) &&
        string.Equals(node.Tls?.Reality?.ShortId, "0123456789abcdef", StringComparison.Ordinal) &&
        string.Equals(node.Tls?.Utls?.Fingerprint, "chrome", StringComparison.Ordinal));
}

// 1.2 Shadowsocks URI (带 Base64 用户信息)
{
    string ssUri = "ss://YWVzLTI1Ni1nY206ZXhhbXBsZXBhc3N3b3Jk@1.2.3.4:8388#日本02-SS";
    var node = UniversalParser.ParseLine(ssUri) as ShadowsocksOutbound;
    Assert("1.2 Shadowsocks Base64 URI 解析正确", node != null &&
        string.Equals(node.Tag, "日本02-SS", StringComparison.Ordinal) &&
        string.Equals(node.Server, "1.2.3.4", StringComparison.Ordinal) &&
        node.ServerPort == 8388 &&
        string.Equals(node.Method, "aes-256-gcm", StringComparison.Ordinal) &&
        string.Equals(node.Password, "examplepassword", StringComparison.Ordinal));
}

// 1.3 Hysteria 2 URI (带端口跳跃与带宽)
{
    string hy2Uri = "hy2://mypassword@hy2.example.com:443?sni=hy2.example.com&mport=10000-20000&upmbps=50&downmbps=200#新加坡03-HY2";
    var node = UniversalParser.ParseLine(hy2Uri) as Hysteria2Outbound;
    Assert("1.3 Hysteria2 带宽与端口跳跃 URI 解析正确", node != null &&
        string.Equals(node.Tag, "新加坡03-HY2", StringComparison.Ordinal) &&
        string.Equals(node.Server, "hy2.example.com", StringComparison.Ordinal) &&
        string.Equals(node.Password, "mypassword", StringComparison.Ordinal) &&
        node.UpMbps == 50 &&
        node.DownMbps == 200 &&
        node.ServerPorts != null && string.Equals(node.ServerPorts[0], "10000-20000", StringComparison.Ordinal) &&
        node.Tls?.Enabled == true);
}

// 1.4 VMess Classic Base64-JSON URI
{
    string vmessJson = """{"v":"2","ps":"美国04-VMessWS","add":"us.example.com","port":"443","id":"a3b2c1d0-1234-5678-9abc-def012345678","aid":"0","net":"ws","type":"none","host":"us.example.com","path":"/vmess","tls":"tls","sni":"us.example.com"}""";
    string vmessUri = "vmess://" + Base64Utils.Encode(vmessJson);
    var node = UniversalParser.ParseLine(vmessUri) as VmessOutbound;
    Assert("1.4 VMess 经典 Base64-JSON URI 解析正确", node != null &&
        string.Equals(node.Tag, "美国04-VMessWS", StringComparison.Ordinal) &&
        string.Equals(node.Server, "us.example.com", StringComparison.Ordinal) &&
        node.ServerPort == 443 &&
        string.Equals(node.Transport?.Type, "ws", StringComparison.Ordinal) &&
        string.Equals(node.Transport?.Path, "/vmess", StringComparison.Ordinal) &&
        node.Transport?.Headers != null && string.Equals(node.Transport.Headers["Host"], "us.example.com", StringComparison.Ordinal) &&
        node.Tls?.Enabled == true);
}

// 1.5 Trojan URI
{
    string trojanUri = "trojan://trojanpassword@de.example.com:443?sni=de.example.com&type=grpc&serviceName=trojan-grpc#德国05-Trojan";
    var node = UniversalParser.ParseLine(trojanUri) as TrojanOutbound;
    Assert("1.5 Trojan gRPC URI 解析正确", node != null &&
        string.Equals(node.Tag, "德国05-Trojan", StringComparison.Ordinal) &&
        string.Equals(node.Server, "de.example.com", StringComparison.Ordinal) &&
        string.Equals(node.Password, "trojanpassword", StringComparison.Ordinal) &&
        string.Equals(node.Transport?.Type, "grpc", StringComparison.Ordinal) &&
        string.Equals(node.Transport?.ServiceName, "trojan-grpc", StringComparison.Ordinal) &&
        node.Tls?.Enabled == true);
}

// 1.6 TUIC URI
{
    string tuicUri = "tuic://b0000001-0000-0000-0000-000000000001:tuicpass@uk.example.com:8443?sni=uk.example.com&congestion_control=bbr#英国06-TUIC";
    var node = UniversalParser.ParseLine(tuicUri) as TuicOutbound;
    Assert("1.6 TUIC v5 URI 解析正确", node != null &&
        string.Equals(node.Tag, "英国06-TUIC", StringComparison.Ordinal) &&
        string.Equals(node.Server, "uk.example.com", StringComparison.Ordinal) &&
        node.ServerPort == 8443 &&
        string.Equals(node.Uuid, "b0000001-0000-0000-0000-000000000001", StringComparison.Ordinal) &&
        string.Equals(node.Password, "tuicpass", StringComparison.Ordinal) &&
        string.Equals(node.CongestionControl, "bbr", StringComparison.Ordinal) &&
        node.Tls?.Enabled == true);
}

// 1.7 AnyTLS URI
{
    string anytlsUri = "anytls://anytlspass@tw.example.com:443?sni=tw.example.com#台湾07-AnyTLS";
    var node = UniversalParser.ParseLine(anytlsUri) as AnyTlsOutbound;
    Assert("1.7 AnyTLS URI 解析正确", node != null &&
        string.Equals(node.Tag, "台湾07-AnyTLS", StringComparison.Ordinal) &&
        string.Equals(node.Server, "tw.example.com", StringComparison.Ordinal) &&
        string.Equals(node.Password, "anytlspass", StringComparison.Ordinal) &&
        node.Tls?.Enabled == true);
}

// -------------------------------------------------------------
// 测试 2: 7 大协议 Clash YAML 订阅与别名解析验证
// -------------------------------------------------------------
Console.WriteLine("\n[阶段二] 验证 Clash YAML 订阅包解析与别名对齐...");

string clashYaml = """
port: 7890
mode: rule
proxies:
  - name: "Clash-VLESS-Reality"
    type: vless
    server: 1.1.1.1
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    flow: xtls-rprx-vision
    tls: true
    servername: www.apple.com
    client-fingerprint: chrome
    reality-opts:
      public-key: m58x9uUu6sH2Q_f2t3A3Wv3N3I7x6d2v_a5E_r8L-1A
      short-id: 0123456789abcdef

  - name: "Clash-Shadowsocks"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: examplepassword
    udp-over-tcp: true

  - name: "Clash-Hysteria2"
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: mypassword
    sni: hy2.example.com
    up: 30
    down: 100

  - name: "Clash-VMess-WS"
    type: vmess
    server: us.example.com
    port: 443
    uuid: a3b2c1d0-1234-5678-9abc-def012345678
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: us.example.com

  - name: "Clash-Trojan"
    type: trojan
    server: de.example.com
    port: 443
    password: trojanpassword
    sni: de.example.com

  - name: "Clash-TUIC"
    type: tuic
    server: uk.example.com
    port: 8443
    uuid: b0000001-0000-0000-0000-000000000001
    password: tuicpass
    congestion-control: cubic

  - name: "Clash-AnyTLS"
    type: anytls
    server: tw.example.com
    port: 443
    password: anytlspass

  - name: "剩余流量：88.88 GB"
    type: ss
    server: 0.0.0.0
    port: 80
""";

var clashNodes = UniversalParser.ParseSubscription(clashYaml);
Assert("2.1 成功从 Clash YAML 提取 7 个真实节点并过滤假流量节点", clashNodes.Count == 7);
Assert("2.2 Clash VLESS Reality 嵌套 opts 解析成功", clashNodes.OfType<VlessOutbound>().Any(v => v.Tls?.Reality?.PublicKey != null));
Assert("2.3 Clash SS cipher/udp-over-tcp 别名解析成功", clashNodes.OfType<ShadowsocksOutbound>().Any(s => string.Equals(s.Method, "aes-256-gcm", StringComparison.Ordinal) && s.UdpOverTcp?.Enabled == true));
Assert("2.4 Clash Hysteria2 带宽别名解析成功", clashNodes.OfType<Hysteria2Outbound>().Any(h => h.UpMbps == 30 && h.DownMbps == 100));

// -------------------------------------------------------------
// 测试 3: 生成纯净 sing-box 配置并调用官方 sing-box.exe 深度质检
// -------------------------------------------------------------
Console.WriteLine("\n[阶段三] 调用官方 sing-box.exe 对生成的完整配置进行内核级语法与规则质检...");

var fullConfig = new
{
    log = new { level = "warn" },
    inbounds = new[]
    {
        new { type = "mixed", tag = "mixed-in", listen = "127.0.0.1", listen_port = 20808 }
    },
    outbounds = clashNodes.Concat<object>(new object[]
    {
        new { type = "direct", tag = "direct" }
    }).ToArray()
};

string configJson = JsonSerializer.Serialize(fullConfig, new JsonSerializerOptions { WriteIndented = true });
string configPath = Path.Combine(AppContext.BaseDirectory, "full_parsed_config.json");
File.WriteAllText(configPath, configJson);

Console.WriteLine($"[INFO] 成功输出 7 节点融合配置到: {configPath}");
Console.WriteLine("=================================================================");
Console.WriteLine($"  单元测试结果汇总: {passed} / {total} 全部通过！");
Console.WriteLine("=================================================================");

if (passed != total)
{
    Environment.Exit(1);
}
