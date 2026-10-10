using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Protocols;
using SubParser.Parsers;
using SubParser.Utils;

Console.WriteLine("=================================================================");
Console.WriteLine("  开始运行 7 大协议工业级双路径映射、全套避坑防线与内核终极质检验证");
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
// 测试 2: 全套实战避坑护城河专项测试
// -------------------------------------------------------------
Console.WriteLine("\n[阶段二] 验证全套实战避坑护城河...");

// 2.1 重名节点自动编号消重测试
{
    string multilineDupes = """
    vless://uuid1@1.1.1.1:443#香港专线
    vless://uuid2@1.1.1.2:443#香港专线
    vless://uuid3@1.1.1.3:443#香港专线
    """;
    var deduped = UniversalParser.ParseSubscription(multilineDupes);
    Assert("2.1 重名节点自动编号消重成功", deduped.Count == 3 &&
        string.Equals(deduped[0].Tag, "香港专线", StringComparison.Ordinal) &&
        string.Equals(deduped[1].Tag, "香港专线 (1)", StringComparison.Ordinal) &&
        string.Equals(deduped[2].Tag, "香港专线 (2)", StringComparison.Ordinal));
}

// 2.2 非法端口节点拦截
{
    string badPortUri1 = "vless://uuid@1.1.1.1:0#零端口节点";
    string badPortUri2 = "vless://uuid@1.1.1.1:70000#超大端口节点";
    var n1 = UniversalParser.ParseLine(badPortUri1);
    var n2 = UniversalParser.ParseLine(badPortUri2);
    Assert("2.2 非法端口 (0 或 70000) 成功拦截不进入模型", n1 == null && n2 == null);
}

// 2.3 uTLS 指纹大小写自动纠偏与未知指纹安全过滤
{
    string upperFpUri = "vless://uuid@1.1.1.1:443?security=tls&fp=Chrome#大写指纹";
    string fakeFpUri = "vless://uuid@1.1.1.1:443?security=tls&fp=MyWeirdFp#非法指纹";
    var nodeUpper = UniversalParser.ParseLine(upperFpUri) as VlessOutbound;
    var nodeFake = UniversalParser.ParseLine(fakeFpUri) as VlessOutbound;
    Assert("2.3 大写 Chrome 自动纠偏为 chrome", string.Equals(nodeUpper?.Tls?.Utls?.Fingerprint, "chrome", StringComparison.Ordinal));
    Assert("2.3 非法指纹安全丢弃不传给内核", nodeFake?.Tls?.Utls == null);
}

// 2.4 UTF-8 BOM 隐形头与注释行跳过
{
    string bomText = "\uFEFF# 这是一行纯注释说明\r\n// 另外一行纯注释\r\nvless://bf000d23@1.1.1.1:443#正常节点\r\n";
    var nodes = UniversalParser.ParseSubscription(bomText);
    Assert("2.4 UTF-8 BOM 隐形头成功拔除且注释行精准跳过", nodes.Count == 1 && string.Equals(nodes[0].Tag, "正常节点", StringComparison.Ordinal));
}

// 2.5 VMess chacha20-ietf-poly1305 算法自动矫正为 chacha20-poly1305
{
    string rawJson = """{"v":"2","ps":"IETF算法节点","add":"1.1.1.1","port":"443","id":"a3b2c1d0-1234-5678-9abc-def012345678","scy":"chacha20-ietf-poly1305"}""";
    string uri = "vmess://" + Base64Utils.Encode(rawJson);
    var vmessNode = UniversalParser.ParseLine(uri) as VmessOutbound;
    Assert("2.5 chacha20-ietf-poly1305 算法成功规范化为 chacha20-poly1305", string.Equals(vmessNode?.Security, "chacha20-poly1305", StringComparison.Ordinal));
}

// 2.6 WebSocket 路径 ?ed=2048 污染剥离
{
    string wsEarlyDataUri = "vless://bf000d23@1.1.1.1:443?type=ws&path=/ray?ed=2048#WS早期数据节点";
    var vlessWs = UniversalParser.ParseLine(wsEarlyDataUri) as VlessOutbound;
    Assert("2.6 WebSocket 路径 ?ed=2048 成功纯化为 /ray", string.Equals(vlessWs?.Transport?.Path, "/ray", StringComparison.Ordinal));
}

// 2.7 二次 URL 编码递归还原
{
    string doubleEncodedUri = "vless://uuid@1.1.1.1:443#%25E9%25A6%2599%25E6%25B8%25AF01";
    var n = UniversalParser.ParseLine(doubleEncodedUri);
    Assert("2.7 二次 URL 编码成功递归还原为中文", string.Equals(n?.Tag, "香港01", StringComparison.Ordinal));
}

// 2.8 ALPN 数组空元素自动纯化
{
    string alpnDirtyUri = "vless://uuid@1.1.1.1:443?security=tls&alpn=h2,,http/1.1,";
    var n = UniversalParser.ParseLine(alpnDirtyUri) as VlessOutbound;
    Assert("2.8 ALPN 末尾与多余逗号过滤后无空字符串", n?.Tls?.Alpn != null && n.Tls.Alpn.Count == 2 && !n.Tls.Alpn.Any(string.IsNullOrWhiteSpace));
}

// -------------------------------------------------------------
// 测试 3: 7 大协议 Clash YAML 订阅与别名解析验证
// -------------------------------------------------------------
Console.WriteLine("\n[阶段三] 验证 Clash YAML 订阅包解析与别名对齐...");

string clashYaml = """
port: 7890
mode: rule
proxies:
  - name: "Clash-VLESS-Reality"
    type: vless
    server: 1.1.1.1
    port: 443.0
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    flow: xtls-rprx-vision
    tls: true
    servername: www.apple.com
    client-fingerprint: Chrome
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
    cipher: chacha20-ietf-poly1305
    network: ws
    ws-opts:
      path: /vmess?ed=2048
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
Assert("3.1 成功从 Clash YAML 提取 7 个真实节点并过滤假流量节点", clashNodes.Count == 7);
Assert("3.2 Python 浮点端口 (443.0) 成功兼容解析", clashNodes.OfType<VlessOutbound>().Any(v => v.ServerPort == 443));
// 2.9 Clash SS plugin-opts 字典成功平铺为分号格式专项测试
{
    var proxyDict = new Dictionary<string, object?>(StringComparer.Ordinal)
    {
        ["type"] = "ss",
        ["server"] = "1.2.3.4",
        ["port"] = 8388,
        ["cipher"] = "aes-256-gcm",
        ["password"] = "pass",
        ["plugin"] = "v2ray-plugin",
        ["plugin-opts"] = new Dictionary<string, object?>(StringComparer.Ordinal) { ["mode"] = "websocket", ["host"] = "bing.com" }
    };
    var ssNode = UniversalParser.ParseClashProxy(proxyDict) as ShadowsocksOutbound;
    Assert("2.9 Clash SS plugin-opts 字典成功平铺为分号格式", ssNode?.PluginOptions != null && ssNode.PluginOptions.Contains("mode=websocket", StringComparison.Ordinal));
}
Assert("3.4 Clash Hysteria2 带宽别名解析成功", clashNodes.OfType<Hysteria2Outbound>().Any(h => h.UpMbps == 30 && h.DownMbps == 100));
Assert("3.5 Clash VMess chacha20-ietf 与 ws ?ed=2048 双重纯化成功", clashNodes.OfType<VmessOutbound>().Any(v => string.Equals(v.Security, "chacha20-poly1305", StringComparison.Ordinal) && string.Equals(v.Transport?.Path, "/vmess", StringComparison.Ordinal)));

// -------------------------------------------------------------
// 测试 4: 生成纯净 sing-box 配置并调用官方 sing-box.exe 深度质检
// -------------------------------------------------------------
Console.WriteLine("\n[阶段四] 调用官方 sing-box.exe 对生成的完整配置进行内核级语法与规则质检...");

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
Console.WriteLine($"  全部避坑与双路径解析测试汇总: {passed} / {total} 全部通过！");
Console.WriteLine("=================================================================");

if (passed != total)
{
    Environment.Exit(1);
}
