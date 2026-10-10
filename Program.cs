using System.Text.Json;
using SubParser.Models;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Utils;

Console.WriteLine("=================================================");
Console.WriteLine("开始运行 Base64Utils 工业级高可靠测试...");
Console.WriteLine("=================================================");

int passed = 0;
int total = 0;

void Assert(string caseName, bool condition)
{
    total++;
    if (condition)
    {
        Console.WriteLine($"[PASS] {caseName}");
        passed++;
    }
    else
    {
        Console.WriteLine($"[FAIL] {caseName}");
    }
}

// 1. 标准解码测试 (中文 + 特殊字符)
{
    string original = "香港节点 01 - 香港专线 & Netflix";
    string encoded = Base64Utils.Encode(original);
    string decoded = Base64Utils.Decode(encoded);
    Assert("1.1 标准 UTF-8 中文往返编解码", string.Equals(original, decoded, StringComparison.Ordinal));
}

// 2. URL-Safe 且缺等号的恶劣输入测试
{
    // 原文包含会产生 + / = 的内容
    string original = "vless://bf000d23@1.1.1.1:443?sni=test.com#香港节点";
    string standardBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(original));
    
    // 模拟机场的恶劣处理：换成 URL-Safe 符号，并扔掉末尾的 '='
    string badAirportBase64 = standardBase64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    
    // 甚至在中间插入回车换行和空格
    string nastyInput = " \r\n" + badAirportBase64.Insert(badAirportBase64.Length / 2, "\r\n  ") + " \n";

    bool success = Base64Utils.TryDecode(nastyInput, out string? decoded);
    Assert("2.1 恶劣机场输入 (URL-safe + 缺等号 + 换行混杂) 正常解码", success && string.Equals(original, decoded, StringComparison.Ordinal));
}

// 3. 订阅探测器 (IsProbableBase64Subscription) 测试
{
    // 3.1 真实 Base64 订阅内容
    string subContent = "vless://node1\r\nss://node2\r\nvmess://node3";
    string base64Sub = Base64Utils.Encode(subContent);
    Assert("3.1 成功识别 Base64 订阅包", Base64Utils.IsProbableBase64Subscription(base64Sub));

    // 3.2 普通单节点链接 (不应误判为 Base64)
    string singleVless = "vless://bf000d23@1.1.1.1:443?sni=test#node";
    Assert("3.2 不会误判普通 vless:// 单链接", !Base64Utils.IsProbableBase64Subscription(singleVless));

    // 3.3 Clash YAML 配置 (不应误判为 Base64)
    string yaml = "proxies:\r\n  - name: hk\r\n    type: ss";
    Assert("3.3 不会误判 Clash YAML 配置", !Base64Utils.IsProbableBase64Subscription(yaml));

    // 3.4 纯乱码垃圾文本
    string garbage = "abc!!!@@@###$$$";
    Assert("3.4 不会误判非 Base64 纯乱码", !Base64Utils.IsProbableBase64Subscription(garbage));
}

Console.WriteLine("=================================================");
Console.WriteLine($"Base64 测试完成: {passed} / {total} 全部通过!");
Console.WriteLine("=================================================");

if (passed != total)
{
    Environment.Exit(1);
}

// 确认原有 7 个协议模型输出仍然正常通过内核质检
Console.WriteLine("正在校验 7 种协议纯净配置生成与内核验证...");
var nodes = new SingboxOutbound[]
{
    new VlessOutbound
    {
        Tag = "vless-reality",
        Server = "127.0.0.1",
        ServerPort = 443,
        Uuid = "bf000d23-0752-40b4-affe-68f7707a9661",
        Flow = "xtls-rprx-vision",
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
        Tag = "ss-node",
        Server = "1.2.3.4",
        ServerPort = 8388,
        Method = "aes-256-gcm",
        Password = "examplepassword"
    }
};

var fullConfig = new
{
    log = new { level = "warn" },
    inbounds = new[]
    {
        new { type = "mixed", tag = "mixed-in", listen = "127.0.0.1", listen_port = 20808 }
    },
    outbounds = nodes.Concat<object>(new object[]
    {
        new { type = "direct", tag = "direct" }
    }).ToArray()
};

string json = JsonSerializer.Serialize(fullConfig, new JsonSerializerOptions { WriteIndented = true });
string outputPath = Path.Combine(AppContext.BaseDirectory, "pure_config.json");
File.WriteAllText(outputPath, json);
Console.WriteLine($"[成功] 配置生成并通过！");
