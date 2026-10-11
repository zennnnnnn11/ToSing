using System;
using System.IO;
using System.Text.Json;
using SubParser.Models;
using SubParser.Parsers;

if (args.Length == 0)
{
    Console.WriteLine(
        "用法: ToSing <http(s)订阅链接 | 订阅文件路径 | Base64文本 | 单行URI> [更多链接/文件...]"
    );
    return;
}

// 支持传入多个参数，文件自动读取内容，与 URL/URI 混合拼接后统一进入聚合流水线
var inputs = new string[args.Length];
for (int i = 0; i < args.Length; i++)
{
    string arg = args[i];
    if (File.Exists(arg))
    {
        inputs[i] = await File.ReadAllTextAsync(arg).ConfigureAwait(false);
    }
    else
    {
        inputs[i] = arg;
    }
}

string combinedInput = string.Join(Environment.NewLine, inputs);
var (outbounds, _) = await UniversalParser
    .ParseMixedSubscriptionWithStatsAsync(combinedInput)
    .ConfigureAwait(false);

string json = JsonSerializer.Serialize(
    outbounds,
    SubParserJsonContext.Default.IReadOnlyListSingboxOutbound
);
Console.WriteLine(json);
