using System;
using System.IO;
using System.Text.Json;
using SubParser.Parsers;

if (args.Length == 0)
{
    Console.WriteLine("用法: SubParser <订阅链接|订阅文件路径|Base64文本>");
    return;
}

string input = args[0];
string content;

if (File.Exists(input))
{
    content = File.ReadAllText(input);
}
else
{
    content = input;
}

var outbounds = UniversalParser.ParseSubscription(content);

var options = new JsonSerializerOptions
{
    WriteIndented = true
};

string json = JsonSerializer.Serialize(outbounds, options);
Console.WriteLine(json);
