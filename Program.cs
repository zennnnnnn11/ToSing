using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using SubParser.Models;
using SubParser.Parsers;

if (args.Length == 0)
{
    Console.WriteLine("用法: SubParser <http(s)订阅链接 | 订阅文件路径 | Base64文本 | 单行URI>");
    return;
}

string input = args[0];
string content;

if (
    Uri.TryCreate(input, UriKind.Absolute, out Uri? uri)
    && (
        string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
        || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
    )
)
{
    using var handler = new SocketsHttpHandler
    {
        UseProxy = true,
        Proxy = WebRequest.GetSystemWebProxy(),
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(1),
    };
    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
    client.DefaultRequestHeaders.UserAgent.ParseAdd("clash.meta");
    client.DefaultRequestHeaders.Accept.ParseAdd("*/*");

    try
    {
        content = await client.GetStringAsync(uri).ConfigureAwait(false);
    }
    catch
    {
        using var browserClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
        browserClient.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
        );
        content = await browserClient.GetStringAsync(uri).ConfigureAwait(false);
    }
}
else if (File.Exists(input))
{
    content = await File.ReadAllTextAsync(input).ConfigureAwait(false);
}
else
{
    content = input;
}

var outbounds = UniversalParser.ParseSubscription(content);

string json = JsonSerializer.Serialize(
    outbounds,
    SubParserJsonContext.Default.IReadOnlyListSingboxOutbound
);
Console.WriteLine(json);
