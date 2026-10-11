namespace ToSing.Utils;

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// 工业级订阅抓取器：支持系统代理、全流式解压、双 User-Agent 智能回退。
/// </summary>
public static class SubscriptionFetcher
{
    private static readonly HttpClient SharedClashClient = CreateClashClient();

    private static HttpClient CreateClashClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = true,
            Proxy = WebRequest.GetSystemWebProxy(),
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("clash.meta");
        client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
        return client;
    }

    /// <summary>
    /// 拉取远程订阅内容，优先使用 clash.meta 伪装，失败时平滑降级为 Chrome 浏览器 UA 重试。
    /// </summary>
    public static async Task<string?> FetchAsync(Uri uri, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        try
        {
            return await SharedClashClient.GetStringAsync(uri, ct).ConfigureAwait(false);
        }
        catch
        {
            // 降级回退：使用 Chrome 浏览器 User-Agent 避开某些机场的反爬/非标准限制
            using var browserHandler = new SocketsHttpHandler
            {
                UseProxy = true,
                Proxy = WebRequest.GetSystemWebProxy(),
                AutomaticDecompression = DecompressionMethods.All,
            };
            using var browserClient = new HttpClient(browserHandler)
            {
                Timeout = TimeSpan.FromSeconds(25),
            };
            browserClient.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
            );
            browserClient.DefaultRequestHeaders.Accept.ParseAdd("*/*");
            return await browserClient.GetStringAsync(uri, ct).ConfigureAwait(false);
        }
    }
}
