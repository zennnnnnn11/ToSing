namespace ToSing.Parsers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ToSing.Models;
using ToSing.Parsers.Protocols;
using ToSing.Utils;
using YamlDotNet.Serialization;

/// <summary>
/// 通用订阅与节点解析调度引擎。
/// 支持处理单链接、多行链接、Base64 订阅及 Clash YAML 配置中的 proxies 列表。
/// </summary>
public static partial class UniversalParser
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithObjectFactory(new AotObjectFactory())
        .IgnoreUnmatchedProperties()
        .Build();

    private sealed class AotObjectFactory
        : YamlDotNet.Serialization.ObjectFactories.DefaultObjectFactory
    {
        public override object Create(Type type)
        {
            if (type == typeof(Dictionary<string, object>))
                return new Dictionary<string, object>(StringComparer.Ordinal);
            if (type == typeof(Dictionary<object, object>))
                return new Dictionary<object, object>();
            if (type == typeof(List<object>))
                return new List<object>();
            return base.Create(type);
        }
    }

    /// <summary>
    /// 根据 NodeContext 的 Protocol 调度解析出站节点。
    /// </summary>
    public static SingboxOutbound? ParseContext(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string proto = ctx.Protocol.ToLowerInvariant();
        string rawType = ctx.GetRaw("type") is string t
            ? t.Trim().ToLowerInvariant()
            : string.Empty;
        string netType = ctx.GetRaw("network") is string n
            ? n.Trim().ToLowerInvariant()
            : string.Empty;
        if (string.IsNullOrEmpty(netType) && ctx.GetRaw("net") is string nt)
        {
            netType = nt.Trim().ToLowerInvariant();
        }
        if (netType is "xhttp" || rawType is "xhttp")
            return null;

        SingboxOutbound? outbound = proto switch
        {
            "vless" => VlessParser.Parse(ctx),
            "ss" or "shadowsocks" => ShadowsocksParser.Parse(ctx),
            "hy2" or "hysteria2" => Hysteria2Parser.Parse(ctx),
            "vmess" => VmessParser.Parse(ctx),
            "trojan" => TrojanParser.Parse(ctx),
            "tuic" => TuicParser.Parse(ctx),
            "anytls" => AnyTlsParser.Parse(ctx),
            _ => null,
        };

        if (outbound == null)
            return null;
        outbound = ApplyCommonDialerOptions(outbound, ctx);
        SingboxContractValidator.Validate(outbound);
        return outbound;
    }

    /// <summary>
    /// 解析单行节点 URI 链接。
    /// </summary>
    public static SingboxOutbound? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        string trimmed = CleanRawText(line);
        if (IsCommentLine(trimmed))
            return null;

        if (trimmed.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            var ctx = VmessParser.ParseVmessJsonUri(trimmed);
            return ParseContext(ctx);
        }

        try
        {
            var ctx = NodeContext.FromUri(trimmed);
            return ParseContext(ctx);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 解析 Clash YAML 的单个代理节点字典。
    /// </summary>
    public static SingboxOutbound? ParseClashProxy(IReadOnlyDictionary<string, object?> proxy)
    {
        if (proxy == null || proxy.Count == 0)
            return null;

        var ctx = NodeContext.FromClash(proxy);
        return ParseContext(ctx);
    }

    /// <summary>
    /// 解析订阅内容，自动识别 Clash YAML、Base64 订阅或多行 URI。
    /// </summary>
    public static IReadOnlyList<SingboxOutbound> ParseSubscription(
        string rawText,
        bool filterAds = true
    )
    {
        return ParseSubscriptionWithStats(rawText, filterAds).Outbounds;
    }

    public static readonly string[] DefaultFilterKeywords =
    [
        "网址",
        "官网",
        "发布页",
        "流量",
        "剩余",
        "到期",
        "时间",
        "重置",
        "过期",
        "通知",
        "公告",
        "bandwidth",
        "traffic",
        "expire",
    ];

    private enum YamlScanState
    {
        Normal,
        InProxies,
        InOtherSection,
    }

    /// <summary>
    /// 全能混合多源订阅与节点聚合流水线。
    /// 自动对齐处理包含多个远程 HTTP(S) 订阅、完整/局部 Clash YAML、单行/多行节点 URI 及 Base64 密文的混合输入。
    /// </summary>
    public static async Task<(
        IReadOnlyList<SingboxOutbound> Outbounds,
        int FilteredAdCount
    )> ParseMixedSubscriptionWithStatsAsync(
        string rawInput,
        Func<Uri, Task<string?>>? remoteFetcher = null,
        bool filterAds = true,
        IReadOnlyCollection<string>? filterKeywords = null,
        CancellationToken ct = default
    )
    {
        var allOutbounds = new List<SingboxOutbound>();
        int totalFiltered = 0;

        if (string.IsNullOrWhiteSpace(rawInput))
            return (allOutbounds, 0);

        string content = CleanRawText(rawInput);

        // 如果整段文本是一个完整的纯 Base64 订阅大包
        if (Base64Utils.IsProbableBase64Subscription(content))
        {
            string decoded = Base64Utils.Decode(content);
            if (!string.IsNullOrWhiteSpace(decoded))
            {
                content = CleanRawText(decoded);
            }
        }

        // 如果整段文本是以大括号包裹的纯 JSON 格式配置 (例如 multi-proxy 的 JSON 格式 Clash 订阅)
        string trimmedContent = content.Trim();
        if (
            trimmedContent.Length >= 2
            && trimmedContent[0] == '{'
            && trimmedContent[^1] == '}'
            && (
                trimmedContent.Contains("\"proxies\"", StringComparison.OrdinalIgnoreCase)
                || trimmedContent.Contains("proxies:", StringComparison.OrdinalIgnoreCase)
            )
        )
        {
            var (directNodes, directFiltered) = ParseClashYamlWithStats(
                content,
                filterAds,
                filterKeywords
            );
            if (directNodes.Count > 0 || directFiltered > 0)
            {
                return (DeduplicateTags(directNodes), directFiltered);
            }
        }

        var remoteUrls = new HashSet<Uri>();
        var directNodeLines = new List<string>();

        using var reader = new StringReader(content);
        string? rawLine;
        var yamlBuilder = new StringBuilder();
        var scanState = YamlScanState.Normal;

        while ((rawLine = await reader.ReadLineAsync(ct).ConfigureAwait(false)) != null)
        {
            ct.ThrowIfCancellationRequested();

            // 剥离行尾注释后再判断有效语法结构
            string codePart = StripLineComment(rawLine).TrimEnd();

            // 判断是否是顶级 YAML 键（顶格未缩进、不是注释、代码主体不含 :// 协议前缀、匹配键名）
            bool isTopLevelKey =
                !string.IsNullOrWhiteSpace(codePart)
                && !char.IsWhiteSpace(codePart[0])
                && !codePart.StartsWith("- ", StringComparison.Ordinal)
                && !codePart.Contains("://", StringComparison.Ordinal)
                && TopLevelYamlKeyRegex().IsMatch(codePart);

            if (isTopLevelKey)
            {
                // 如果当前已经在收集 proxies 块，立即提交解析
                if (scanState == YamlScanState.InProxies && yamlBuilder.Length > 0)
                {
                    var (yamlNodes, yamlFiltered) = ParseClashYamlWithStats(
                        yamlBuilder.ToString(),
                        filterAds,
                        filterKeywords
                    );
                    allOutbounds.AddRange(yamlNodes);
                    totalFiltered += yamlFiltered;
                    yamlBuilder.Clear();
                }

                // 判断是否是 proxies: 节
                if (ProxiesBlockRegex().IsMatch(codePart))
                {
                    scanState = YamlScanState.InProxies;
                    yamlBuilder.AppendLine(rawLine);
                }
                else
                {
                    // 进入其他顶级 YAML 节（如 rules:, rule-providers:, dns: 等）
                    scanState = YamlScanState.InOtherSection;
                }
                continue;
            }

            switch (scanState)
            {
                case YamlScanState.InProxies:
                    if (string.IsNullOrWhiteSpace(rawLine) || IsCommentLine(rawLine.Trim()))
                    {
                        yamlBuilder.AppendLine(rawLine);
                    }
                    else if (
                        rawLine.StartsWith("  ", StringComparison.Ordinal)
                        || (rawLine.Length > 0 && rawLine[0] == '\t')
                        || rawLine.TrimStart().StartsWith("- ", StringComparison.Ordinal)
                    )
                    {
                        yamlBuilder.AppendLine(rawLine);
                    }
                    else
                    {
                        // 缩进归零：退出 proxies 块
                        scanState = YamlScanState.Normal;
                        var (yamlNodes, yamlFiltered) = ParseClashYamlWithStats(
                            yamlBuilder.ToString(),
                            filterAds,
                            filterKeywords
                        );
                        allOutbounds.AddRange(yamlNodes);
                        totalFiltered += yamlFiltered;
                        yamlBuilder.Clear();

                        ProcessNormalLine(rawLine, remoteUrls, directNodeLines);
                    }
                    break;

                case YamlScanState.InOtherSection:
                    // 在非 proxies 的 YAML 节中，下属缩进行、列表项全部静默跳过
                    if (
                        string.IsNullOrWhiteSpace(rawLine)
                        || IsCommentLine(rawLine.Trim())
                        || rawLine.StartsWith("  ", StringComparison.Ordinal)
                        || (rawLine.Length > 0 && rawLine[0] == '\t')
                        || rawLine.TrimStart().StartsWith("- ", StringComparison.Ordinal)
                    )
                    {
                        continue;
                    }

                    // 缩进归零：退出 OtherSection 状态
                    scanState = YamlScanState.Normal;
                    ProcessNormalLine(rawLine, remoteUrls, directNodeLines);
                    break;

                case YamlScanState.Normal:
                    ProcessNormalLine(rawLine, remoteUrls, directNodeLines);
                    break;
            }
        }

        // 文件读完后，如果最后还处于 proxies 块中
        if (scanState == YamlScanState.InProxies && yamlBuilder.Length > 0)
        {
            var (yamlNodes, yamlFiltered) = ParseClashYamlWithStats(
                yamlBuilder.ToString(),
                filterAds,
                filterKeywords
            );
            allOutbounds.AddRange(yamlNodes);
            totalFiltered += yamlFiltered;
            yamlBuilder.Clear();
        }

        // 并发拉取所有远程订阅 URL
        if (remoteUrls.Count > 0)
        {
            var fetchTasks = remoteUrls.Select(async url =>
            {
                try
                {
                    string? subContent =
                        remoteFetcher != null
                            ? await remoteFetcher(url).ConfigureAwait(false)
                            : await SubscriptionFetcher.FetchAsync(url, ct).ConfigureAwait(false);

                    if (!string.IsNullOrWhiteSpace(subContent))
                    {
                        return ParseSubscriptionWithStats(subContent, filterAds, filterKeywords);
                    }
                }
                catch
                {
                    // 单个订阅拉取失败隔离，绝不影响其他订阅与节点
                }

                return (
                    Outbounds: (IReadOnlyList<SingboxOutbound>)Array.Empty<SingboxOutbound>(),
                    FilteredAdCount: 0
                );
            });

            var fetchedResults = await Task.WhenAll(fetchTasks).ConfigureAwait(false);
            foreach (var result in fetchedResults)
            {
                allOutbounds.AddRange(result.Outbounds);
                totalFiltered += result.FilteredAdCount;
            }
        }

        // 逐行解析所有本地直连节点 URI
        foreach (string uriLine in directNodeLines)
        {
            try
            {
                var outbound = ParseLine(uriLine);
                if (outbound != null)
                {
                    if (filterAds && IsFakeOrAdNode(outbound.Tag, filterKeywords))
                    {
                        totalFiltered++;
                    }
                    else
                    {
                        allOutbounds.Add(outbound);
                    }
                }
            }
            catch
            {
                // 隔离单行异常
            }
        }

        // 全局节点统一去重
        var deduplicated = DeduplicateTags(allOutbounds);
        return (deduplicated, totalFiltered);
    }

    private static void ProcessNormalLine(
        string rawLine,
        HashSet<Uri> remoteUrls,
        List<string> directNodeLines
    )
    {
        string trimmed = CleanRawText(rawLine);
        if (string.IsNullOrWhiteSpace(trimmed) || IsCommentLine(trimmed))
            return;

        // 1. 优先判定已知代理协议前缀：整行作为单行节点，内部任何子字符串绝不外泄
        if (IsKnownProtocolUri(trimmed))
        {
            directNodeLines.Add(trimmed);
            return;
        }

        // 2. 判定 Base64 编码行
        if (Base64Utils.IsProbableBase64Subscription(trimmed))
        {
            string decoded = Base64Utils.Decode(trimmed);
            if (!string.IsNullOrWhiteSpace(decoded))
            {
                using var subReader = new StringReader(decoded);
                string? subLine;
                while ((subLine = subReader.ReadLine()) != null)
                {
                    ProcessNormalLine(subLine, remoteUrls, directNodeLines);
                }
                return;
            }
        }

        // 3. 严格判定独立订阅 URL
        if (TryExtractSubscriptionUrls(trimmed, out var extractedUrls))
        {
            foreach (var url in extractedUrls)
            {
                remoteUrls.Add(url);
            }
        }
    }

    private static bool TryExtractSubscriptionUrls(string line, out List<Uri> urls)
    {
        urls = [];

        // 排除 YAML 列表项
        if (line.StartsWith("- ", StringComparison.Ordinal))
        {
            return false;
        }

        // 按空白、管道符、分号、逗号切分 token
        string[] tokens = line.Split(
            [' ', '\t', '|', ';', ','],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
        );
        if (tokens.Length == 0)
            return false;

        var temp = new List<Uri>(tokens.Length);
        foreach (string token in tokens)
        {
            if (
                Uri.TryCreate(token, UriKind.Absolute, out Uri? uri)
                && IsProbableSubscriptionUrl(uri)
            )
            {
                temp.Add(uri);
            }
            else
            {
                // 只要任何一个 token 不是合法的订阅 HTTP(S) URL，整行就绝对不能被当作订阅 URL
                return false;
            }
        }

        urls = temp;
        return urls.Count > 0;
    }

    private static bool IsProbableSubscriptionUrl(Uri uri)
    {
        if (
            !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        )
        {
            return false;
        }

        // 含有用户名密码凭据（UserInfo），属于 HTTP 代理节点而非订阅地址
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        // 远程订阅链接必须具有实质性的请求路径（非根路径 "/"）或查询参数
        // 纯根路径 "/" 且没有 query 参数的，属于 HTTP(S) 代理节点
        bool hasSubPath =
            uri.AbsolutePath.Length > 1
            && !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal);
        bool hasQuery = !string.IsNullOrEmpty(uri.Query);

        if (!hasSubPath && !hasQuery)
        {
            return false;
        }

        return true;
    }

    private static string StripLineComment(string line)
    {
        int commentIdx = line.IndexOf('#', StringComparison.Ordinal);
        if (commentIdx < 0)
            return line;
        return line[..commentIdx];
    }

    private static bool IsKnownProtocolUri(string line)
    {
        return line.StartsWith("vless://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("ss://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("shadowsocks://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("anytls://", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 解析订阅内容并返回节点列表和过滤的广告节点统计。
    /// </summary>
    public static (
        IReadOnlyList<SingboxOutbound> Outbounds,
        int FilteredAdCount
    ) ParseSubscriptionWithStats(
        string rawText,
        bool filterAds = true,
        IReadOnlyCollection<string>? filterKeywords = null
    )
    {
        var rawNodes = new List<SingboxOutbound>();
        int filteredAdCount = 0;
        if (string.IsNullOrWhiteSpace(rawText))
            return (rawNodes, 0);

        string content = CleanRawText(rawText);

        if (
            content.Contains("proxies:", StringComparison.OrdinalIgnoreCase)
            || content.Contains("\"proxies\"", StringComparison.OrdinalIgnoreCase)
            || content.Contains("'proxies'", StringComparison.OrdinalIgnoreCase)
        )
        {
            var (yamlNodes, yamlFiltered) = ParseClashYamlWithStats(
                content,
                filterAds,
                filterKeywords
            );
            if (yamlNodes.Count > 0 || yamlFiltered > 0)
            {
                return (DeduplicateTags(yamlNodes), yamlFiltered);
            }
        }

        if (Base64Utils.IsProbableBase64Subscription(content))
        {
            string decoded = Base64Utils.Decode(content);
            if (!string.IsNullOrWhiteSpace(decoded))
            {
                content = CleanRawText(decoded);
            }
        }

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            string trimmed = CleanRawText(line);
            if (string.IsNullOrWhiteSpace(trimmed) || IsCommentLine(trimmed))
                continue;

            SingboxOutbound? outbound = null;
            try
            {
                outbound = ParseLine(trimmed);
            }
            catch
            {
                // 隔离单行格式异常
            }

            if (outbound != null)
            {
                if (filterAds && IsFakeOrAdNode(outbound.Tag, filterKeywords))
                {
                    filteredAdCount++;
                }
                else
                {
                    rawNodes.Add(outbound);
                }
            }
        }

        return (DeduplicateTags(rawNodes), filteredAdCount);
    }

    private static (List<SingboxOutbound> Outbounds, int FilteredAdCount) ParseClashYamlWithStats(
        string content,
        bool filterAds,
        IReadOnlyCollection<string>? filterKeywords = null
    )
    {
        var results = new List<SingboxOutbound>();
        int filteredCount = 0;
        try
        {
            var yamlData = YamlDeserializer.Deserialize<Dictionary<string, object>>(content);
            if (
                yamlData != null
                && yamlData.TryGetValue("proxies", out object? proxiesObj)
                && proxiesObj is IEnumerable<object> proxyList
            )
            {
                foreach (object item in proxyList)
                {
                    try
                    {
                        if (item is Dictionary<object, object> objMap)
                        {
                            var stringMap =
                                (Dictionary<string, object?>)NormalizeYamlObject(objMap)!;
                            var outbound = ParseClashProxy(stringMap);
                            if (outbound != null)
                            {
                                if (filterAds && IsFakeOrAdNode(outbound.Tag, filterKeywords))
                                {
                                    filteredCount++;
                                }
                                else
                                {
                                    results.Add(outbound);
                                }
                            }
                        }
                    }
                    catch
                    {
                        // 局部隔离单个畸形节点的异常，绝不中断后续节点解析
                    }
                }
            }
        }
        catch
        {
            // 忽略 YAML 解析异常并返回已解析项
        }
        return (results, filteredCount);
    }

    /// <summary>
    /// 对同名节点追加递增编号后缀，确保出站标签全局唯一。
    /// </summary>
    public static IReadOnlyList<SingboxOutbound> DeduplicateTags(
        IReadOnlyList<SingboxOutbound> nodes
    )
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var result = new List<SingboxOutbound>(nodes.Count);

        foreach (var node in nodes)
        {
            string originalTag = !string.IsNullOrWhiteSpace(node.Tag) ? node.Tag : "Proxy";
            if (seen.Add(originalTag))
            {
                counts[originalTag] = 1;
                result.Add(
                    string.Equals(node.Tag, originalTag, StringComparison.Ordinal)
                        ? node
                        : node with
                        {
                            Tag = originalTag,
                        }
                );
            }
            else
            {
                int index = counts.TryGetValue(originalTag, out int c) ? c : 1;
                string newTag;
                do
                {
                    newTag = $"{originalTag} ({index.ToString(CultureInfo.InvariantCulture)})";
                    index++;
                } while (!seen.Add(newTag));

                counts[originalTag] = index;
                result.Add(node with { Tag = newTag });
            }
        }

        return result;
    }

    private static SingboxOutbound ApplyCommonDialerOptions(SingboxOutbound node, NodeContext ctx)
    {
        var dialer = NativeOptionsParser.Read<ParsedDialerOptions>(
            ctx,
            ("tfo", "tcp_fast_open"),
            ("fast-open", "tcp_fast_open"),
            ("fastopen", "tcp_fast_open"),
            ("dialer-proxy", "detour"),
            ("interface-name", "bind_interface"),
            ("mptcp", "tcp_multi_path")
        );
        return node with
        {
            Detour = dialer.Detour,
            DomainStrategy = dialer.DomainStrategy,
            TcpFastOpen = dialer.TcpFastOpen,
            ConnectTimeout = dialer.ConnectTimeout,
            BindInterface = dialer.BindInterface,
            Inet4BindAddress = dialer.Inet4BindAddress,
            Inet6BindAddress = dialer.Inet6BindAddress,
            RoutingMark = dialer.RoutingMark,
            ReuseAddr = dialer.ReuseAddr,
            TcpMultiPath = dialer.TcpMultiPath,
            UdpFragment = dialer.UdpFragment,
            DomainResolver = dialer.DomainResolver,
            BindAddressNoPort = dialer.BindAddressNoPort,
            ProtectPath = dialer.ProtectPath,
            NetNs = dialer.NetNs,
            DisableTcpKeepAlive = dialer.DisableTcpKeepAlive,
            TcpKeepAlive = dialer.TcpKeepAlive,
            TcpKeepAliveInterval = dialer.TcpKeepAliveInterval,
            NetworkStrategy = dialer.NetworkStrategy,
            NetworkType = dialer.NetworkType,
            FallbackNetworkType = dialer.FallbackNetworkType,
            FallbackDelay = dialer.FallbackDelay,
        };
    }

    private static object? NormalizeYamlObject(object? obj)
    {
        if (obj is IDictionary<object, object> dict)
        {
            var map = new Dictionary<string, object?>(dict.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var kv in dict)
            {
                if (kv.Key != null)
                {
                    map[kv.Key.ToString()!] = NormalizeYamlObject(kv.Value);
                }
            }
            return map;
        }
        if (obj is IList<object> list)
        {
            var resultList = new List<object?>(list.Count);
            foreach (var item in list)
            {
                resultList.Add(NormalizeYamlObject(item));
            }
            return resultList;
        }
        return obj;
    }

    /// <summary>
    /// 移除 UTF-8 BOM 及首尾空白字符。
    /// </summary>
    public static string CleanRawText(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return string.Empty;
        return raw.Trim('\uFEFF', '\u200B', ' ', '\r', '\n', '\t');
    }

    private static bool IsCommentLine(string line)
    {
        if (line.Length == 0)
            return true;
        bool startsWithComment =
            line[0] == '#' || line.StartsWith("//", StringComparison.Ordinal) || line[0] == ';';
        return startsWithComment && !line.Contains("://", StringComparison.Ordinal);
    }

    [GeneratedRegex(
        @"^\s*[""']?proxies[""']?\s*:",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000
    )]
    private static partial Regex ProxiesBlockRegex();

    [GeneratedRegex(
        @"^\s*[""']?[a-zA-Z0-9_-]+[""']?\s*:",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000
    )]
    private static partial Regex TopLevelYamlKeyRegex();

    [GeneratedRegex(
        @"(?i)(?:网址|官网|发布页|流量|剩余|到期|时间|重置|过期|通知|公告|bandwidth|traffic|expire)",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        matchTimeoutMilliseconds: 1000
    )]
    private static partial Regex FakeOrAdNodeRegex();

    private static bool IsFakeOrAdNode(
        string? tag,
        IReadOnlyCollection<string>? customKeywords = null
    )
    {
        if (string.IsNullOrWhiteSpace(tag))
            return false;

        if (customKeywords != null)
        {
            if (customKeywords.Count == 0)
                return false;

            foreach (string word in customKeywords)
            {
                if (
                    !string.IsNullOrWhiteSpace(word)
                    && tag.Contains(word, StringComparison.OrdinalIgnoreCase)
                )
                {
                    return true;
                }
            }
            return false;
        }

        return FakeOrAdNodeRegex().IsMatch(tag);
    }
}
