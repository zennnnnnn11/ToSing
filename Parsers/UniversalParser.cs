namespace SubParser.Parsers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using SubParser.Models;
using SubParser.Parsers.Protocols;
using SubParser.Utils;
using YamlDotNet.Serialization;

/// <summary>
/// 通用订阅与节点解析调度引擎。
/// 支持处理单链接、多行链接、Base64 订阅及 Clash YAML 配置中的 proxies 列表。
/// </summary>
public static partial class UniversalParser
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>
    /// 根据 NodeContext 的 Protocol 调度解析出站节点。
    /// </summary>
    public static SingboxOutbound? ParseContext(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string proto = ctx.Protocol.ToLowerInvariant();
        SingboxOutbound? outbound = proto switch
        {
            "vless" => VlessParser.Parse(ctx),
            "ss" or "shadowsocks" => ShadowsocksParser.Parse(ctx),
            "hy2" or "hysteria2" => Hysteria2Parser.Parse(ctx),
            "vmess" => VmessParser.Parse(ctx),
            "trojan" => TrojanParser.Parse(ctx),
            "tuic" => TuicParser.Parse(ctx),
            "anytls" => AnyTlsParser.Parse(ctx),
            _ => null
        };

        if (outbound == null) return null;
        return ApplyCommonDialerOptions(outbound, ctx);
    }

    /// <summary>
    /// 解析单行节点 URI 链接。
    /// </summary>
    public static SingboxOutbound? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        string trimmed = CleanRawText(line);
        if (IsCommentLine(trimmed)) return null;

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
        if (proxy == null || proxy.Count == 0) return null;

        var ctx = NodeContext.FromClash(proxy);
        return ParseContext(ctx);
    }

    /// <summary>
    /// 解析订阅内容，自动识别 Clash YAML、Base64 订阅或多行 URI。
    /// </summary>
    public static IReadOnlyList<SingboxOutbound> ParseSubscription(string rawText)
    {
        var rawNodes = new List<SingboxOutbound>();
        if (string.IsNullOrWhiteSpace(rawText)) return rawNodes;

        string content = CleanRawText(rawText);

        if (content.Contains("proxies:", StringComparison.OrdinalIgnoreCase))
        {
            var yamlNodes = ParseClashYaml(content);
            if (yamlNodes.Count > 0)
            {
                return DeduplicateTags(yamlNodes);
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
            if (string.IsNullOrWhiteSpace(trimmed) || IsCommentLine(trimmed)) continue;

            var outbound = ParseLine(trimmed);
            if (outbound != null && !IsFakeOrAdNode(outbound.Tag))
            {
                rawNodes.Add(outbound);
            }
        }

        return DeduplicateTags(rawNodes);
    }

    private static List<SingboxOutbound> ParseClashYaml(string content)
    {
        var results = new List<SingboxOutbound>();
        try
        {
            var yamlData = YamlDeserializer.Deserialize<Dictionary<string, object>>(content);
            if (yamlData != null && yamlData.TryGetValue("proxies", out object? proxiesObj) && proxiesObj is IEnumerable<object> proxyList)
            {
                foreach (object item in proxyList)
                {
                    if (item is Dictionary<object, object> objMap)
                    {
                        var stringMap = (Dictionary<string, object?>)NormalizeYamlObject(objMap)!;
                        var outbound = ParseClashProxy(stringMap);
                        if (outbound != null && !IsFakeOrAdNode(outbound.Tag))
                        {
                            results.Add(outbound);
                        }
                    }
                }
            }
        }
        catch
        {
            // 忽略 YAML 解析异常并返回已解析项
        }
        return results;
    }

    /// <summary>
    /// 对同名节点追加递增编号后缀，确保出站标签全局唯一。
    /// </summary>
    public static IReadOnlyList<SingboxOutbound> DeduplicateTags(IReadOnlyList<SingboxOutbound> nodes)
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
                result.Add(string.Equals(node.Tag, originalTag, StringComparison.Ordinal) ? node : node with { Tag = originalTag });
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
        string detour = ctx.GetString("detour");
        string domainStrategy = ctx.GetString("domain_strategy", "domain-strategy");
        bool tcpFastOpen = ctx.GetBool("tcp_fast_open", "tcp-fast-open", "tfo");
        string connectTimeout = ctx.GetString("connect_timeout", "connect-timeout");
        string bindInterface = ctx.GetString("bind_interface", "bind-interface", "interface-name");
        string inet4 = ctx.GetString("inet4_bind_address", "inet4-bind-address");
        string inet6 = ctx.GetString("inet6_bind_address", "inet6-bind-address");
        uint? routingMark = ctx.GetUIntNullable("routing_mark", "routing-mark");
        bool reuseAddr = ctx.GetBool("reuse_addr", "reuse-addr");
        bool tcpMultiPath = ctx.GetBool("tcp_multi_path", "tcp-multi-path", "mptcp");
        bool? udpFragment = ctx.GetBoolNullable("udp_fragment", "udp-fragment");
        object? domainResolver = NormalizeDomainResolver(ctx.GetRaw("domain_resolver") ?? ctx.GetRaw("domain-resolver"));

        return node with
        {
            Detour = !string.IsNullOrEmpty(detour) ? detour : node.Detour,
            DomainStrategy = !string.IsNullOrEmpty(domainStrategy) ? domainStrategy : node.DomainStrategy,
            TcpFastOpen = tcpFastOpen || node.TcpFastOpen,
            ConnectTimeout = !string.IsNullOrEmpty(connectTimeout) ? connectTimeout : node.ConnectTimeout,
            BindInterface = !string.IsNullOrEmpty(bindInterface) ? bindInterface : node.BindInterface,
            Inet4BindAddress = !string.IsNullOrEmpty(inet4) ? inet4 : node.Inet4BindAddress,
            Inet6BindAddress = !string.IsNullOrEmpty(inet6) ? inet6 : node.Inet6BindAddress,
            RoutingMark = routingMark ?? node.RoutingMark,
            ReuseAddr = reuseAddr || node.ReuseAddr,
            TcpMultiPath = tcpMultiPath || node.TcpMultiPath,
            UdpFragment = udpFragment ?? node.UdpFragment,
            DomainResolver = domainResolver ?? node.DomainResolver
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

    private static object? NormalizeDomainResolver(object? raw)
    {
        if (raw == null) return null;
        if (raw is string str) return str;
        if (raw is IDictionary<string, object?> map)
        {
            var res = new Dictionary<string, object?>(map.Count, StringComparer.Ordinal);
            foreach (var (k, v) in map)
            {
                if (string.Equals(k, "disable_cache", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(k, "disable_optimistic_cache", StringComparison.OrdinalIgnoreCase))
                {
                    res[k] = v is bool b ? b : (v is string s && (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(s, "1", StringComparison.Ordinal)));
                }
                else if (string.Equals(k, "rewrite_ttl", StringComparison.OrdinalIgnoreCase))
                {
                    if (v is uint u) res[k] = u;
                    else if (v is int i && i >= 0) res[k] = (uint)i;
                    else if (v is string s && uint.TryParse(s, CultureInfo.InvariantCulture, out uint parsedTtl)) res[k] = parsedTtl;
                    else res[k] = v;
                }
                else
                {
                    res[k] = v;
                }
            }
            return res;
        }
        return raw;
    }

    /// <summary>
    /// 移除 UTF-8 BOM 及首尾空白字符。
    /// </summary>
    public static string CleanRawText(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        return raw.Trim(['\uFEFF', '\u200B', ' ', '\r', '\n', '\t']);
    }

    private static bool IsCommentLine(string line)
    {
        if (line.Length == 0) return true;
        bool startsWithComment = line[0] == '#' ||
                                 line.StartsWith("//", StringComparison.Ordinal) ||
                                 line[0] == ';';
        return startsWithComment && !line.Contains("://", StringComparison.Ordinal);
    }

    [GeneratedRegex(
        @"(?i)(?:网址|官网|发布页|流量|剩余|到期|时间|重置|过期|通知|公告|bandwidth|traffic|expire)",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex FakeOrAdNodeRegex();

    private static bool IsFakeOrAdNode(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag)) return false;
        return FakeOrAdNodeRegex().IsMatch(tag);
    }
}
