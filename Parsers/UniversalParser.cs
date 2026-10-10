namespace SubParser.Parsers;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using SubParser.Models;
using SubParser.Parsers.Protocols;
using SubParser.Utils;
using YamlDotNet.Serialization;

/// <summary>
/// 通用订阅与节点解析调度引擎
/// 吸收 Sub-Store 实战避坑经验:
/// - 自动过滤无效/垃圾/广告节点
/// - 自动全局消重 (Duplicate Tag 智能编号重命名)
/// - 严格合法端口范围校验 (1 ~ 65535)
/// </summary>
public static class UniversalParser
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public static SingboxOutbound? ParseContext(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        string proto = ctx.Protocol.ToLowerInvariant();
        return proto switch
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
    }

    public static SingboxOutbound? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        string trimmed = line.Trim();
        if (trimmed.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            var ctx = VmessParser.ParseVmessJsonUri(trimmed);
            return VmessParser.Parse(ctx);
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

    public static SingboxOutbound? ParseClashProxy(IReadOnlyDictionary<string, object?> proxy)
    {
        if (proxy == null || proxy.Count == 0) return null;

        var ctx = NodeContext.FromClash(proxy);
        return ParseContext(ctx);
    }

    public static IReadOnlyList<SingboxOutbound> ParseSubscription(string rawText)
    {
        var rawNodes = new List<SingboxOutbound>();
        if (string.IsNullOrWhiteSpace(rawText)) return rawNodes;

        string content = rawText.Trim();

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
            if (!string.IsNullOrWhiteSpace(decoded)) content = decoded;
        }

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var outbound = ParseLine(line);
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
                        var stringMap = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                        foreach (var kv in objMap)
                        {
                            if (kv.Key != null) stringMap[kv.Key.ToString()!] = kv.Value;
                        }

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
            // 忽略失败，降级处理
        }
        return results;
    }

    /// <summary>
    /// 核心防坑利器: 全局唯一 Tag 消重与自动编号器
    /// 彻底消除 sing-box 启动时报 duplicate tag 崩溃闪退
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

    private static bool IsFakeOrAdNode(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag)) return false;

        string lower = tag.ToLowerInvariant();
        return lower.Contains("剩余流量", StringComparison.Ordinal) ||
               lower.Contains("到期时间", StringComparison.Ordinal) ||
               lower.Contains("重置日", StringComparison.Ordinal) ||
               lower.Contains("官网", StringComparison.Ordinal) ||
               lower.Contains("通知", StringComparison.Ordinal) ||
               lower.Contains("traffic", StringComparison.Ordinal) ||
               lower.Contains("expire", StringComparison.Ordinal);
    }
}
