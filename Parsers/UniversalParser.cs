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
/// 吸收 Sub-Store 与成熟转换器全套实战避坑经验:
/// - 自动清洗 UTF-8 BOM (\uFEFF) 与隐形空白字符
/// - 自动跳过纯注释行 (#, //, ;) 与空行杂质
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

        string trimmed = CleanRawText(line);
        if (IsCommentLine(trimmed)) return null;

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

        // 1. 深度清洗 BOM 头与不可见控制字符
        string content = CleanRawText(rawText);

        // 2. 识别 Clash YAML
        if (content.Contains("proxies:", StringComparison.OrdinalIgnoreCase))
        {
            var yamlNodes = ParseClashYaml(content);
            if (yamlNodes.Count > 0)
            {
                return DeduplicateTags(yamlNodes);
            }
        }

        // 3. 识别 Base64 订阅
        if (Base64Utils.IsProbableBase64Subscription(content))
        {
            string decoded = Base64Utils.Decode(content);
            if (!string.IsNullOrWhiteSpace(decoded))
            {
                content = CleanRawText(decoded);
            }
        }

        // 4. 逐行安全扫描
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
            // 降级处理
        }
        return results;
    }

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
    /// 拔除 UTF-8 BOM (\uFEFF) 与隐形空格杂质
    /// </summary>
    public static string CleanRawText(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        return raw.Trim(['\uFEFF', '\u200B', ' ', '\r', '\n', '\t']);
    }

    /// <summary>
    /// 判定是否为纯注释行 (#, //, ; 开头且不含 :// 协议标记)
    /// </summary>
    private static bool IsCommentLine(string line)
    {
        if (line.Length == 0) return true;
        bool startsWithComment = line[0] == '#' ||
                                 line.StartsWith("//", StringComparison.Ordinal) ||
                                 line[0] == ';';
        return startsWithComment && !line.Contains("://", StringComparison.Ordinal);
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
