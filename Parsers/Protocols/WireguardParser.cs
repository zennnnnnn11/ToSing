namespace ToSing.Parsers.Protocols;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using ToSing.Models.Protocols;

/// <summary>
/// sing-box 1.11+ 标准 WireGuard 协议解析器。
/// 严格对齐官方端点规范，并融合 Sub-Store 的双栈 CIDR 合并、多 Peer 隔离与非法数据防护。
/// </summary>
public static class WireguardParser
{
    /// <summary>
    /// 从 NodeContext 解析 WireGuard 节点并映射为 sing-box 1.11+ 标准结构。
    /// </summary>
    public static WireguardOutbound? Parse(NodeContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        // 私钥验证 (必须存在且为 32 字节合法 Curve25519 Base64 密钥)
        string privateKey = ctx.GetString("private-key", "privatekey", "private_key");
        if (!IsValidCurve25519Key(privateKey))
        {
            return null;
        }

        // 本地地址列表构建 (支持 IPv4/IPv6 双栈、独立 CIDR、带括号 IP 等)
        var addressList = ParseAndNormalizeAddresses(ctx);
        if (addressList.Count == 0)
        {
            return null; // 必须至少分配一个合法接口 IP
        }

        // 顶层全局备选服务器和端口
        string topServer = !string.IsNullOrWhiteSpace(ctx.Server)
            ? ctx.Server
            : ctx.GetString("server", "endpoint", "peer");
        int topPort = ctx.ServerPort > 0
            ? ctx.ServerPort
            : ctx.GetInt("port", "endpoint-port");

        (topServer, topPort) = SplitHostAndPort(topServer, topPort);

        // 顶层备选公钥与预共享密钥
        string topPublicKey = ctx.GetString("public-key", "publickey", "public_key", "peer-public-key", "peer_public_key");
        string topPsk = ctx.GetString("pre-shared-key", "preshared-key", "presharedkey", "pre_shared_key");

        // 顶层 AllowedIPs 与 Reserved
        var topAllowedIpsResult = ParseAllowedIps(ctx, addressList);
        if (!topAllowedIpsResult.IsValid)
        {
            return null; // 包含非法 AllowedIPs (如 0.0.0.0/99)，严格拒绝
        }

        var topReservedResult = ParseReservedBytes(ctx.GetRaw("reserved"));
        if (!topReservedResult.IsValid)
        {
            return null; // 提供了非法 Reserved 格式，严格拒绝
        }

        int topKeepalive = ctx.GetInt("persistent-keepalive-interval", "persistent-keepalive", "keepalive");
        if (topKeepalive is < 0 or > 65535)
        {
            return null; // 非法 keepalive 拒绝
        }
        int? topKeepaliveVal = topKeepalive > 0 ? topKeepalive : null;

        var peers = new List<WireguardPeer>();

        // 优先检查是否存在多 peers 列表 (Clash 或原生 sing-box)
        object? rawPeersObj = ctx.GetRaw("peers");
        if (rawPeersObj is IEnumerable<object> rawPeersList)
        {
            foreach (object item in rawPeersList)
            {
                var peerCtx = NodeContextFromObject(item);
                if (peerCtx == null)
                    continue;

                var peer = ParseSinglePeer(
                    peerCtx,
                    topServer,
                    topPort,
                    topPublicKey,
                    topPsk,
                    topAllowedIpsResult.List,
                    topReservedResult.Bytes,
                    addressList,
                    isInnerPeer: true
                );
                if (peer == null)
                {
                    return null; // 单个 Peer 数据损坏，严格拒绝整个节点
                }
                peers.Add(peer);
            }
        }

        // 若无 peers 列表，则从顶层字段构造单个 Peer
        if (peers.Count == 0)
        {
            var singlePeer = ParseSinglePeer(
                ctx,
                topServer,
                topPort,
                topPublicKey,
                topPsk,
                topAllowedIpsResult.List,
                topReservedResult.Bytes,
                addressList,
                isInnerPeer: false
            );
            if (singlePeer == null)
            {
                return null;
            }
            peers.Add(singlePeer);
        }

        // 模型已有字段补齐 (支持原生 sing-box 接口 name 映射)
        bool system = ctx.GetBool("system", "system_interface", "system-interface");
        string? name = ctx.GetString("name", "interface_name", "interface-name");
        if (string.IsNullOrWhiteSpace(name))
        {
            name = null;
        }

        int listenPort = ctx.GetInt("listen_port", "listen-port", "listenport");
        int? listenPortVal = (listenPort is >= 1 and <= 65535) ? listenPort : null;

        int mtu = ctx.GetInt("mtu");
        int? mtuVal = (mtu is >= 576 and <= 65535) ? mtu : null;

        int workers = ctx.GetInt("workers");
        int? workersVal = workers > 0 ? workers : null;

        string tag = !string.IsNullOrWhiteSpace(ctx.Tag)
            ? ctx.Tag
            : ctx.GetString("tag", "name", "ps");
        if (string.IsNullOrWhiteSpace(tag))
        {
            tag = $"WireGuard {peers[0].Address}:{peers[0].Port}";
        }

        return new WireguardOutbound
        {
            Tag = tag,
            System = system,
            Name = name,
            ListenPort = listenPortVal,
            Address = addressList,
            PrivateKey = privateKey,
            Peers = peers,
            Mtu = mtuVal,
            Workers = workersVal,
        };
    }

    /// <summary>
    /// 解析单个 Peer，严格执行密码学与数据范围验证。
    /// </summary>
    private static WireguardPeer? ParseSinglePeer(
        NodeContext peerCtx,
        string fallbackServer,
        int fallbackPort,
        string fallbackPublicKey,
        string fallbackPsk,
        IReadOnlyList<string>? fallbackAllowedIps,
        IReadOnlyList<int>? fallbackReserved,
        IReadOnlyList<string> addressList,
        bool isInnerPeer
    )
    {
        string server = peerCtx.GetString("server", "endpoint", "peer");
        if (isInnerPeer && string.IsNullOrWhiteSpace(server))
        {
            server = peerCtx.GetString("address");
        }
        if (string.IsNullOrWhiteSpace(server))
            server = fallbackServer;

        int port = peerCtx.GetInt("port", "endpoint-port");
        if (port <= 0)
            port = fallbackPort;

        (server, port) = SplitHostAndPort(server, port);
        if (string.IsNullOrWhiteSpace(server) || port is < 1 or > 65535)
        {
            return null;
        }

        string publicKey = peerCtx.GetString("public-key", "publickey", "public_key", "peer-public-key", "peer_public_key");
        if (string.IsNullOrWhiteSpace(publicKey))
            publicKey = fallbackPublicKey;

        if (!IsValidCurve25519Key(publicKey))
        {
            return null; // 必须有合法 32 字节公钥
        }

        string psk = peerCtx.GetString("pre-shared-key", "preshared-key", "presharedkey", "pre_shared_key");
        if (string.IsNullOrWhiteSpace(psk))
            psk = fallbackPsk;

        if (!string.IsNullOrEmpty(psk))
        {
            if (!IsValidCurve25519Key(psk))
            {
                return null; // 提供了非法 PSK，严格拒绝
            }
        }
        else
        {
            psk = null!;
        }

        var allowedIpsResult = ParseAllowedIps(peerCtx, addressList);
        if (!allowedIpsResult.IsValid)
        {
            return null; // 包含非法 AllowedIPs，严格拒绝
        }

        var allowedIps = allowedIpsResult.List ?? fallbackAllowedIps;
        if (allowedIps == null || allowedIps.Count == 0)
        {
            allowedIps = ["0.0.0.0/0"];
        }

        var reservedRes = ParseReservedBytes(peerCtx.GetRaw("reserved"));
        if (!reservedRes.IsValid)
        {
            return null; // 提供了非法 reserved 拒绝
        }
        var reserved = reservedRes.Bytes ?? fallbackReserved;

        int keepalive = peerCtx.GetInt("persistent-keepalive-interval", "persistent-keepalive", "keepalive");
        if (keepalive is < 0 or > 65535)
        {
            return null; // 超出范围拒绝
        }
        int? keepaliveVal = keepalive > 0 ? keepalive : null;

        return new WireguardPeer
        {
            Address = server,
            Port = port,
            PublicKey = publicKey,
            PreSharedKey = string.IsNullOrEmpty(psk) ? null : psk,
            AllowedIps = allowedIps,
            PersistentKeepaliveInterval = keepaliveVal,
            Reserved = reserved,
        };
    }

    /// <summary>
    /// 解析标准 INI 格式 WireGuard 配置文件 ([Interface] / 多 [Peer])。
    /// 彻底隔离不同 Peer 块，防止串味与互相覆盖。
    /// </summary>
    public static WireguardOutbound? ParseConf(string confText, string? defaultTag = null)
    {
        if (string.IsNullOrWhiteSpace(confText))
            return null;

        var interfaceMap = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var peersList = new List<Dictionary<string, object?>>();
        Dictionary<string, object?>? currentPeerMap = null;
        bool inInterface = false;

        using var reader = new System.IO.StringReader(confText);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            string trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed[0] == '#' || trimmed[0] == ';')
            {
                // 提取注释中可能的 WARP 扩展 (如 "# Reserved = 0, 0, 0")
                if (trimmed.Contains("reserved", StringComparison.OrdinalIgnoreCase))
                {
                    int colonOrEqual = trimmed.IndexOfAny([':', '=']);
                    if (colonOrEqual >= 0)
                    {
                        string commentVal = trimmed[(colonOrEqual + 1)..].Trim();
                        if (commentVal.Length > 0)
                        {
                            if (currentPeerMap != null && !currentPeerMap.ContainsKey("reserved"))
                            {
                                currentPeerMap["reserved"] = commentVal;
                            }
                            else if (!interfaceMap.ContainsKey("reserved"))
                            {
                                interfaceMap["reserved"] = commentVal;
                            }
                        }
                    }
                }
                continue;
            }

            if (trimmed.StartsWith('[', StringComparison.Ordinal) && trimmed.EndsWith(']', StringComparison.Ordinal))
            {
                string section = trimmed[1..^1].Trim().ToLowerInvariant();
                if (string.Equals(section, "interface", StringComparison.OrdinalIgnoreCase))
                {
                    inInterface = true;
                    currentPeerMap = null;
                }
                else if (string.Equals(section, "peer", StringComparison.OrdinalIgnoreCase))
                {
                    inInterface = false;
                    currentPeerMap = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    peersList.Add(currentPeerMap);
                }
                else
                {
                    inInterface = false;
                    currentPeerMap = null;
                }
                continue;
            }

            int eq = trimmed.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
                continue;

            string key = trimmed[..eq].Trim().ToLowerInvariant();
            string val = trimmed[(eq + 1)..].Trim();

            if (inInterface)
            {
                switch (key)
                {
                    case "privatekey":
                        interfaceMap["private-key"] = val;
                        break;
                    case "address":
                        interfaceMap["address"] = val;
                        break;
                    case "listenport":
                        interfaceMap["listen_port"] = val;
                        break;
                    case "mtu":
                        interfaceMap["mtu"] = val;
                        break;
                }
            }
            else if (currentPeerMap != null)
            {
                switch (key)
                {
                    case "publickey":
                        currentPeerMap["public-key"] = val;
                        break;
                    case "presharedkey":
                        currentPeerMap["pre-shared-key"] = val;
                        break;
                    case "endpoint":
                        currentPeerMap["endpoint"] = val;
                        break;
                    case "allowedips":
                        currentPeerMap["allowed-ips"] = val;
                        break;
                    case "persistentkeepalive":
                        currentPeerMap["persistent-keepalive-interval"] = val;
                        break;
                    case "reserved":
                        currentPeerMap["reserved"] = val;
                        break;
                }
            }
        }

        interfaceMap["type"] = "wireguard";
        if (!string.IsNullOrEmpty(defaultTag))
        {
            interfaceMap["name"] = defaultTag;
        }

        if (peersList.Count > 0)
        {
            interfaceMap["peers"] = peersList;
        }

        return Parse(NodeContext.FromClash(interfaceMap));
    }

    /// <summary>
    /// 校验 Curve25519 32 字节 Base64 密钥。
    /// </summary>
    private static bool IsValidCurve25519Key(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return false;

        string trimmed = key.Trim();
        try
        {
            byte[] bytes = Convert.FromBase64String(trimmed);
            return bytes.Length == 32;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 提取并标准化本地接口 IP 列表（完整支持双栈、独立 CIDR、带括号 IP 等）。
    /// </summary>
    private static List<string> ParseAndNormalizeAddresses(NodeContext ctx)
    {
        var result = new List<string>();

        // 1. 处理结构化 IPv4: ip + ip-cidr
        string ip = ctx.GetString("ip");
        int ipCidr = ctx.GetInt("ip-cidr", "ip_cidr");
        string normV4 = NormalizeSingleAddress(ip, ipCidr, isV6: false);
        if (!string.IsNullOrEmpty(normV4))
        {
            result.Add(normV4);
        }

        // 2. 处理结构化 IPv6: ipv6 + ipv6-cidr
        string ipv6 = ctx.GetString("ipv6");
        int ipv6Cidr = ctx.GetInt("ipv6-cidr", "ipv6_cidr");
        string normV6 = NormalizeSingleAddress(ipv6, ipv6Cidr, isV6: true);
        if (!string.IsNullOrEmpty(normV6) && !result.Contains(normV6))
        {
            result.Add(normV6);
        }

        // 3. 处理多值 address / local_address 字段
        var rawList = ctx.GetStringList("address", "local_address", "local-address");
        foreach (string raw in rawList)
        {
            var parts = raw.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (string part in parts)
            {
                string norm = ParseAddressToken(part);
                if (!string.IsNullOrEmpty(norm) && !result.Contains(norm))
                {
                    result.Add(norm);
                }
            }
        }

        return result;
    }

    private static string NormalizeSingleAddress(string rawHost, int customCidr, bool isV6)
    {
        if (string.IsNullOrWhiteSpace(rawHost))
            return string.Empty;

        string cleaned = rawHost.Trim().Trim('[', ']');
        int slash = cleaned.IndexOf('/', StringComparison.Ordinal);
        int parsedCidr = -1;
        if (slash >= 0)
        {
            string cidrStr = cleaned[(slash + 1)..].Trim();
            cleaned = cleaned[..slash].Trim();
            if (int.TryParse(cidrStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int c))
            {
                parsedCidr = c;
            }
        }

        if (!IPAddress.TryParse(cleaned, out var ip))
            return string.Empty;

        int finalCidr;
        int max = isV6 ? 128 : 32;

        if (customCidr > 0)
        {
            if (customCidr > max)
                return string.Empty; // 非法 CIDR
            finalCidr = customCidr;
        }
        else if (parsedCidr >= 0)
        {
            if (parsedCidr > max)
                return string.Empty; // 非法 CIDR
            finalCidr = parsedCidr;
        }
        else
        {
            finalCidr = max;
        }

        return $"{cleaned}/{finalCidr}";
    }

    private static string ParseAddressToken(string rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return string.Empty;

        string trimmed = rawToken.Trim();
        int slash = trimmed.IndexOf('/', StringComparison.Ordinal);
        string hostPart;
        int? cidr = null;

        if (slash >= 0)
        {
            hostPart = trimmed[..slash].Trim().Trim('[', ']');
            string cidrStr = trimmed[(slash + 1)..].Trim();
            if (int.TryParse(cidrStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int c))
            {
                cidr = c;
            }
            else
            {
                return string.Empty; // 带有无效斜杠 CIDR
            }
        }
        else
        {
            hostPart = trimmed.Trim('[', ']');
        }

        if (!IPAddress.TryParse(hostPart, out var ip))
            return string.Empty;

        bool isV6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        int max = isV6 ? 128 : 32;

        int finalCidr = cidr ?? max;
        if (finalCidr < 0 || finalCidr > max)
            return string.Empty;

        return $"{hostPart}/{finalCidr}";
    }

    /// <summary>
    /// 正确拆分 host 和 port，杜绝将纯 IPv6 地址的冒号切坏，并约定 WireGuard 默认端口为 51820。
    /// </summary>
    private static (string Host, int Port) SplitHostAndPort(string hostStr, int portVal)
    {
        if (string.IsNullOrWhiteSpace(hostStr))
            return (string.Empty, portVal > 0 ? portVal : 51820);

        string trimmed = hostStr.Trim();
        int port = portVal > 0 ? portVal : 51820;

        if (trimmed.StartsWith('[', StringComparison.Ordinal))
        {
            int closeBracket = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket > 0)
            {
                string ipv6 = trimmed[1..closeBracket].Trim();
                if (closeBracket + 1 < trimmed.Length && trimmed[closeBracket + 1] == ':')
                {
                    string portStr = trimmed[(closeBracket + 2)..].Trim();
                    if (int.TryParse(portStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int p) && p is >= 1 and <= 65535)
                    {
                        return (ipv6, p);
                    }
                }
                return (ipv6, port);
            }
        }

        // 仅当只有一个冒号时才视作 host:port
        int firstColon = trimmed.IndexOf(':', StringComparison.Ordinal);
        int lastColon = trimmed.LastIndexOf(':', StringComparison.Ordinal);
        if (firstColon >= 0 && firstColon == lastColon)
        {
            string hostPart = trimmed[..firstColon].Trim();
            string portPart = trimmed[(firstColon + 1)..].Trim();
            if (int.TryParse(portPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out int p) && p is >= 1 and <= 65535)
            {
                return (hostPart, p);
            }
        }

        // 多个冒号（裸 IPv6，如 2001:db8::1）或无冒号：保持原样，不切断！
        return (trimmed, port);
    }

    /// <summary>
    /// 校验并提取 AllowedIPs，遇到非法 CIDR (如 0.0.0.0/99) 判定为无效。
    /// </summary>
    private static (bool IsValid, IReadOnlyList<string>? List) ParseAllowedIps(
        NodeContext ctx,
        IReadOnlyList<string> addressList
    )
    {
        var rawAllowed = ctx.GetStringList("allowed-ips", "allowed_ips");
        if (rawAllowed.Count > 0)
        {
            var validList = new List<string>(rawAllowed.Count);
            foreach (string item in rawAllowed)
            {
                var parts = item.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (string part in parts)
                {
                    if (!IsValidAllowedIp(part))
                    {
                        return (false, null); // 包含非法 AllowedIPs (如 0.0.0.0/99)，严格拒绝
                    }
                    validList.Add(part);
                }
            }
            return (true, validList);
        }

        var defaultList = new List<string> { "0.0.0.0/0" };
        foreach (string addr in addressList)
        {
            if (addr.Contains(':', StringComparison.Ordinal))
            {
                defaultList.Add("::/0");
                break;
            }
        }
        return (true, defaultList);
    }

    private static bool IsValidAllowedIp(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        string trimmed = raw.Trim();
        int slash = trimmed.IndexOf('/', StringComparison.Ordinal);
        string hostPart;
        int? cidr = null;

        if (slash >= 0)
        {
            hostPart = trimmed[..slash].Trim().Trim('[', ']');
            string cidrStr = trimmed[(slash + 1)..].Trim();
            if (int.TryParse(cidrStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int c))
            {
                cidr = c;
            }
            else
            {
                return false;
            }
        }
        else
        {
            hostPart = trimmed.Trim('[', ']');
        }

        if (!IPAddress.TryParse(hostPart, out var ip))
            return false;

        bool isV6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        int max = isV6 ? 128 : 32;

        if (cidr.HasValue)
        {
            if (cidr.Value < 0 || cidr.Value > max)
                return false; // 比如 /99 超过了 32，判定非法！
        }

        return true;
    }

    /// <summary>
    /// 解析 Cloudflare WARP 3 字节保留字段（合法返回 bytes，若提供了非法数据严格报错）。
    /// </summary>
    private static (bool IsValid, List<int>? Bytes) ParseReservedBytes(object? val)
    {
        if (val == null)
            return (true, null); // 未提供，合法且为空

        if (val is IEnumerable<object> list)
        {
            var res = new List<int>();
            foreach (object item in list)
            {
                if (int.TryParse(item.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int b) && b is >= 0 and <= 255)
                {
                    res.Add(b);
                }
                else
                {
                    return (false, null); // 包含非法数值
                }
            }
            return (res.Count == 3, res.Count == 3 ? res : null);
        }

        string str = val.ToString()?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(str))
            return (true, null);

        if (str.StartsWith('[', StringComparison.Ordinal) && str.EndsWith(']', StringComparison.Ordinal))
        {
            str = str[1..^1].Trim();
        }

        if (str.Contains(',', StringComparison.Ordinal))
        {
            var parts = str.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 3)
                return (false, null);

            var res = new List<int>(3);
            foreach (string p in parts)
            {
                if (int.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out int b) && b is >= 0 and <= 255)
                {
                    res.Add(b);
                }
                else
                {
                    return (false, null);
                }
            }
            return (true, res);
        }

        // 尝试 Base64 (必须恰好解码为 3 字节)
        try
        {
            byte[] bytes = Convert.FromBase64String(str);
            if (bytes.Length == 3)
            {
                return (true, [bytes[0], bytes[1], bytes[2]]);
            }
        }
        catch
        {
            // 忽略非 Base64 格式
        }

        return (false, null); // 提供了非法的格式
    }

    private static NodeContext? NodeContextFromObject(object item)
    {
        if (item is IReadOnlyDictionary<string, object?> roDict)
        {
            return NodeContext.FromClash(roDict);
        }
        if (item is IDictionary<string, object?> dict)
        {
            return NodeContext.FromClash(new Dictionary<string, object?>(dict, StringComparer.OrdinalIgnoreCase));
        }
        if (item is IDictionary<object, object> objDict)
        {
            var map = new Dictionary<string, object?>(objDict.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var kv in objDict)
            {
                if (kv.Key != null)
                {
                    map[kv.Key.ToString()!] = kv.Value;
                }
            }
            return NodeContext.FromClash(map);
        }
        return null;
    }
}
