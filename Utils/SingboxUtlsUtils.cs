namespace SubParser.Utils;

using System;
using System.Collections.Frozen;
using System.Collections.Generic;

/// <summary>
/// sing-box uTLS 指纹标准化工具。
/// </summary>
public static class SingboxUtlsUtils
{
    private static readonly FrozenSet<string> ValidFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 标准化指纹为合法枚举小写值；非白名单内容返回 null。
    /// </summary>
    public static string? NormalizeFingerprint(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        string normalized = raw.Trim().ToLowerInvariant();
        return ValidFingerprints.Contains(normalized) ? normalized : null;
    }
}
