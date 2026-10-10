namespace SubParser.Utils;

using System;
using System.Collections.Frozen;
using System.Collections.Generic;

/// <summary>
/// sing-box 官方 uTLS 指纹标准化工具
/// - 严格对齐官方 option/tls.go 与 Sub-Store 实战经验
/// - 自动强制小写规范化 (如 "Chrome" / "iOS" 纠偏)
/// - 非白名单指纹安全过滤为 null，防止内核报未定义指纹直接闪退
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
    /// 标准化指纹字符串，若不在官方白名单内则返回 null
    /// </summary>
    public static string? NormalizeFingerprint(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        string normalized = raw.Trim().ToLowerInvariant();
        return ValidFingerprints.Contains(normalized) ? normalized : null;
    }
}
