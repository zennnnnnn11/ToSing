namespace SubParser.Utils;

using System.Diagnostics.CodeAnalysis;
using System.Text;

/// <summary>
/// 工业级 Base64 容错编解码工具类
/// - 吸收 v2rayN、Sub-Store、subconverter 实战经验
/// - 自动过滤回车、换行、空格杂质
/// - 自动兼容 URL-Safe Base64 (- 和 _)
/// - 自动补全末尾缺失的 '=' Padding
/// - 零异常崩溃保证 (TryDecode API)
/// </summary>
public static class Base64Utils
{
    /// <summary>
    /// 安全解码 Base64 字符串为 UTF-8 文本
    /// 如果解码失败或输入为空，返回空字符串，绝不抛出异常
    /// </summary>
    public static string Decode(string? input)
    {
        return TryDecode(input, out string? result) ? result : string.Empty;
    }

    /// <summary>
    /// 尝试解码 Base64 字符串为 UTF-8 文本
    /// </summary>
    public static bool TryDecode(string? input, [NotNullWhen(true)] out string? result)
    {
        result = null;
        if (!TryDecodeToBytes(input, out byte[]? bytes))
        {
            return false;
        }

        try
        {
            result = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 尝试将 Base64 解码为原始字节数组
    /// </summary>
    public static bool TryDecodeToBytes(string? input, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string sanitized = SanitizeBase64(input);
        if (sanitized.Length == 0)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromBase64String(sanitized);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 将文本编码为 Base64 字符串
    /// </summary>
    public static string Encode(string? input, bool urlSafe = false)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(input);
        string base64 = Convert.ToBase64String(bytes);

        if (urlSafe)
        {
            base64 = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        return base64;
    }

    /// <summary>
    /// 探测一段文本是否极大概率是 Base64 订阅内容（且不是普通的以协议开头的单链接）
    /// </summary>
    public static bool IsProbableBase64Subscription(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string trimmed = input.Trim();

        // 如果明显是普通的链接协议开头，则不是 Base64 订阅包
        if (trimmed.StartsWith("vless://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("ss://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("anytls://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("proxies:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 尝试解码并检查解出来的文本是否包含至少一个合法的协议头
        if (TryDecode(trimmed, out string? decoded))
        {
            return decoded.Contains("://", StringComparison.Ordinal) ||
                   decoded.Contains("proxies:", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    /// <summary>
    /// 核心清洗函数：去空、换符号、补齐等号
    /// </summary>
    private static string SanitizeBase64(string raw)
    {
        // 1. 去除首尾与内部空白符、换行符
        var sb = new StringBuilder(raw.Length + 4);
        foreach (char c in raw)
        {
            if (c is not ('\r' or '\n' or ' ' or '\t'))
            {
                // 2. 转换 URL-safe 符号
                char replaced = c switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => c
                };
                sb.Append(replaced);
            }
        }

        // 3. 补齐末尾缺失的 '=' 等号 (长度必须为 4 的整数倍)
        int mod = sb.Length % 4;
        if (mod > 0)
        {
            sb.Append('=', 4 - mod);
        }

        return sb.ToString();
    }
}
