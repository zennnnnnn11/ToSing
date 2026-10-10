namespace SubParser.Utils;

using System.Diagnostics.CodeAnalysis;
using System.Text;

/// <summary>
/// Base64 编解码辅助类，支持 URL-Safe 字符与填充自动补齐。
/// </summary>
public static class Base64Utils
{
    /// <summary>
    /// 解码 Base64 字符串为 UTF-8 文本，失败时返回空字符串。
    /// </summary>
    public static string Decode(string? input)
    {
        return TryDecode(input, out string? result) ? result : string.Empty;
    }

    /// <summary>
    /// 尝试解码 Base64 字符串为 UTF-8 文本。
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
    /// 尝试将 Base64 字符串解码为字节数组。
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
    /// 将文本编码为 Base64 字符串。
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
    /// 检查输入是否可能为 Base64 编码的订阅内容。
    /// </summary>
    public static bool IsProbableBase64Subscription(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string trimmed = input.Trim();

        if (
            trimmed.StartsWith("vless://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("ss://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("anytls://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("proxies:", StringComparison.OrdinalIgnoreCase)
        )
        {
            return false;
        }

        if (TryDecode(trimmed, out string? decoded))
        {
            return decoded.Contains("://", StringComparison.Ordinal)
                || decoded.Contains("proxies:", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static string SanitizeBase64(string raw)
    {
        var sb = new StringBuilder(raw.Length + 4);
        foreach (char c in raw)
        {
            if (c is not ('\r' or '\n' or ' ' or '\t'))
            {
                char replaced = c switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => c,
                };
                sb.Append(replaced);
            }
        }

        int mod = sb.Length % 4;
        if (mod > 0)
        {
            sb.Append('=', 4 - mod);
        }

        return sb.ToString();
    }
}
