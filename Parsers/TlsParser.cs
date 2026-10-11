namespace ToSing.Parsers;

using System;
using System.Collections.Generic;
using ToSing.Models.Common;
using ToSing.Utils;

/// <summary>
/// 出站 TLS 配置解析器。
/// </summary>
public static class TlsParser
{
    /// <summary>
    /// 从节点上下文解析 TLS 选项。
    /// </summary>
    public static OutboundTLSOptions? Parse(
        NodeContext ctx,
        string defaultServer,
        bool allowUtls = true,
        bool forceTls = false
    )
    {
        ArgumentNullException.ThrowIfNull(ctx);

        if (ctx.GetRaw("tls") is { } rawTls && NativeOptionsParser.IsObject(rawTls))
        {
            var nativeTls = NativeOptionsParser.Deserialize<OutboundTLSOptions>(rawTls);
            if (!allowUtls && nativeTls.Utls?.Enabled == true)
                throw new FormatException("uTLS cannot be used by this QUIC protocol");
            return nativeTls;
        }

        if (!CheckTlsEnabled(ctx, forceTls))
            return null;

        string serverName = ctx.GetString("sni", "servername", "peer", "amp;sni", "amp;servername");
        if (string.IsNullOrEmpty(serverName))
            serverName = defaultServer;

        var alpnList = ctx.GetStringList("alpn", "amp;alpn");
        var cipherSuites = ctx.GetStringList("cipher_suites", "cipher-suites", "ciphers");
        string minVersion = ctx.GetString("min_version", "min-version");
        string maxVersion = ctx.GetString("max_version", "max-version");
        var certs = ParseCertificates(ctx);

        var native = NativeOptionsParser.Read<OutboundTLSOptions>(ctx);
        var reality = ParseReality(ctx) ?? native.Reality;
        var utls = allowUtls ? (ParseUtls(ctx) ?? native.Utls) : null;
        if (reality?.Enabled == true && utls == null && allowUtls)
        {
            utls = new OutboundUTLSOptions { Enabled = true, Fingerprint = "chrome" };
        }

        return native with
        {
            Enabled = true,
            ServerName = serverName,
            Insecure = ctx.GetBool(
                "insecure",
                "skip-cert-verify",
                "allowInsecure",
                "allow_insecure",
                "allow-insecure"
            ),
            DisableSNI = ctx.GetBool("disable_sni", "disable-sni"),
            MinVersion = !string.IsNullOrEmpty(minVersion) ? minVersion : null,
            MaxVersion = !string.IsNullOrEmpty(maxVersion) ? maxVersion : null,
            Alpn = alpnList.Count > 0 ? alpnList : null,
            Utls = utls,
            Reality = reality,
            CipherSuites = cipherSuites.Count > 0 ? cipherSuites : null,
            Certificate = certs.Certificate,
            CertificatePath = certs.CertificatePath,
            CertificateSHA256 = certs.CertificateSHA256,
            CertificatePublicKeySHA256 = certs.CertificatePublicKeySHA256,
            ClientCertificate = certs.ClientCertificate,
            ClientCertificatePath = certs.ClientCertificatePath,
            ClientKey = certs.ClientKey,
            ClientKeyPath = certs.ClientKeyPath,
            Ech = ParseEch(ctx),
        };
    }

    private static bool CheckTlsEnabled(NodeContext ctx, bool forceTls)
    {
        string security = ctx.GetString("security", "amp;security").ToLowerInvariant();
        string tlsRaw = ctx.GetString("tls", "amp;tls").ToLowerInvariant();
        string pbk = ctx.GetString("pbk", "public-key", "reality-opts.public-key", "amp;pbk");

        return forceTls
            || ctx.GetBool("tls")
            || string.Equals(tlsRaw, "tls", StringComparison.Ordinal)
            || string.Equals(tlsRaw, "1", StringComparison.Ordinal)
            || string.Equals(tlsRaw, "true", StringComparison.Ordinal)
            || string.Equals(security, "tls", StringComparison.Ordinal)
            || string.Equals(security, "reality", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(pbk);
    }

    private static (
        IReadOnlyList<string>? Certificate,
        string? CertificatePath,
        IReadOnlyList<string>? CertificateSHA256,
        IReadOnlyList<string>? CertificatePublicKeySHA256,
        IReadOnlyList<string>? ClientCertificate,
        string? ClientCertificatePath,
        IReadOnlyList<string>? ClientKey,
        string? ClientKeyPath
    ) ParseCertificates(NodeContext ctx)
    {
        var certificate = ctx.GetStringList("certificate", "ca", "ca_str", "ca-str");
        var rawCertSha256 = ctx.GetStringList(
            "certificate_sha256",
            "certificate-sha256",
            "cert-sha256",
            "ca-sha256",
            "ca_sha256",
            "pinSHA256",
            "pin-sha256",
            "pin_sha256",
            "pcs",
            "pinnedCertSha256",
            "pinned-cert-sha256",
            "pinned_cert_sha256"
        );
        var rawFingerprint = ctx.GetStringList("fingerprint");
        var certSha256 = new List<string>();

        foreach (string item in rawCertSha256)
        {
            string? normalized = NormalizeCertificateSha256(item);
            if (
                !string.IsNullOrEmpty(normalized)
                && !certSha256.Contains(normalized, StringComparer.Ordinal)
            )
            {
                certSha256.Add(normalized);
            }
        }

        bool isHysteria =
            string.Equals(ctx.Protocol, "hysteria2", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ctx.Protocol, "hysteria", StringComparison.OrdinalIgnoreCase);

        foreach (string item in rawFingerprint)
        {
            if (isHysteria || IsPotentialCertificateSha256(item))
            {
                string? normalized = NormalizeCertificateSha256(item);
                if (
                    !string.IsNullOrEmpty(normalized)
                    && !certSha256.Contains(normalized, StringComparer.Ordinal)
                )
                {
                    certSha256.Add(normalized);
                }
            }
        }

        var rawCertPubKeySha256 = ctx.GetStringList(
            "certificate_public_key_sha256",
            "certificate-public-key-sha256"
        );
        var certPubKeySha256 = new List<string>();
        foreach (string item in rawCertPubKeySha256)
        {
            string? normalized = NormalizeCertificateSha256(item);
            if (
                !string.IsNullOrEmpty(normalized)
                && !certPubKeySha256.Contains(normalized, StringComparer.Ordinal)
            )
            {
                certPubKeySha256.Add(normalized);
            }
        }

        var clientCert = ctx.GetStringList("client_certificate", "client-certificate");
        var clientKey = ctx.GetStringList("client_key", "client-key");

        string certPath = ctx.GetString(
            "certificate_path",
            "certificate-path",
            "ca_path",
            "ca-path"
        );
        string clientCertPath = ctx.GetString("client_certificate_path", "client-certificate-path");
        string clientKeyPath = ctx.GetString("client_key_path", "client-key-path");

        if (certSha256.Count > 0 || certPubKeySha256.Count > 0)
        {
            certificate = [];
            certPath = string.Empty;
        }

        return (
            certificate.Count > 0 ? certificate : null,
            !string.IsNullOrEmpty(certPath) ? certPath : null,
            certSha256.Count > 0 ? certSha256 : null,
            certPubKeySha256.Count > 0 ? certPubKeySha256 : null,
            clientCert.Count > 0 ? clientCert : null,
            !string.IsNullOrEmpty(clientCertPath) ? clientCertPath : null,
            clientKey.Count > 0 ? clientKey : null,
            !string.IsNullOrEmpty(clientKeyPath) ? clientKeyPath : null
        );
    }

    private static OutboundUTLSOptions? ParseUtls(NodeContext ctx)
    {
        if (
            string.Equals(ctx.Protocol, "hysteria2", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ctx.Protocol, "hysteria", StringComparison.OrdinalIgnoreCase)
        )
        {
            return null;
        }

        string fpRaw = ctx.GetString("fp", "client-fingerprint", "fingerprint", "amp;fp");
        if (IsPotentialCertificateSha256(fpRaw))
        {
            return null;
        }

        string? fp = SingboxUtlsUtils.NormalizeFingerprint(fpRaw);
        return fp != null ? new OutboundUTLSOptions { Enabled = true, Fingerprint = fp } : null;
    }

    public static bool IsValidRealityPublicKey(string? pbk)
    {
        if (string.IsNullOrWhiteSpace(pbk))
            return false;

        return Base64Utils.TryDecodeToBytes(pbk.Trim(), out byte[]? bytes) && bytes.Length == 32;
    }

    private static OutboundRealityOptions? ParseReality(NodeContext ctx)
    {
        string security = ctx.GetString("security", "amp;security").ToLowerInvariant();
        string pbk = ctx.GetString("pbk", "public-key", "reality-opts.public-key", "amp;pbk");

        if (
            !string.Equals(security, "reality", StringComparison.Ordinal)
            && string.IsNullOrEmpty(pbk)
        )
        {
            return null;
        }

        string sid = ctx.GetString("sid", "short-id", "reality-opts.short-id", "amp;sid");
        return new OutboundRealityOptions
        {
            Enabled = true,
            PublicKey = pbk,
            ShortId = !string.IsNullOrEmpty(sid) ? sid : null,
        };
    }

    private static OutboundECHOptions? ParseEch(NodeContext ctx)
    {
        if (ctx.GetRaw("ech") is { } native && NativeOptionsParser.IsObject(native))
        {
            var options = NativeOptionsParser.Deserialize<OutboundECHOptions>(native);
            return options.Enabled == true ? options : null;
        }
        bool? echExplicit = ctx.GetBoolNullable("ech.enabled", "ech-enabled", "ech");
        if (echExplicit == false)
            return null;

        var echConfig = ctx.GetStringList("ech.config", "ech-config");
        string echConfigPath = ctx.GetString("ech.config_path", "ech-config-path");
        string echQuerySni = ctx.GetString("ech.query_server_name", "ech-query-server-name");

        if (
            echExplicit != true
            && echConfig.Count == 0
            && string.IsNullOrEmpty(echConfigPath)
            && string.IsNullOrEmpty(echQuerySni)
        )
        {
            return null;
        }

        return new OutboundECHOptions
        {
            Enabled = true,
            Config = NormalizeEchConfig(echConfig),
            ConfigPath = !string.IsNullOrEmpty(echConfigPath) ? echConfigPath : null,
            QueryServerName = !string.IsNullOrEmpty(echQuerySni) ? echQuerySni : null,
        };
    }

    private static string? NormalizeCertificateSha256(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        string clean = raw.Trim();
        string hexOnly = clean
            .Replace(":", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal);

        if (hexOnly.Length == 64 && IsHexString(hexOnly))
        {
            byte[] bytes = Convert.FromHexString(hexOnly);
            return Convert.ToBase64String(bytes);
        }

        if (TryDecodeBase64Sha256(clean, out string? base64Result))
        {
            return base64Result;
        }

        return clean;
    }

    private static bool IsPotentialCertificateSha256(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string clean = text.Trim();
        string hexOnly = clean
            .Replace(":", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal);

        if (hexOnly.Length == 64 && IsHexString(hexOnly))
        {
            return true;
        }

        return TryDecodeBase64Sha256(clean, out _);
    }

    private static bool IsHexString(string text)
    {
        foreach (char c in text)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }
        return true;
    }

    private static bool TryDecodeBase64Sha256(string text, out string? result)
    {
        result = null;
        try
        {
            byte[] bytes = Convert.FromBase64String(text);
            if (bytes.Length == 32)
            {
                result = text;
                return true;
            }
        }
        catch (FormatException)
        {
            // 不是合法 Base64 编码
        }
        return false;
    }

    private static IReadOnlyList<string>? NormalizeEchConfig(IReadOnlyList<string> rawConfigs)
    {
        if (rawConfigs.Count == 0)
            return null;

        foreach (string c in rawConfigs)
        {
            if (c.Contains("BEGIN ECH CONFIGS", StringComparison.Ordinal))
                return rawConfigs;
        }

        var result = new List<string>(rawConfigs.Count + 2) { "-----BEGIN ECH CONFIGS-----" };
        result.AddRange(rawConfigs);
        result.Add("-----END ECH CONFIGS-----");
        return result;
    }
}
