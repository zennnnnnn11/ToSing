namespace SubParser.Models;

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Parsers;

/// <summary>
/// Native AOT 编译期源生成 JSON 序列化上下文。
/// 完全无需运行时代码生成或动态反射。
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified
)]
[JsonSerializable(typeof(IReadOnlyList<SingboxOutbound>))]
[JsonSerializable(typeof(List<SingboxOutbound>))]
[JsonSerializable(typeof(SingboxOutbound))]
[JsonSerializable(typeof(VlessOutbound))]
[JsonSerializable(typeof(VmessOutbound))]
[JsonSerializable(typeof(TrojanOutbound))]
[JsonSerializable(typeof(ShadowsocksOutbound))]
[JsonSerializable(typeof(Hysteria2Outbound))]
[JsonSerializable(typeof(TuicOutbound))]
[JsonSerializable(typeof(AnyTlsOutbound))]
[JsonSerializable(typeof(OutboundTLSOptions))]
[JsonSerializable(typeof(OutboundECHOptions))]
[JsonSerializable(typeof(OutboundUTLSOptions))]
[JsonSerializable(typeof(OutboundRealityOptions))]
[JsonSerializable(typeof(V2RayTransportOptions))]
[JsonSerializable(typeof(OutboundMultiplexOptions))]
[JsonSerializable(typeof(BrutalOptions))]
[JsonSerializable(typeof(SingboxDialerOptions))]
[JsonSerializable(typeof(ParsedDialerOptions))]
[JsonSerializable(typeof(DomainResolveOptions))]
[JsonSerializable(typeof(HttpClientOptions))]
[JsonSerializable(typeof(Hysteria2RealmOptions))]
[JsonSerializable(typeof(Hysteria2RealmPortMappingOptions))]
[JsonSerializable(typeof(Hysteria2ObfsOptions))]
[JsonSerializable(typeof(UdpOverTcpOptions))]
[JsonSerializable(typeof(Dictionary<string, object?>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(List<object?>))]
[JsonSerializable(typeof(List<object>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(IReadOnlyList<string>))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(uint))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(ulong))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(JsonElement))]
public sealed partial class SubParserJsonContext : JsonSerializerContext { }
