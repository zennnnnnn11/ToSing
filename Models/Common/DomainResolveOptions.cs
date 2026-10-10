namespace SubParser.Models.Common;

using System.Text.Json.Serialization;

public sealed record class DomainResolveOptions
{
    [JsonPropertyName("server")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Server { get; init; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Timeout { get; init; }

    [JsonPropertyName("strategy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Strategy { get; init; }

    [JsonPropertyName("disable_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableCache { get; init; }

    [JsonPropertyName("disable_optimistic_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableOptimisticCache { get; init; }

    [JsonPropertyName("rewrite_ttl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? RewriteTTL { get; init; }

    [JsonPropertyName("client_subnet")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientSubnet { get; init; }
}
