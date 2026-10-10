using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SubParser.Models;
using SubParser.Models.Common;
using SubParser.Models.Protocols;
using SubParser.Parsers;

if (args.Length != 2) throw new ArgumentException("Usage: AlignmentProbe <core-schema.json> <output-directory>");
var schema = JsonNode.Parse(File.ReadAllText(args[0]))!.AsObject();
string output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(output);
var issues = new List<string>();
using (var stream=typeof(SingboxOutbound).Assembly.GetManifestResourceStream("SubParser.Models.SingboxContract.json")) {
    if(stream==null) issues.Add("Missing embedded field contract");
    else {
        var contract=JsonNode.Parse(stream)!.AsObject();
        var reference=(JsonObject)schema.DeepClone();
        foreach(var group in reference) foreach(var field in group.Value!.AsObject()) field.Value!.AsObject().Remove("source");
        File.WriteAllText(Path.Combine(output,"contract-candidate.json"),reference.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
        if(!JsonNode.DeepEquals(contract,reference)) issues.Add("Embedded field contract differs from supplied sing-box source; reconcile Models/SingboxContract.json before claiming alignment");
    }
}
var cases = new List<JsonObject>();
var coverage = new SortedDictionary<string, string[]>();
const string uuid = "11111111-1111-4111-8111-111111111111";
string cert = File.ReadAllText(Path.Combine(output, "test-cert.pem"));
string key = File.ReadAllText(Path.Combine(output, "test-key.pem"));
string ech = File.ReadAllText(Path.Combine(output, "test-ech.pem"));
string PathFixture(string file) => Path.Combine(output, file).Replace('\\', '/');
JsonNode J(object? value) => JsonSerializer.SerializeToNode(value)!;

JsonObject Tls() => new() { ["enabled"] = true, ["server_name"] = "audit.example" };
JsonObject Realm() => new() { ["server_url"] = "https://realm.example", ["realm_id"] = "audit", ["stun_servers"] = J(new[] {"127.0.0.1:3478"}) };
JsonObject Base(string protocol) {
    var body = new JsonObject { ["type"] = protocol, ["tag"] = "audit", ["server"] = "127.0.0.1", ["server_port"] = 443 };
    if (protocol is "vless" or "vmess" or "tuic") body["uuid"] = uuid;
    if (protocol == "vmess") body["security"] = "auto";
    if (protocol is "trojan" or "anytls" or "hysteria2" or "tuic" or "shadowsocks") body["password"] = "test-password";
    if (protocol == "shadowsocks") body["method"] = "aes-128-gcm";
    else body["tls"] = Tls();
    return body;
}

var groups = new Dictionary<string, (Type Model, string Protocol, string Prefix)> {
    ["vmess"] = (typeof(VmessOutbound), "vmess", ""),
    ["vless"] = (typeof(VlessOutbound), "vless", ""),
    ["trojan"] = (typeof(TrojanOutbound), "trojan", ""),
    ["shadowsocks"] = (typeof(ShadowsocksOutbound), "shadowsocks", ""),
    ["hysteria2"] = (typeof(Hysteria2Outbound), "hysteria2", ""),
    ["tuic"] = (typeof(TuicOutbound), "tuic", ""),
    ["anytls"] = (typeof(AnyTlsOutbound), "anytls", ""),
    ["dialer"] = (typeof(SingboxDialerOptions), "vless", ""),
    ["tls"] = (typeof(OutboundTLSOptions), "vless", "tls"),
    ["ech"] = (typeof(OutboundECHOptions), "vless", "tls.ech"),
    ["utls"] = (typeof(OutboundUTLSOptions), "vless", "tls.utls"),
    ["reality"] = (typeof(OutboundRealityOptions), "vless", "tls.reality"),
    ["multiplex"] = (typeof(OutboundMultiplexOptions), "vless", "multiplex"),
    ["brutal"] = (typeof(BrutalOptions), "vless", "multiplex.brutal"),
    ["uot"] = (typeof(UdpOverTcpOptions), "shadowsocks", "udp_over_tcp"),
    ["http"] = (typeof(V2RayTransportOptions), "vless", "transport"),
    ["ws"] = (typeof(V2RayTransportOptions), "vless", "transport"),
    ["grpc"] = (typeof(V2RayTransportOptions), "vless", "transport"),
    ["httpupgrade"] = (typeof(V2RayTransportOptions), "vless", "transport"),
    ["quic"] = (typeof(V2RayTransportOptions), "vless", "transport"),
    ["realm"] = (typeof(Hysteria2RealmOptions), "hysteria2", "realm"),
    ["realm_port_mapping"] = (typeof(Hysteria2RealmPortMappingOptions), "hysteria2", "realm.port_mapping"),
    ["hy2_obfs"] = (typeof(Hysteria2ObfsOptions), "hysteria2", "obfs"),
    ["http_client"] = (typeof(HttpClientOptions), "hysteria2", "realm.http_client"),
    ["domain_resolver"] = (typeof(DomainResolveOptions), "vless", "domain_resolver")
};
var transportGroups = new HashSet<string> { "http", "ws", "grpc", "httpupgrade", "quic" };
var transportUnion = transportGroups.SelectMany(g => schema[g]!.AsObject().Select(x => x.Key)).Append("type").ToHashSet(StringComparer.Ordinal);

JsonObject Parent(JsonObject root, string prefix) {
    JsonObject result = root;
    foreach (string part in prefix.Split('.', StringSplitOptions.RemoveEmptyEntries)) {
        if (result[part] is not JsonObject child) { child = new JsonObject(); result[part] = child; }
        result = child;
    }
    return result;
}
void Set(JsonObject body, string path, JsonNode? value) {
    int dot = path.LastIndexOf('.');
    Parent(body, dot < 0 ? "" : path[..dot])[dot < 0 ? path : path[(dot+1)..]] = value?.DeepClone();
}
object? Plain(JsonNode? node) {
    if (node is JsonObject map) return map.ToDictionary(kv => kv.Key, kv => Plain(kv.Value), StringComparer.OrdinalIgnoreCase);
    if (node is JsonArray array) return array.Select(Plain).ToList();
    if (node == null) return null;
    var element = JsonSerializer.SerializeToElement(node);
    return element.ValueKind switch {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.True => true, JsonValueKind.False => false,
        JsonValueKind.Number when element.TryGetInt32(out int i) => i,
        JsonValueKind.Number when element.TryGetInt64(out long l) => l,
        JsonValueKind.Number when element.TryGetUInt64(out ulong u) => u,
        JsonValueKind.Number => element.GetDouble(),
        _ => null
    };
}

JsonObject Context(string group, string field) {
    var spec = groups[group];
    var body = Base(spec.Protocol);
    if (transportGroups.Contains(group)) body["transport"] = new JsonObject {["type"] = group};
    if (group == "multiplex" || group == "brutal") body["multiplex"] = new JsonObject {["enabled"]=true, ["protocol"]="smux"};
    if (group == "uot") body["udp_over_tcp"] = new JsonObject {["enabled"]=true};
    if (group == "brutal") Parent(body, "multiplex")["brutal"] = new JsonObject {["enabled"]=true,["up_mbps"]=100,["down_mbps"]=200};
    if (group == "ech") Parent(body,"tls")["ech"] = new JsonObject {["enabled"]=true, ["config"]=J(new[]{ech})};
    if (group == "utls") Parent(body,"tls")["utls"] = new JsonObject {["enabled"]=true, ["fingerprint"]="chrome"};
    if (group == "reality") Parent(body,"tls")["reality"] = new JsonObject {["enabled"]=true, ["public_key"]=Convert.ToBase64String(Enumerable.Repeat((byte)1,32).ToArray()).TrimEnd('='), ["short_id"]="0123456789abcdef"};
    if (group == "reality" || (group == "tls" && field == "reality")) Parent(body,"tls")["utls"] = new JsonObject {["enabled"]=true,["fingerprint"]="chrome"};
    if (group == "tls" && field == "spoof_method") Parent(body,"tls")["spoof"] = "cover.example";
    if (group.StartsWith("realm", StringComparison.Ordinal) || group == "http_client" || (group == "hysteria2" && field == "realm")) {
        body.Remove("server"); body.Remove("server_port"); body["realm"] = Realm();
    }
    if (group == "realm_port_mapping") Parent(body,"realm")["port_mapping"] = new JsonObject {["enabled"]=true, ["timeout"]="5s", ["lifetime"]="30m"};
    if (group == "http_client") Parent(body,"realm")["http_client"] = new JsonObject {["version"]=3};
    if (group == "hy2_obfs") body["obfs"] = new JsonObject {["type"]="gecko", ["password"]="obfs-password", ["min_packet_size"]=256, ["max_packet_size"]=1200};
    if (group == "tls" && field.StartsWith("client_",StringComparison.Ordinal)) {
        Parent(body,"tls")["client_certificate_path"]=PathFixture("test-cert.pem");
        Parent(body,"tls")["client_key_path"]=PathFixture("test-key.pem");
    }
    if (group == "domain_resolver") body["domain_resolver"] = new JsonObject {["server"]="dns-local"};
    return body;
}

JsonNode? Sample(string group, string field) {
    if (field == "server") return J(group=="domain_resolver" ? "dns-local" : "127.0.0.1");
    if (field == "engine") return J("go");
    if (field == "type") return J(group=="hy2_obfs" ? "gecko" : group);
    if (field == "tag") return J(group=="http_client" ? "http-via" : "audit");
    if (field == "timeout" || field.EndsWith("_timeout",StringComparison.Ordinal) || field is "heartbeat" or "hop_interval" or "hop_interval_max" or "tcp_keep_alive" or "tcp_keep_alive_interval" or "keep_alive_period" or "idle_session_check_interval" or "idle_session_timeout") return J("30s");
    if (field is "fallback_delay" or "fragment_fallback_delay") return J("250ms");
    return field switch {
        "server_port" => J(8443), "uuid" => J(uuid),
        "password" => J("prefix:tail"), "client_metadata" => J("audit-client"),
        "security" => J("aes-128-gcm"), "method" => J(group=="http" ? "POST" : "aes-128-gcm"),
        "alter_id" => J(1), "packet_encoding" => J("xudp"), "flow" => J("xtls-rprx-vision"),
        "network" => J(new[]{"tcp","udp"}), "detour" => J("via"), "domain_strategy" or "strategy" => J("prefer_ipv4"),
        "connect_timeout" => J("5s"), "bind_interface" => J(System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().First().Name),
        "inet4_bind_address" => J("127.0.0.1"), "inet6_bind_address" => J("::1"),
        "routing_mark" => J("0x2023"), "protect_path" => J("/tmp/alignment-protect.sock"), "netns" => J("alignment-ns"),
        "network_strategy" => J("default"), "network_type" or "fallback_network_type" => J(new[]{"wifi"}),
        "domain_resolver" => new JsonObject{["server"]="dns-local",["disable_cache"]=true,["rewrite_ttl"]=60},
        "tls" => Tls(), "transport" => new JsonObject {["type"]="ws",["path"]="/ws"},
        "multiplex" => new JsonObject {["enabled"]=true,["protocol"]="smux"}, "brutal" => new JsonObject {["enabled"]=true,["up_mbps"]=100,["down_mbps"]=200},
        "protocol" => J("smux"), "max_connections" => J(2), "min_streams" => J(4), "max_streams" => J(16),
        "up_mbps" or "down_mbps" => J(100), "udp_over_tcp" => new JsonObject {["enabled"]=true,["version"]=2},
        "version" => J(group=="http_client" ? 3 : 2), "plugin" => J("v2ray-plugin"), "plugin_opts" => J("mode=websocket;mux=0;path=/ws"),
        "server_ports" => J(new[]{"443:443","8443:8450"}), "bbr_profile" => J("standard"),
        "obfs" => new JsonObject {["type"]="salamander",["password"]="obfs-password"},
        "realm" => Realm(), "ip_version" => J(4), "realm_id" => J("audit"), "server_url" => J("https://realm.example"),
        "token" => J("token"), "stun_servers" => J(new[]{"127.0.0.1:3478"}), "port_mapping" => new JsonObject {["enabled"]=true,["timeout"]="5s",["lifetime"]="30m"},
        "http_client" => new JsonObject {["version"]=3}, "lifetime" => J("30m"),
        "min_packet_size" => J(256), "max_packet_size" => J(1200),
        "idle_timeout" or "ping_timeout" => J("30s"), "initial_packet_size" => J(1200), "max_concurrent_streams" => J(32),
        "stream_receive_window" or "connection_receive_window" => J("2mb"), "congestion_control" => J("bbr"), "udp_relay_mode" => J("native"),
        "min_idle_session" => J(2), "server_name" => J("audit.example"),
        "alpn" => J(new[]{"h2","http/1.1"}), "min_version" => J("1.2"), "max_version" => J("1.3"),
        "cipher_suites" => J(new[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}), "curve_preferences" => J(new[]{"X25519","P256"}),
        "certificate" or "client_certificate" => J(new[]{cert}), "client_key" => J(new[]{key}),
        "certificate_path" or "client_certificate_path" => J(PathFixture("test-cert.pem")), "client_key_path" => J(PathFixture("test-key.pem")),
        "certificate_sha256" or "certificate_public_key_sha256" => J(new[]{Convert.ToBase64String(new byte[32])}),
        "spoof" => J("cover.example"), "spoof_method" => J("wrong-checksum"),
        "ech" => new JsonObject {["enabled"]=true,["config"]=J(new[]{ech})},
        "utls" => new JsonObject {["enabled"]=true,["fingerprint"]="chrome"},
        "reality" => new JsonObject {["enabled"]=true,["public_key"]=Convert.ToBase64String(Enumerable.Repeat((byte)1,32).ToArray()).TrimEnd('=')},
        "fingerprint" => J("chrome"), "public_key" => J(Convert.ToBase64String(Enumerable.Repeat((byte)1,32).ToArray()).TrimEnd('=')), "short_id" => J("0123456789abcdef"),
        "config" => J(new[]{ech}), "config_path" => J(PathFixture("test-ech.pem")), "query_server_name" => J("audit.example"),
        "path" => J("/ws?token=abc"), "host" => group=="httpupgrade" ? J("audit.example") : J(new[]{"audit.example"}),
        "headers" => new JsonObject {["X-Audit"]=J(new[]{"first","second"})},
        "max_early_data" => J(2048), "early_data_header_name" => J("Sec-WebSocket-Protocol"), "service_name" => J("audit"),
        "rewrite_ttl" => J(60), "client_subnet" => J("192.0.2.0/24"),
        _ => null
    };
}
string Platform(string field) => field switch {
    "routing_mark" or "netns" or "protect_path" or "bind_address_no_port" or "tcp_multi_path" or "kernel_rx" or "kernel_tx" => "Platform/socket option: schema and core decoded values checked; no socket execution on this host.",
    _ => ""
};
void AddCase(string name, JsonObject input, JsonObject expected, string schemaOnly="", bool invalid=false) {
    JsonObject actual;
    bool parserRejected=false;
    try {
        var map = (Dictionary<string,object?>)Plain(input)!;
        var outbound = UniversalParser.ParseClashProxy(map);
        if (outbound == null) {
            if (!invalid) { issues.Add(name+": unexpectedly filtered"); return; }
            parserRejected=true;
            actual = (JsonObject)input.DeepClone();
        } else actual = JsonSerializer.SerializeToNode<SingboxOutbound>(outbound)!.AsObject();
    } catch (Exception e) {
        if (!invalid) { issues.Add(name+": "+e.Message); return; }
        parserRejected=true;
        actual = (JsonObject)input.DeepClone();
    }
    cases.Add(new JsonObject {["name"]=name, ["actual"]=actual, ["expected"]=expected.DeepClone(), ["schema_only"]=schemaOnly, ["expect_invalid"]=invalid, ["parser_rejected"]=parserRejected});
}

foreach (var (group, spec) in groups) {
    if (schema[group] is not JsonObject core) { issues.Add("Core type missing: "+group); continue; }
    var model = spec.Model.GetProperties().Select(p=>p.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name).OfType<string>().ToHashSet(StringComparer.Ordinal);
    foreach (var field in core) {
        bool deprecated = field.Value?["deprecated"]?.GetValue<bool>() == true;
        if (!model.Contains(field.Key) && !deprecated) issues.Add($"Missing model: {group}.{field.Key} ({field.Value?["source"]})");
    }
    var allowed = transportGroups.Contains(group) ? transportUnion : core.Select(kv=>kv.Key).ToHashSet(StringComparer.Ordinal);
    if (spec.Prefix.Length==0 && group!="dialer") allowed.Add("tag");
    foreach (string field in model.Except(allowed)) issues.Add($"Unknown model field: {group}.{field}");
    var touched = new List<string>();
    if (transportGroups.Contains(group)) AddCase(group+"/discriminator", Context(group,""), Context(group,""));
    foreach (var (field, metadata) in core.OrderBy(kv=>kv.Key,StringComparer.Ordinal)) {
        if (!model.Contains(field) && metadata?["deprecated"]?.GetValue<bool>()==true) continue;
        string kind = metadata!["kind"]!.GetValue<string>();
        JsonNode? sample = kind=="bool" ? J(true) : Sample(group,field);
        if (sample==null) { issues.Add($"Missing fixture: {group}.{field} ({metadata["go_type"]})"); continue; }
        touched.Add(field);
        string path = spec.Prefix.Length==0 ? field : spec.Prefix+"."+field;
        var expected = Context(group,field);
        Set(expected,path,sample);
        bool unsupported = group == "anytls" && field == "tcp_fast_open";
        AddCase(group+"/"+field, expected, expected, Platform(field), unsupported);
        // Every boolean must preserve both true and false, including explicit disabled sections.
        if (kind=="bool") {
            var off = (JsonObject)expected.DeepClone(); Set(off,path,J(false));
            AddCase(group+"/"+field+"/false",off,off);
        }
        if (metadata["go_type"]?.GetValue<string>() == "int" && metadata["enum"] == null) {
            foreach (long boundary in new[]{(long)int.MaxValue+1, 9007199254740992L}) {
                var numeric=Context(group,field); Set(numeric,path,J(boundary));
                AddCase(group+"/"+field+"/int64-"+boundary,numeric,numeric,
                    "Large integer boundary: core decoding and value preservation checked; constructors may allocate proportional to this value.");
            }
            var signed=Context(group,field); Set(signed,path,J(-1L));
            AddCase(group+"/"+field+"/signed-int",signed,signed,
                "Signed integer boundary: Go decoding and value preservation checked; runtime semantics depend on the option.");
            var tooLarge=Context(group,field); Set(tooLarge,path,J(long.MaxValue));
            // This reference core's excluded-object decoder rounds through float64,
            // so Int64.MaxValue is rejected after rounding to 2^63.
            AddCase(group+"/"+field+"/core-int64-overflow",tooLarge,tooLarge,"",true);
        }
        if (metadata["go_type"]?.GetValue<string>().Contains("MemoryBytes",StringComparison.Ordinal)==true) {
            foreach (long boundary in new[]{0L, 2147483648L, -1L}) {
                var numeric=Context(group,field); Set(numeric,path,J(boundary));
                AddCase(group+"/"+field+"/integer-bytes-"+boundary,numeric,numeric);
            }
            var overflow=Context(group,field); Set(overflow,path,J(ulong.MaxValue));
            AddCase(group+"/"+field+"/integer-bytes-overflow",overflow,overflow,"",true);
        }
        // A string scalar where the Go type demands a boolean/numeric value must not silently become a default.
        if (kind=="bool" || kind=="string" || kind.StartsWith("int",StringComparison.Ordinal) || kind.StartsWith("uint",StringComparison.Ordinal)) {
            var bad = (JsonObject)expected.DeepClone(); Set(bad,path,new JsonObject{["invalid"]=true});
            AddCase(group+"/"+field+"/invalid-type",bad,bad,"",true);
        }
        if (metadata["enum"] is JsonArray enums) {
            foreach (var enumNode in enums) {
                string value = enumNode!.GetValue<string>();
                JsonNode enumValue = int.TryParse(value,out int number) && (kind.StartsWith("int",StringComparison.Ordinal) || kind.StartsWith("uint",StringComparison.Ordinal)) ? J(number) : J(value);
                var variant = Context(group,field); Set(variant,path,enumValue);
                string platform = Platform(field);
                if (field=="engine" && value!="go") platform="Native TLS/HTTP engine requires a platform-specific build; decoded values checked.";
                if (group=="shadowsocks" && field=="method" && value.StartsWith("2022-",StringComparison.Ordinal)) variant["password"]=Convert.ToBase64String(new byte[value.Contains("aes-128",StringComparison.Ordinal)?16:32]);
                if (group=="vmess" && field=="security" && value=="aes-128-cfb") variant["alter_id"]=1;
                AddCase(group+"/"+field+"/enum-"+value,variant,variant,platform);
            }
            // Enum tags are checked against the core implementation, not a copied whitelist.
            if (kind=="string") {
                var invalidEnum=(JsonObject)expected.DeepClone(); Set(invalidEnum,path,J("not-a-core-value"));
                AddCase(group+"/"+field+"/invalid-enum",invalidEnum,invalidEnum,"",true);
                cases[^1]["enum_path"]=path;
                cases[^1]["allowed_enum"]=enums.DeepClone();
            }
        }
    }
    coverage[group] = touched.ToArray();
}
// Boundary cases independent from model declaration defaults.
foreach (string protocol in new[]{"vless","vmess","trojan","shadowsocks","hysteria2","tuic"}) {
    var body=Base(protocol); body["network"]=J("udp"); AddCase(protocol+"/network-scalar",body,body);
}
foreach (string mark in new[]{"0xFFFFFFFF","0b1010","0o12","012"}) {
    var body=Base("vless"); body["routing_mark"]=mark; AddCase("routing-mark/"+mark,body,body,Platform("routing_mark"));
}
foreach (string protocol in new[]{"trojan","anytls","hysteria2","tuic","shadowsocks"}) {
    var body=Base(protocol); body["password"]="  p:+%@/尾巴  "; AddCase(protocol+"/password-verbatim",body,body);
}
foreach (string protocol in new[]{"trojan","anytls","hysteria2","tuic","shadowsocks"}) {
    foreach (string password in new[]{"literal+plus:tail", "  encoded:%@/尾巴  "}) {
        string auth=Uri.EscapeDataString(password);
        if(protocol=="tuic") auth=uuid+":"+auth;
        if(protocol=="shadowsocks") auth=Uri.EscapeDataString("aes-128-gcm:"+password);
        string uri=(protocol=="shadowsocks" ? "ss" : protocol)+"://"+auth+"@127.0.0.1:443?sni=audit.example#audit";
        var expected=Base(protocol); expected["password"]=password;
        try {
            var node=UniversalParser.ParseLine(uri);
            if(node==null) { issues.Add(protocol+"/uri-secret: unexpectedly filtered"); continue; }
            cases.Add(new JsonObject{["name"]=protocol+"/uri-secret/"+cases.Count,["actual"]=JsonSerializer.SerializeToNode<SingboxOutbound>(node),["expected"]=expected});
        } catch(Exception error) { issues.Add(protocol+"/uri-secret: "+error.Message); }
    }
}
var uintWs=Context("ws","max_early_data"); Parent(uintWs,"transport")["max_early_data"]=uint.MaxValue;
AddCase("ws/max-early-data-uint32",uintWs,uintWs);
foreach(string field in new[]{"not_a_core_option","tag","type"}) {
    var body=Base("vless"); Parent(body,"tls")[field]=true;
    AddCase("tls/unknown-field/"+field,body,body,"",true);
}
var wrongTransport=Context("ws",""); Parent(wrongTransport,"transport")["service_name"]="grpc-only";
AddCase("transport/wrong-variant-field",wrongTransport,wrongTransport,"",true);
var badUot=Context("uot",""); Parent(badUot,"udp_over_tcp")["version"]=256;
AddCase("uot/uint8-overflow",badUot,badUot,"",true);
foreach(bool flag in new[]{true,false}) {
    var body=Base("shadowsocks"); body["udp_over_tcp"]=flag;
    AddCase("uot/boolean-"+flag,body,body);
}
var domainRef=Base("vless"); domainRef["domain_resolver"]="dns-local";
AddCase("domain-resolver/string-reference",domainRef,domainRef);
var httpRef=Context("realm","http_client"); Parent(httpRef,"realm")["http_client"]="http-via";
AddCase("realm/http-client-reference",httpRef,httpRef);
var portOnly=Base("hysteria2"); portOnly.Remove("server_port"); portOnly["server_ports"]=J(new[]{"443:443"});
AddCase("hysteria2/server-ports-without-single-port",portOnly,portOnly);
var realmConflict=Base("hysteria2"); realmConflict["realm"]=Realm();
AddCase("hysteria2/native-realm-endpoint-conflict",realmConflict,realmConflict,"",true);
var tuicConflict=Base("tuic"); tuicConflict["udp_relay_mode"]="quic"; tuicConflict["udp_over_stream"]=true;
AddCase("tuic/native-udp-mode-conflict",tuicConflict,tuicConflict,"",true);
foreach(string protocol in new[]{"hysteria2","tuic","anytls"}) {
    var disabled=Base(protocol); Parent(disabled,"tls")["enabled"]=false;
    AddCase(protocol+"/required-tls-disabled",disabled,disabled,"",true);
}
var explicitEmpty=Base("vless"); explicitEmpty["packet_encoding"]=""; AddCase("vless/packet-encoding-empty",explicitEmpty,explicitEmpty);
var unknown=Base("vless"); unknown["not_a_core_option"]=true; cases.Add(new JsonObject{["name"]="checker/unknown-field-rejected",["actual"]=unknown,["expected"]=unknown.DeepClone(),["expect_invalid"]=true});
// Self-test: valid JSON that lost TLS must be detected by semantic comparison.
var tlsExpected=Base("vless"); var tlsLost=(JsonObject)tlsExpected.DeepClone(); tlsLost.Remove("tls");
cases.Add(new JsonObject{["name"]="checker/lost-tls-detected",["actual"]=tlsLost,["expected"]=tlsExpected,["expect_mismatch"]=true});
File.WriteAllText(Path.Combine(output,"field-cases.json"),JsonSerializer.Serialize(cases,new JsonSerializerOptions{WriteIndented=true}));
File.WriteAllText(Path.Combine(output,"model-report.json"),JsonSerializer.Serialize(new{issues,coverage,case_count=cases.Count},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"Model groups: {groups.Count}; field cases: {cases.Count}; model/conversion issues: {issues.Count}");
foreach(string issue in issues) Console.WriteLine(issue);
return issues.Count==0 ? 0 : 1;
