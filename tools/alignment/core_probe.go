// Run from the supplied sing-box module, so its own dependency versions are used.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
)

type Field struct {
	GoType     string   `json:"go_type"`
	Kind       string   `json:"kind"`
	Enum       []string `json:"enum,omitempty"`
	Deprecated bool     `json:"deprecated,omitempty"`
	Source     string   `json:"source"`
}

var locations = map[string]string{}

func sourceLocations(root string) {
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, filepath.Join(root, "option"), nil, 0)
	if err != nil {
		panic(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				spec, ok := node.(*ast.TypeSpec)
				if !ok {
					return true
				}
				str, ok := spec.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, f := range str.Fields.List {
					if f.Tag == nil {
						continue
					}
					tag, _ := strconv.Unquote(f.Tag.Value)
					name := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
					pos := set.Position(f.Pos())
					locations[spec.Name.Name+"/"+name] = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
				}
				return true
			})
		}
	}
}

func fields(t reflect.Type) map[string]Field {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	result := map[string]Field{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			for k, v := range fields(f.Type) {
				result[k] = v
			}
			continue
		}
		if name == "" {
			continue
		}
		base := f.Type
		for base.Kind() == reflect.Pointer {
			base = base.Elem()
		}
		loc := locations[t.Name()+"/"+name]
		if loc == "" {
			loc = locations["_"+t.Name()+"/"+name]
		}
		if loc == "" {
			loc = t.PkgPath() + "." + t.Name() + "." + f.Name
		}
		value := Field{GoType: f.Type.String(), Kind: base.Kind().String(), Deprecated: f.Tag.Get("schema") == "omit", Source: loc}
		if enum := f.Tag.Get("enum"); enum != "" {
			value.Enum = strings.Split(enum, ",")
		}
		result[name] = value
	}
	return result
}

func schema(root string) any {
	sourceLocations(root)
	types := map[string]reflect.Type{
		"vmess":              reflect.TypeFor[option.VMessOutboundOptions](),
		"vless":              reflect.TypeFor[option.VLESSOutboundOptions](),
		"trojan":             reflect.TypeFor[option.TrojanOutboundOptions](),
		"shadowsocks":        reflect.TypeFor[option.ShadowsocksOutboundOptions](),
		"hysteria2":          reflect.TypeFor[option.Hysteria2OutboundOptions](),
		"tuic":               reflect.TypeFor[option.TUICOutboundOptions](),
		"anytls":             reflect.TypeFor[option.AnyTLSOutboundOptions](),
		"dialer":             reflect.TypeFor[option.DialerOptions](),
		"tls":                reflect.TypeFor[option.OutboundTLSOptions](),
		"ech":                reflect.TypeFor[option.OutboundECHOptions](),
		"utls":               reflect.TypeFor[option.OutboundUTLSOptions](),
		"reality":            reflect.TypeFor[option.OutboundRealityOptions](),
		"multiplex":          reflect.TypeFor[option.OutboundMultiplexOptions](),
		"brutal":             reflect.TypeFor[option.BrutalOptions](),
		"uot":                reflect.TypeFor[option.UDPOverTCPOptions](),
		"http":               reflect.TypeFor[option.V2RayHTTPOptions](),
		"ws":                 reflect.TypeFor[option.V2RayWebsocketOptions](),
		"grpc":               reflect.TypeFor[option.V2RayGRPCOptions](),
		"httpupgrade":        reflect.TypeFor[option.V2RayHTTPUpgradeOptions](),
		"quic":               reflect.TypeFor[option.V2RayQUICOptions](),
		"realm":              reflect.TypeFor[option.Hysteria2Realm](),
		"realm_port_mapping": reflect.TypeFor[option.Hysteria2RealmPortMapping](),
		"hy2_obfs":           reflect.TypeFor[option.Hysteria2Obfs](),
		"http_client":        reflect.TypeFor[option.HTTPClientOptions](),
		"domain_resolver":    reflect.TypeFor[option.DomainResolveOptions](),
	}
	result := map[string]map[string]Field{}
	for name, t := range types {
		result[name] = fields(t)
	}
	for k, v := range fields(reflect.TypeFor[option.Hysteria2ObfsGecko]()) {
		result["hy2_obfs"][k] = v
	}
	for k, v := range fields(reflect.TypeFor[option.QUICOptions]()) {
		result["http_client"][k] = v
	}
	return result
}

type Case struct {
	Name           string          `json:"name"`
	Actual         json.RawMessage `json:"actual"`
	Expected       json.RawMessage `json:"expected"`
	SchemaOnly     string          `json:"schema_only,omitempty"`
	ExpectInvalid  bool            `json:"expect_invalid,omitempty"`
	ExpectMismatch bool            `json:"expect_mismatch,omitempty"`
	EnumPath       string          `json:"enum_path,omitempty"`
	AllowedEnum    []string        `json:"allowed_enum,omitempty"`
	ParserRejected *bool           `json:"parser_rejected,omitempty"`
}

func enumError(c Case) error {
	if c.EnumPath == "" {
		return nil
	}
	var value any
	if err := json.Unmarshal(c.Actual, &value); err != nil {
		return err
	}
	for _, key := range strings.Split(c.EnumPath, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value, ok = object[key]
		if !ok {
			return nil
		}
	}
	for _, allowed := range c.AllowedEnum {
		if fmt.Sprint(value) == allowed {
			return nil
		}
	}
	return fmt.Errorf("value violates enum declared by core struct tag: %s", c.EnumPath)
}

func decode(ctx context.Context, raw []byte) (option.Outbound, error) {
	var outbound option.Outbound
	err := sj.UnmarshalContext(ctx, raw, &outbound)
	return outbound, err
}

func canonical(ctx context.Context, value option.Outbound) (string, error) {
	data, err := sj.MarshalContext(ctx, &value)
	if err != nil {
		return "", err
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&object); err != nil {
		return "", err
	}
	data, err = json.Marshal(object)
	return string(data), err
}

func load(ctx context.Context, outbound option.Outbound) error {
	direct, err := decode(ctx, []byte(`{"type":"direct","tag":"via"}`))
	if err != nil {
		return err
	}
	var config option.Options
	// Supply references used by fixtures. No server connection is started.
	err = sj.UnmarshalContext(ctx, []byte(`{"log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns-local"}]},"http_clients":[{"tag":"http-via","version":1}]}`), &config)
	if err != nil {
		return err
	}
	config.Outbounds = []option.Outbound{outbound, direct}
	instance, err := box.New(box.Options{Context: ctx, Options: config})
	if err == nil {
		instance.Close()
	}
	return err
}

func check(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var cases []Case
	if err = json.Unmarshal(data, &cases); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	for _, c := range cases {
		ctx, cancel := context.WithCancel(include.Context(context.Background()))
		result := map[string]any{"name": c.Name, "passed": false, "schema_only": c.SchemaOnly}
		actual, aerr := decode(ctx, c.Actual)
		if c.ExpectInvalid {
			if aerr == nil {
				aerr = enumError(c)
			}
			if aerr == nil {
				aerr = load(ctx, actual)
			}
			result["passed"] = aerr != nil
			if aerr != nil {
				result["rejection"] = aerr.Error()
			}
			if c.ParserRejected != nil {
				result["parser_rejected"] = *c.ParserRejected
				if !*c.ParserRejected {
					result["passed"] = false
					result["error"] = "parser emitted an invalid core option instead of rejecting it"
				}
			}
		} else {
			expected, eerr := decode(ctx, c.Expected)
			if eerr != nil {
				result["error"] = "invalid oracle: " + eerr.Error()
			} else if aerr != nil {
				result["error"] = "invalid generated output: " + aerr.Error()
			} else {
				a, ae := canonical(ctx, actual)
				e, ee := canonical(ctx, expected)
				if ae != nil || ee != nil {
					// Some core versions cannot marshal HTTPClientOptions(version=1).
					// Compare actual decoded Go structs, retaining a trace of this limitation.
					if reflect.DeepEqual(actual, expected) {
						result["comparison"] = "decoded Go structs (core marshal unavailable)"
						result["core_marshal_error"] = fmt.Sprint(ae, ee)
						a, e, ae, ee = "", "", nil, nil
					}
				}
				if ae != nil || ee != nil {
					result["error"] = fmt.Sprint(ae, ee)
				} else if a != e {
					if c.ExpectMismatch {
						result["passed"] = true
						result["detected_mismatch"] = true
					} else {
						result["error"] = "core decoded values differ"
					}
					result["actual_decoded"] = a
					result["expected_decoded"] = e
				} else if c.ExpectMismatch {
					result["error"] = "checker self-test failed to detect changed values"
				} else if c.SchemaOnly != "" {
					result["passed"] = true
					result["runtime_checked"] = false
				} else if err := load(ctx, expected); err != nil {
					result["error"] = "oracle cannot initialize: " + err.Error()
				} else if err := load(ctx, actual); err != nil {
					result["error"] = "generated output cannot initialize: " + err.Error()
				} else {
					result["passed"] = true
					result["runtime_checked"] = true
				}
			}
		}
		cancel()
		results = append(results, result)
	}
	return results
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: core-probe schema <source-root> <output> | check <cases> <output>")
	}
	var result any
	switch os.Args[1] {
	case "schema":
		result = schema(os.Args[2])
	case "check":
		result = check(os.Args[2])
	default:
		panic("unknown mode")
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[3], data, 0600); err != nil {
		panic(err)
	}
	fmt.Println(os.Args[3])
}
