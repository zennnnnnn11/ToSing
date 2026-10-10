param([string]$AuditDir = $PSScriptRoot, [string]$CaseFilter = '')
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir -CaseFilter $CaseFilter
$taskSsUser = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('aes-128-gcm:test-password')).TrimEnd('=')
$taskVmessJson = @{ v = '2'; ps = 'basic-vmess'; add = '127.0.0.1'; port = '443'; id = $taskUuid; aid = '0'; scy = 'auto'; net = 'tcp'; tls = 'tls' } | ConvertTo-Json -Compress
$taskVmessLink = 'vmess://' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($taskVmessJson))
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443'
$taskTuic = 'tuic://' + $taskUuid + ':test-password@127.0.0.1:443'

Add-AuditCase '01-basic-vless' ($taskVless + '?security=tls#basic-vless') { param($n) $n.Count -eq 1 }
Add-AuditCase '02-basic-vmess' $taskVmessLink { param($n) $n.Count -eq 1 }
Add-AuditCase '03-basic-trojan' 'trojan://test-password@127.0.0.1:443#basic-trojan' { param($n) $n.Count -eq 1 }
Add-AuditCase '04-basic-ss' ('ss://' + $taskSsUser + '@127.0.0.1:8388#basic-ss') { param($n) $n.Count -eq 1 }
Add-AuditCase '05-basic-hysteria2' 'hysteria2://test-password@127.0.0.1:443#basic-hy2' { param($n) $n.Count -eq 1 }
Add-AuditCase '06-basic-tuic' ($taskTuic + '#basic-tuic') { param($n) $n.Count -eq 1 }
Add-AuditCase '07-basic-anytls' 'anytls://test-password@127.0.0.1:443#basic-anytls' { param($n) $n.Count -eq 1 }

foreach ($taskProto in @('vless','vmess','trojan')) {
    $taskAuthYaml = if ($taskProto -eq 'trojan') { "    password: test-password" } else { "    uuid: $taskUuid" }
    $taskYaml = @('proxies:', "  - name: h2-$taskProto", "    type: $taskProto", '    server: 127.0.0.1', '    port: 443', $taskAuthYaml, '    tls: true', '    network: h2', '    path: /tunnel') -join [Environment]::NewLine
    Add-AuditCase "h2-$taskProto" $taskYaml { param($n) $n.Count -eq 1 -and $n[0].transport.type -eq 'http' } { param($n) $n[0].transport.type = 'http'; return ,$n }
}
Add-AuditCase 'hy2-utls' 'hy2://test-password@127.0.0.1:443?fp=chrome#hy2-utls' { param($n) $n.Count -eq 1 -and !$n[0].tls.ContainsKey('utls') } { param($n) [void]$n[0].tls.Remove('utls'); return ,$n }
Add-AuditCase 'tuic-utls' ($taskTuic + '?fp=chrome#tuic-utls') { param($n) $n.Count -eq 1 -and !$n[0].tls.ContainsKey('utls') } { param($n) [void]$n[0].tls.Remove('utls'); return ,$n }
Add-AuditCase 'ws-query' ($taskVless + '?security=tls&type=ws&path=%2Fws%3Ftoken%3Dabc#ws-query') { param($n) $n.Count -eq 1 -and $n[0].transport.path -eq '/ws?token=abc' } { param($n) $n[0].transport.path = '/ws?token=abc'; return ,$n }
$taskWsYaml = @"
proxies:
  - name: ws-extra
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: front.example.com
        X-Custom: audit-value
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
"@
Add-AuditCase 'ws-headers-early-data' $taskWsYaml { param($n) $n[0].transport.headers['X-Custom'] -eq 'audit-value' -and $n[0].transport.max_early_data -eq 2048 } { param($n) $n[0].transport.headers['X-Custom'] = 'audit-value'; $n[0].transport.max_early_data = 2048; $n[0].transport.early_data_header_name = 'Sec-WebSocket-Protocol'; return ,$n }
$taskHttpYaml = @"
proxies:
  - name: http-options
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    network: http
    http-opts:
      path: [/tunnel]
      method: POST
      headers:
        Host: [front.example.com]
        User-Agent: audit-agent
"@
Add-AuditCase 'http-options' $taskHttpYaml { param($n) $n[0].transport.path -eq '/tunnel' -and $n[0].transport.method -eq 'POST' } { param($n) $n[0].transport.path = '/tunnel'; $n[0].transport.method = 'POST'; $n[0].transport.host = @('front.example.com'); $n[0].transport.headers = @{ 'User-Agent' = 'audit-agent' }; return ,$n }
Add-AuditCase 'httpupgrade-host' ($taskVless + '?security=tls&type=httpupgrade&host=front.example.com&path=%2Ftunnel#upgrade') { param($n) $n[0].transport.host -eq 'front.example.com' } { param($n) $n[0].transport.host = 'front.example.com'; return ,$n }
Add-AuditCase 'v2ray-quic' ($taskVless + '?security=tls&type=quic#v2ray-quic') { param($n) $n[0].transport.type -eq 'quic' } { param($n) $n[0].transport = @{ type = 'quic' }; return ,$n }
$taskPlugin = 'obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dfront.example.com'
Add-AuditCase 'ss-plugin-query-no-slash' ('ss://' + $taskSsUser + '@127.0.0.1:8388?plugin=' + $taskPlugin + '#ss-plugin') { param($n) $n.Count -eq 1 -and $n[0].plugin -eq 'obfs-local' } { param($n) return ,@(@{ type = 'shadowsocks'; tag = 'ss-plugin'; server = '127.0.0.1'; server_port = 8388; method = 'aes-128-gcm'; password = 'test-password'; plugin = 'obfs-local'; plugin_opts = 'obfs=http;obfs-host=front.example.com' }) }
Add-AuditCase 'ss-plugin-query-with-slash' ('ss://' + $taskSsUser + '@127.0.0.1:8388/?plugin=' + $taskPlugin + '#ss-plugin') { param($n) $n.Count -eq 1 -and $n[0].plugin -eq 'obfs-local' } { param($n) $n[0].plugin = 'obfs-local'; $n[0].plugin_opts = 'obfs=http;obfs-host=front.example.com'; return ,$n }
Add-AuditCase 'hy2-userpass' 'hy2://alice:test-password@127.0.0.1:443#userpass' { param($n) $n[0].password -eq 'alice:test-password' } { param($n) $n[0].password = 'alice:test-password'; return ,$n }
Add-AuditCase 'vless-empty-packet-encoding' ($taskVless + '?security=tls&packet_encoding=#empty-packet') { param($n) $n[0].ContainsKey('packet_encoding') -and $n[0].packet_encoding -eq '' } { param($n) $n[0].packet_encoding = ''; return ,$n }
Add-AuditCase 'tls-options' ($taskVless + '?security=tls&disable_sni=true&min_version=1.3&max_version=1.3#tls-options') { param($n) $n[0].tls.disable_sni -eq $true -and $n[0].tls.min_version -eq '1.3' } { param($n) $n[0].tls.disable_sni = $true; $n[0].tls.min_version = '1.3'; $n[0].tls.max_version = '1.3'; return ,$n }
$taskMuxYaml = @"
proxies:
  - name: mux-options
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    smux:
      enabled: true
      protocol: yamux
      max-connections: 2
      min-streams: 2
      max-streams: 8
      padding: true
"@
Add-AuditCase 'mux-options' $taskMuxYaml { param($n) $n[0].multiplex.protocol -eq 'yamux' -and $n[0].multiplex.padding -eq $true -and $n[0].multiplex.max_streams -eq 8 } { param($n) $n[0].multiplex.protocol = 'yamux'; $n[0].multiplex.padding = $true; $n[0].multiplex.min_streams = 2; $n[0].multiplex.max_streams = 8; return ,$n }
Add-AuditCase 'tuic-stream-heartbeat' ($taskTuic + '?udp_over_stream=true&heartbeat=15s#tuic-options') { param($n) $n[0].udp_over_stream -eq $true -and $n[0].heartbeat -eq '15s' } { param($n) $n[0].udp_over_stream = $true; $n[0].heartbeat = '15s'; return ,$n }
Add-AuditCase 'anytls-client-metadata' 'anytls://test-password@127.0.0.1:443?client_metadata=audit-client#anytls-metadata' { param($n) $n[0].client_metadata -eq 'audit-client' } { param($n) $n[0].client_metadata = 'audit-client'; return ,$n }
Add-AuditCase 'hy2-hop-interval' 'hy2://test-password@127.0.0.1:443?mport=20000%3A20010&hop_interval=10s&hop_interval_max=20s#hy2-hop' { param($n) $n[0].hop_interval -eq '10s' -and $n[0].hop_interval_max -eq '20s' } { param($n) $n[0].hop_interval = '10s'; $n[0].hop_interval_max = '20s'; return ,$n }
Add-AuditCase 'hy2-hyphen-port-range' 'hy2://test-password@127.0.0.1:443?mport=20000-20010#hy2-port' { param($n) $n[0].server_ports[0] -eq '20000:20010' } { param($n) $n[0].server_ports = @('20000:20010'); return ,$n }
Add-AuditCase 'hy2-missing-obfs-password' 'hy2://test-password@127.0.0.1:443?obfs=salamander#invalid-obfs' { param($n) $n.Count -eq 0 }
Add-AuditCase 'vless-unknown-packet-encoding' ($taskVless + '?security=tls&packet_encoding=bogus#invalid-packet') { param($n) $n.Count -eq 0 }
Add-AuditCase 'tuic-invalid-uuid' 'tuic://invalid-uuid:test-password@127.0.0.1:443#invalid-uuid' { param($n) $n.Count -eq 0 }
Add-AuditCase 'vless-unknown-flow' ($taskVless + '?security=tls&flow=bogus#invalid-flow') { param($n) $n.Count -eq 0 }
Add-AuditCase 'supported-fingerprint-alias' ($taskVless + '?security=tls&fp=chrome_pq#fingerprint-alias') { param($n) $n[0].tls.utls.enabled -eq $true } { param($n) $n[0].tls.utls = @{ enabled = $true; fingerprint = 'chrome_pq' }; return ,$n }

$taskPluginYaml = @"
proxies:
  - name: ss-plugin-flags
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: test-password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: localhost
      tls: false
      mux: 0
      path: /ws;token=abc
"@
Add-AuditCase 'ss-plugin-flags-and-escaping' $taskPluginYaml { param($n) $n[0].plugin_opts -notmatch '(?:^|;)tls=' -and $n[0].plugin_opts.Contains('path=/ws\;token=abc') } { param($n) $n[0].plugin_opts = 'mode=websocket;host=localhost;mux=0;path=/ws\;token=abc'; return ,$n }

. (Join-Path $PSScriptRoot 'runner.ps1')
