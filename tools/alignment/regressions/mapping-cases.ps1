param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443?security=tls'
Add-AuditCase 'mapping-http-timeouts-uri' ($taskVless + '&type=http&idle_timeout=45s&ping_timeout=12s') { param($n) $n[0].transport.idle_timeout -eq '45s' -and $n[0].transport.ping_timeout -eq '12s' } { param($n) $n[0].transport.idle_timeout='45s'; $n[0].transport.ping_timeout='12s'; return ,$n }
Add-AuditCase 'mapping-grpc-keepalive-uri' ($taskVless + '&type=grpc&serviceName=audit&idle_timeout=45s&ping_timeout=12s&permit_without_stream=true') { param($n) $n[0].transport.idle_timeout -eq '45s' -and $n[0].transport.ping_timeout -eq '12s' -and $n[0].transport.permit_without_stream -eq $true } { param($n) $n[0].transport.idle_timeout='45s'; $n[0].transport.ping_timeout='12s'; $n[0].transport.permit_without_stream=$true; return ,$n }
$taskHttp = @"
proxies:
  - name: http-timeout-fields
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    network: http
    http-opts:
      path: /
      idle_timeout: 45s
      ping_timeout: 12s
"@
Add-AuditCase 'mapping-http-timeouts-yaml' $taskHttp { param($n) $n[0].transport.idle_timeout -eq '45s' -and $n[0].transport.ping_timeout -eq '12s' } { param($n) $n[0].transport.idle_timeout='45s'; $n[0].transport.ping_timeout='12s'; return ,$n }
$taskGrpc = @"
proxies:
  - name: grpc-keepalive-fields
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: audit
      idle_timeout: 45s
      ping_timeout: 12s
      permit_without_stream: true
"@
Add-AuditCase 'mapping-grpc-keepalive-yaml' $taskGrpc { param($n) $n[0].transport.idle_timeout -eq '45s' -and $n[0].transport.ping_timeout -eq '12s' -and $n[0].transport.permit_without_stream -eq $true } { param($n) $n[0].transport.idle_timeout='45s'; $n[0].transport.ping_timeout='12s'; $n[0].transport.permit_without_stream=$true; return ,$n }
foreach ($taskProtocol in @('trojan','anytls')) {
    Add-AuditCase ('credential-colon-' + $taskProtocol + '-uri') ($taskProtocol + '://prefix%3Atail@127.0.0.1:443?security=tls') { param($n) $n[0].password -ceq 'prefix:tail' } { param($n) $n[0].password='prefix:tail'; return ,$n }
    $taskPasswordYaml = @"
proxies:
  - name: colon-credential
    type: $taskProtocol
    server: 127.0.0.1
    port: 443
    password: "prefix:tail"
    tls: true
"@
    Add-AuditCase ('credential-colon-' + $taskProtocol + '-yaml') $taskPasswordYaml { param($n) $n[0].password -ceq 'prefix:tail' }
}
Add-AuditCase 'ech-disable-zero-uri' ($taskVless + '&ech=0&ech-config-path=%2Fnonexistent%2Faudit-ech.pem') { param($n) !$n[0].tls.ContainsKey('ech') -or !$n[0].tls.ech.enabled }
Add-AuditCase 'ech-disable-uppercase-uri' ($taskVless + '&ech=FALSE&ech-config-path=%2Fnonexistent%2Faudit-ech.pem') { param($n) !$n[0].tls.ContainsKey('ech') -or !$n[0].tls.ech.enabled }

$taskDialerProxyYaml = @"
proxies:
  - name: dialer-proxy-node
    type: shadowsocks
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: pass
    dialer-proxy: proxy-chain-tag
    fast-open: true
"@
Add-AuditCase 'mapping-dialer-proxy-detour-yaml' $taskDialerProxyYaml { param($n) $n[0].detour -eq 'proxy-chain-tag' -and $n[0].tcp_fast_open -eq $true } { param($n) $n[0].detour = 'proxy-chain-tag'; $n[0].tcp_fast_open = $true; return ,$n }

Add-AuditCase 'mapping-hy2-pinsha256-uri' 'hy2://my-pass@127.0.0.1:443?pinSHA256=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff#hy2-pin' { param($n) $n[0].tls.certificate_sha256[0] -eq 'ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8=' } { param($n) $n[0].tls.certificate_sha256 = @('ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8='); return ,$n }

$taskHy2FingerprintYaml = @"
proxies:
  - name: hy2-fingerprint-hex
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: my-pass
    fingerprint: 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff
"@
Add-AuditCase 'mapping-hy2-fingerprint-hex-yaml' $taskHy2FingerprintYaml { param($n) $n[0].tls.certificate_sha256[0] -eq 'ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8=' } { param($n) $n[0].tls.certificate_sha256 = @('ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8='); return ,$n }

$taskHy2ColonFpYaml = @"
proxies:
  - name: hy2-colon-fp
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: my-pass
    fingerprint: 11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF
"@
Add-AuditCase 'mapping-hy2-colon-fp-yaml' $taskHy2ColonFpYaml { param($n) $n[0].tls.certificate_sha256[0] -eq 'ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8=' } { param($n) $n[0].tls.certificate_sha256 = @('ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8='); return ,$n }

$taskTuicCcYaml = @"
proxies:
  - name: tuic-congestion-controller
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    password: test-password
    congestion-controller: bbr
"@
Add-AuditCase 'mapping-tuic-congestion-controller-yaml' $taskTuicCcYaml { param($n) $n[0].congestion_control -eq 'bbr' } { param($n) $n[0].congestion_control = 'bbr'; return ,$n }

. (Join-Path $PSScriptRoot 'runner.ps1')

