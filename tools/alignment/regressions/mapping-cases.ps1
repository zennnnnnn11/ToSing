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
. (Join-Path $PSScriptRoot 'runner.ps1')

