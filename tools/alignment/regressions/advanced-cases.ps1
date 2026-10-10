param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
function Invoke-ConfigCheck([object[]]$Nodes, [string]$Name) {
    $taskConfigPath = Join-Path $AuditDir ($Name + '.config.json')
    @{ log = @{ level = 'error' }; dns = @{ servers = @(@{ type = 'local'; tag = 'dns-local' }) }; outbounds = @($Nodes) } | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $taskConfigPath -Encoding utf8
    return Invoke-AuditProcess $taskSingbox @('check', '--disable-color', '-c', $taskConfigPath)
}
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443?security=tls'
$taskCertPath = (Join-Path $AuditDir 'test-cert.pem').Replace('\','/')
$taskKeyPath = (Join-Path $AuditDir 'test-key.pem').Replace('\','/')
$taskEchPath = (Join-Path $AuditDir 'test-ech.pem').Replace('\','/')
$taskCertText = Get-Content -LiteralPath $taskCertPath -Raw
$taskEchText = Get-Content -LiteralPath $taskEchPath -Raw
$taskCertIndented = (($taskCertText.TrimEnd() -split '\r?\n') | ForEach-Object { '      ' + $_ }) -join [Environment]::NewLine
$taskEchIndented = (($taskEchText.TrimEnd() -split '\r?\n') | ForEach-Object { '        ' + $_ }) -join [Environment]::NewLine
$taskEchRaw = ($taskEchText -split '\r?\n' | Where-Object {$_ -and !$_.StartsWith('-----')}) -join ''
$taskPin = [Convert]::ToBase64String([byte[]]::new(32))
$taskBaseYaml = @"
proxies:
  - name: advanced-node
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
"@
Add-AuditCase 'advanced-cipher-suites' ($taskVless + '&cipher_suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256%2CTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384') { param($n) $n[0].tls.cipher_suites.Count -eq 2 }
Add-AuditCase 'advanced-ca-inline' ($taskBaseYaml + "`n    certificate: |`n" + $taskCertIndented) { param($n) $n[0].tls.certificate[0].Contains('BEGIN CERTIFICATE') }
Add-AuditCase 'advanced-ca-path' ($taskVless + '&certificate_path=' + [Uri]::EscapeDataString($taskCertPath)) { param($n) $n[0].tls.certificate_path -eq $taskCertPath }
Add-AuditCase 'advanced-certificate-pin' ($taskVless + '&certificate_sha256=' + [Uri]::EscapeDataString($taskPin)) { param($n) $n[0].tls.certificate_sha256[0] -eq $taskPin }
Add-AuditCase 'advanced-public-key-pin' ($taskVless + '&certificate_public_key_sha256=' + [Uri]::EscapeDataString($taskPin)) { param($n) $n[0].tls.certificate_public_key_sha256[0] -eq $taskPin }
Add-AuditCase 'advanced-mtls-paths' ($taskVless + '&client_certificate_path=' + [Uri]::EscapeDataString($taskCertPath) + '&client_key_path=' + [Uri]::EscapeDataString($taskKeyPath)) { param($n) $n[0].tls.client_certificate_path -eq $taskCertPath -and $n[0].tls.client_key_path -eq $taskKeyPath }
Add-AuditCase 'advanced-ech-pem' ($taskBaseYaml + "`n    ech:`n      enabled: true`n      config: |`n" + $taskEchIndented) { param($n) $n[0].tls.ech.enabled -and $n[0].tls.ech.config[0].Contains('BEGIN ECH CONFIGS') }
Add-AuditCase 'advanced-ech-base64' ($taskVless + '&ech=true&ech-config=' + [Uri]::EscapeDataString($taskEchRaw)) { param($n) $n[0].tls.ech.enabled -and $n[0].tls.ech.config[0] -eq '-----BEGIN ECH CONFIGS-----' }
Add-AuditCase 'advanced-dns-string' ($taskVless + '&domain_resolver=dns-local') { param($n) $n[0].domain_resolver -eq 'dns-local' }
Add-AuditCase 'advanced-dns-object-strings' ($taskBaseYaml + "`n    domain_resolver:`n      server: dns-local`n      strategy: ipv4_only") { param($n) $n[0].domain_resolver.server -eq 'dns-local' -and $n[0].domain_resolver.strategy -eq 'ipv4_only' }
Add-AuditCase 'advanced-common-dialer' ($taskVless + '&connect_timeout=5s&tcp_fast_open=true&reuse_addr=true&udp_fragment=false&inet4_bind_address=127.0.0.1&inet6_bind_address=%3A%3A1') { param($n) $n[0].connect_timeout -eq '5s' -and $n[0].tcp_fast_open -and $n[0].reuse_addr -and $n[0].ContainsKey('udp_fragment') -and !$n[0].udp_fragment -and $n[0].inet4_bind_address -eq '127.0.0.1' }
$taskRealmYaml = @"
proxies:
  - name: realm-case
    type: hysteria2
    password: test-password
    realm:
      server_url: https://realm.example.test/
      realm_id: test-realm
      stun_servers: [127.0.0.1:3478]
"@
Add-AuditCase 'advanced-realm-with-sni' ($taskRealmYaml + "`n    server: 127.0.0.1`n    port: 443`n    sni: realm.example.test") { param($n) $n.Count -eq 1 -and $n[0].realm.realm_id -eq 'test-realm' -and !$n[0].ContainsKey('server') -and !$n[0].ContainsKey('server_port') }

$taskVmessJson = @{ v='2'; ps='vmess-tls-token'; add='127.0.0.1'; port='443'; id=$taskUuid; aid='0'; scy='auto'; net='tcp'; tls='tls'; sni='audit.example' } | ConvertTo-Json -Compress
$taskVmessLink = 'vmess://' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($taskVmessJson))
Add-AuditCase 'regression-vmess-tls-token' $taskVmessLink { param($n) $n.Count -eq 1 -and $n[0].tls.enabled -eq $true } { param($n) $n[0].tls = @{enabled=$true;server_name='audit.example'}; return ,$n }
Add-AuditCase 'regression-ech-explicit-false' ($taskBaseYaml + "`n    ech:`n      enabled: false`n      config_path: /nonexistent/audit-ech.pem") { param($n) !$n[0].ContainsKey('tls') -or !$n[0].tls.ContainsKey('ech') -or !$n[0].tls.ech.enabled } { param($n) $n[0].tls.ech = @{enabled=$false}; return ,$n }
Add-AuditCase 'regression-realm-no-endpoint' $taskRealmYaml { param($n) $n.Count -eq 1 -and $n[0].realm.realm_id -eq 'test-realm' } { param($n) return ,@(@{type='hysteria2';tag='realm-case';password='test-password';tls=@{enabled=$true};realm=@{server_url='https://realm.example.test/';realm_id='test-realm';stun_servers=@('127.0.0.1:3478')}}) }
Add-AuditCase 'regression-realm-default-sni' ($taskRealmYaml + "`n    server: 127.0.0.1`n    port: 443") { param($n) $n.Count -eq 1 -and (!$n[0].tls.ContainsKey('server_name') -or $n[0].tls.server_name -eq 'realm.example.test') } { param($n) [void]$n[0].tls.Remove('server_name'); return ,$n }
Add-AuditCase 'regression-dns-object-types' ($taskBaseYaml + "`n    domain_resolver:`n      server: dns-local`n      disable_cache: true`n      rewrite_ttl: 60") { param($n) $n[0].domain_resolver.disable_cache -is [bool] -and $n[0].domain_resolver.rewrite_ttl -is [long] } { param($n) $n[0].domain_resolver.disable_cache = $true; $n[0].domain_resolver.rewrite_ttl = 60; return ,$n }
Add-AuditCase 'regression-legitimate-emergency-tag' ($taskVless + '#香港-应急') { param($n) $n.Count -eq 1 } { param($n) return ,@(@{type='vless';tag='香港-应急';server='127.0.0.1';server_port=443;uuid=$taskUuid;tls=@{enabled=$true;server_name='127.0.0.1'}}) }

. (Join-Path $PSScriptRoot 'runner.ps1')

