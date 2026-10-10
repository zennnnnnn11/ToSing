param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443?security=tls'
Add-AuditCase 'ech-false-uri-scalar' ($taskVless + '&ech=false&ech-config-path=%2Fnonexistent%2Faudit-ech.pem') { param($n) $n.Count -eq 1 -and (!$n[0].tls.ContainsKey('ech') -or !$n[0].tls.ech.enabled) } { param($n) $n[0].tls.ech = @{enabled=$false}; return ,$n }
$taskYaml = @"
proxies:
  - name: ech-false-scalar
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    ech: false
    ech-config-path: /nonexistent/audit-ech.pem
"@
Add-AuditCase 'ech-false-yaml-scalar' $taskYaml { param($n) $n.Count -eq 1 -and (!$n[0].tls.ContainsKey('ech') -or !$n[0].tls.ech.enabled) } { param($n) $n[0].tls.ech = @{enabled=$false}; return ,$n }
. (Join-Path $PSScriptRoot 'runner.ps1')
