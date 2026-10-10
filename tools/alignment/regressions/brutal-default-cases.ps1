param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskEmptyBrutal = @"
proxies:
  - name: empty-brutal
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    smux:
      enabled: true
      brutal: {}
"@
Add-AuditCase 'brutal-empty-section' $taskEmptyBrutal { param($n) $n.Count -eq 1 -and (!$n[0].multiplex.ContainsKey('brutal') -or !$n[0].multiplex.brutal.enabled) } { param($n) $n[0].multiplex.brutal = @{}; return ,$n }
$taskImplicitBrutal = @"
proxies:
  - name: implicit-brutal
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    smux:
      enabled: true
      brutal:
        up_mbps: 10
        down_mbps: 20
"@
Add-AuditCase 'brutal-omitted-enabled' $taskImplicitBrutal { param($n) $n.Count -eq 1 -and !$n[0].multiplex.brutal.enabled } { param($n) [void]$n[0].multiplex.brutal.Remove('enabled'); return ,$n }
. (Join-Path $PSScriptRoot 'runner.ps1')
