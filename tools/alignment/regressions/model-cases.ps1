param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskVmessOptions = @"
proxies:
  - name: vmess-new-fields
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    cipher: auto
    tls: true
    global_padding: true
    authenticated_length: true
"@
Add-AuditCase 'model-vmess-new-fields' $taskVmessOptions { param($n) $n[0].global_padding -eq $true -and $n[0].authenticated_length -eq $true } { param($n) $n[0].global_padding = $true; $n[0].authenticated_length = $true; return ,$n }

$taskHy2Options = @"
proxies:
  - name: hy2-new-fields
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: test-password
    idle_timeout: 120s
    keep_alive_period: 15s
    disable_path_mtu_discovery: true
    bbr_profile: aggressive
"@
Add-AuditCase 'model-hy2-new-fields' $taskHy2Options { param($n) $n[0].idle_timeout -eq '120s' -and $n[0].keep_alive_period -eq '15s' -and $n[0].disable_path_mtu_discovery -eq $true -and $n[0].bbr_profile -eq 'aggressive' } { param($n) $n[0].idle_timeout = '120s'; $n[0].keep_alive_period = '15s'; $n[0].disable_path_mtu_discovery = $true; $n[0].bbr_profile = 'aggressive'; return ,$n }

$taskTuicOptions = @"
proxies:
  - name: tuic-new-fields
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    password: test-password
    idle_timeout: 120s
    keep_alive_period: 15s
    disable_path_mtu_discovery: true
"@
Add-AuditCase 'model-tuic-new-fields' $taskTuicOptions { param($n) $n[0].idle_timeout -eq '120s' -and $n[0].keep_alive_period -eq '15s' -and $n[0].disable_path_mtu_discovery -eq $true } { param($n) $n[0].idle_timeout = '120s'; $n[0].keep_alive_period = '15s'; $n[0].disable_path_mtu_discovery = $true; return ,$n }

$taskBrutalOptions = @"
proxies:
  - name: brutal-new-fields
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    smux:
      enabled: true
      protocol: h2mux
      max-connections: 1
      brutal:
        enabled: true
        up_mbps: 10
        down_mbps: 20
"@
Add-AuditCase 'model-mux-brutal' $taskBrutalOptions { param($n) $n[0].multiplex.brutal.enabled -eq $true -and $n[0].multiplex.brutal.up_mbps -eq 10 } { param($n) $n[0].multiplex.brutal = @{ enabled = $true; up_mbps = 10; down_mbps = 20 }; return ,$n }

. (Join-Path $PSScriptRoot 'runner.ps1')
