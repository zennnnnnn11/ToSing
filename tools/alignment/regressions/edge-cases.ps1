param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443'
$taskTuic = 'tuic://' + $taskUuid + ':test-password@127.0.0.1:443'
$taskSsUser = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('aes-128-gcm:test-password')).TrimEnd('=')

Add-AuditCase 'edge-vless-flow-udp443' ($taskVless + '?security=tls&flow=xtls-rprx-vision-udp443#flow-udp443') { param($n) $n.Count -eq 0 -or $n[0].flow -eq 'xtls-rprx-vision' } { param($n) $n[0].flow = 'xtls-rprx-vision'; return ,$n }
Add-AuditCase 'edge-vless-flow-uppercase' ($taskVless + '?security=tls&flow=XTLS-RPRX-VISION#flow-uppercase') { param($n) $n.Count -eq 0 -or $n[0].flow -ceq 'xtls-rprx-vision' } { param($n) $n[0].flow = 'xtls-rprx-vision'; return ,$n }
Add-AuditCase 'edge-tuic-stream-relay-conflict' ($taskTuic + '?udp_over_stream=true&udp_relay_mode=native#tuic-conflict') { param($n) $n.Count -eq 0 -or !($n[0].udp_over_stream -and $n[0].udp_relay_mode) } { param($n) [void]$n[0].Remove('udp_relay_mode'); return ,$n }
Add-AuditCase 'edge-tuic-parenthesis-uuid' ('tuic://%28' + $taskUuid + '%29:test-password@127.0.0.1:443#tuic-parenthesis') { param($n) $n.Count -eq 0 -or $n[0].uuid -eq $taskUuid } { param($n) $n[0].uuid = $taskUuid; return ,$n }

$taskPluginPlus = [Uri]::EscapeDataString('v2ray-plugin;mode=websocket;host=localhost;mux=0;path=/a+b')
Add-AuditCase 'edge-ss-plugin-plus' ('ss://' + $taskSsUser + '@127.0.0.1:8388?plugin=' + $taskPluginPlus + '#plugin-plus') { param($n) $n[0].plugin_opts.Contains('path=/a+b') } { param($n) $n[0].plugin_opts = 'mode=websocket;host=localhost;mux=0;path=/a+b'; return ,$n }
$taskPluginPercent = [Uri]::EscapeDataString('v2ray-plugin;mode=websocket;host=localhost;mux=0;path=/a%2Fb')
Add-AuditCase 'edge-ss-plugin-percent' ('ss://' + $taskSsUser + '@127.0.0.1:8388?plugin=' + $taskPluginPercent + '#plugin-percent') { param($n) $n[0].plugin_opts.Contains('path=/a%2Fb') } { param($n) $n[0].plugin_opts = 'mode=websocket;host=localhost;mux=0;path=/a%2Fb'; return ,$n }
$taskPluginStringYaml = @"
proxies:
  - name: string-options
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: test-password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: "false"
      path: "true"
      mux: 0
"@
Add-AuditCase 'edge-ss-plugin-string-booleans' $taskPluginStringYaml { param($n) $n[0].plugin_opts.Contains('host=false') -and $n[0].plugin_opts.Contains('path=true') } { param($n) $n[0].plugin_opts = 'mode=websocket;host=false;path=true;mux=0'; return ,$n }
Add-AuditCase 'edge-http-path-ed' ($taskVless + '?security=tls&type=http&path=%2Ftunnel%3Fed%3D2048#http-path-ed') { param($n) $n[0].transport.path -eq '/tunnel?ed=2048' } { param($n) $n[0].transport.path = '/tunnel?ed=2048'; return ,$n }
$taskHeaderYaml = @"
proxies:
  - name: header-list
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
    network: http
    http-opts:
      path: [/tunnel]
      headers:
        X-Audit: [one, two]
"@
Add-AuditCase 'edge-http-multi-header' $taskHeaderYaml { param($n) $n[0].transport.headers['X-Audit'] -is [array] -and $n[0].transport.headers['X-Audit'].Count -eq 2 } { param($n) $n[0].transport.headers['X-Audit'] = @('one','two'); return ,$n }

. (Join-Path $PSScriptRoot 'runner.ps1')
