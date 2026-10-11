param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir

$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443?security=tls#node-vless'
$taskHy2 = 'hysteria2://test-password@127.0.0.1:8443?sni=test.com#node-hy2'
$taskSs = 'ss://' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('aes-128-gcm:test-password')).TrimEnd('=') + '@127.0.0.1:8388#node-vless'

# 测试 1: Clash YAML 与裸 URI 混贴，同名节点自动加 (1) 防冲突
$mixedYamlAndUri = @"
proxies:
  - name: node-vless
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true

$taskVless
$taskHy2
"@

Add-AuditCase 'mixed-yaml-and-uris' $mixedYamlAndUri {
    param($n)
    $n.Count -eq 3 -and $n[0].tag -eq 'node-vless' -and $n[1].tag -eq 'node-vless (1)' -and $n[2].tag -eq 'node-hy2'
} {
    param($n)
    $n[1].tag = 'node-vless (1)'
    return ,$n
}

# 测试 2: 包含注释与广告节点的混贴清洗
$mixedWithAdsAndComments = @"
# 顶部说明注释
$taskHy2

# 广告垃圾节点
vless://$taskUuid@127.0.0.1:443?security=tls#官网永久发布页-流量到期提示

$taskSs
"@

Add-AuditCase 'mixed-ads-and-comments' $mixedWithAdsAndComments {
    param($n)
    $n.Count -eq 2 -and $n[0].tag -eq 'node-hy2' -and $n[1].tag -eq 'node-vless'
} {
    param($n)
    return ,$n
}

. (Join-Path $PSScriptRoot 'runner.ps1')
