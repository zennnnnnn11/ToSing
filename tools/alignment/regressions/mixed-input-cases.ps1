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

# 测试 3: 连续两个纯 proxies 块拼接，节点无缝保留
$twoYamlBlocks = @"
proxies:
  - name: first-yaml
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true

proxies:
  - name: second-yaml
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
"@

Add-AuditCase 'mixed-two-yaml-blocks' $twoYamlBlocks {
    param($n)
    $n.Count -eq 2 -and $n[0].tag -eq 'first-yaml' -and $n[1].tag -eq 'second-yaml'
} {
    param($n)
    return ,$n
}

# 测试 4: YAML 携带 rule-providers 规则网址与节点参数携带 HTTP 路径，静默绝缘不外泄
$yamlWithRulesAndHttpPath = @"
proxies:
  - name: node-with-rules
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true

rule-providers:
  my-rules:
    type: http
    url: https://rules.invalid/my-rules.yaml

vless://$taskUuid@127.0.0.1:443?security=tls&type=ws&path=/go/http://path.invalid/file#node-with-http-path
"@

Add-AuditCase 'mixed-rules-and-http-path' $yamlWithRulesAndHttpPath {
    param($n)
    $n.Count -eq 2 -and $n[0].tag -eq 'node-with-rules' -and $n[1].tag -eq 'node-with-http-path'
} {
    param($n)
    return ,$n
}

# 测试 5: YAML proxies 标头后紧随带网址的注释，整段节点 100% 完整解析
$yamlWithUrlComment = @"
proxies: # source https://source.invalid/sub
  - name: node-url-comment
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: $taskUuid
    tls: true
"@

Add-AuditCase 'mixed-yaml-url-comment' $yamlWithUrlComment {
    param($n)
    $n.Count -eq 1 -and $n[0].tag -eq 'node-url-comment'
} {
    param($n)
    return ,$n
}

. (Join-Path $PSScriptRoot 'runner.ps1')
