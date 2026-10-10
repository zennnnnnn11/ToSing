param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskVless = 'vless://' + $taskUuid + '@127.0.0.1:443?security=tls'
Add-AuditCase 'routing-mark-hex' ($taskVless + '&routing_mark=0x2023') { param($n) $n[0].routing_mark -eq 8227 -or $n[0].routing_mark -eq '0x2023' } { param($n) $n[0].routing_mark = '0x2023'; return ,$n }
Add-AuditCase 'routing-mark-uint32' ($taskVless + '&routing_mark=2147483648') { param($n) $n[0].routing_mark -eq 2147483648 } { param($n) $n[0].routing_mark = [uint32]2147483648; return ,$n }
. (Join-Path $PSScriptRoot 'runner.ps1')
