param([string]$AuditDir = $PSScriptRoot, [string]$CaseFilter = '')
$taskDotnet = if ($env:SUB_PARSER_ALIGNMENT_DOTNET) { $env:SUB_PARSER_ALIGNMENT_DOTNET } else { (Get-Command dotnet -ErrorAction Stop).Source }
$taskParser = Join-Path $AuditDir 'parser\ToSing.dll'
$taskSingbox = Join-Path $AuditDir 'sing-box.exe'
$taskUuid = '11111111-1111-4111-8111-111111111111'
$taskCases = [System.Collections.Generic.List[object]]::new()

function Invoke-AuditProcess([string]$Executable, [string[]]$Arguments) {
    $taskStart = [System.Diagnostics.ProcessStartInfo]::new()
    $taskStart.FileName = $Executable
    $taskStart.UseShellExecute = $false
    $taskStart.CreateNoWindow = $true
    $taskStart.RedirectStandardOutput = $true
    $taskStart.RedirectStandardError = $true
    foreach ($taskArg in $Arguments) { $taskStart.ArgumentList.Add($taskArg) }
    $taskProcess = [System.Diagnostics.Process]::new()
    $taskProcess.StartInfo = $taskStart
    [void]$taskProcess.Start()
    $taskStdout = $taskProcess.StandardOutput.ReadToEndAsync()
    $taskStderr = $taskProcess.StandardError.ReadToEndAsync()
    if (!$taskProcess.WaitForExit(20000)) { $taskProcess.Kill($true); throw "Process timed out: $Executable" }
    $taskResult = [pscustomobject]@{ ExitCode = $taskProcess.ExitCode; Stdout = $taskStdout.GetAwaiter().GetResult(); Stderr = $taskStderr.GetAwaiter().GetResult() }
    $taskProcess.Dispose()
    return $taskResult
}
function Add-AuditCase([string]$Name, [string]$InputText, [scriptblock]$Preserves, [scriptblock]$ReferencePatch = $null) {
    $taskCases.Add([pscustomobject]@{ Name = $Name; InputText = $InputText; Preserves = $Preserves; ReferencePatch = $ReferencePatch })
}
function Invoke-ConfigCheck([object[]]$Nodes, [string]$Name) {
    $taskConfigPath = Join-Path $AuditDir ($Name + '.config.json')
    @{ log = @{ level = 'error' }; outbounds = @($Nodes) } | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $taskConfigPath -Encoding utf8
    return Invoke-AuditProcess $taskSingbox @('check', '--disable-color', '-c', $taskConfigPath)
}

