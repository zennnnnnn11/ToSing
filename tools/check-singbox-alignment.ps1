#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SingBoxSource,
    [string]$DotNet = 'dotnet',
    [string]$Go = 'go',
    [switch]$RequireAllRuntime
)

$ErrorActionPreference = 'Stop'
$alignmentRepo = Split-Path $PSScriptRoot -Parent
$alignmentCore = (Resolve-Path -LiteralPath $SingBoxSource).Path
if (!(Test-Path -LiteralPath (Join-Path $alignmentCore 'go.mod'))) {
    $alignmentNested = Join-Path $alignmentCore 'sing-box-testing'
    if (Test-Path -LiteralPath (Join-Path $alignmentNested 'go.mod')) { $alignmentCore = $alignmentNested }
}
if (!(Test-Path -LiteralPath (Join-Path $alignmentCore 'go.mod')) -or
    !(Select-String -LiteralPath (Join-Path $alignmentCore 'go.mod') -Pattern '^module github.com/sagernet/sing-box$' -Quiet)) {
    throw "Not a sing-box Go module: $alignmentCore"
}
$alignmentDotNet = (Get-Command $DotNet -ErrorAction Stop).Source
$alignmentGo = (Get-Command $Go -ErrorAction Stop).Source
$alignmentPwsh = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
$alignmentTags = 'with_quic,with_utls,with_grpc,with_wireguard,with_clash_api'
$alignmentRun = Join-Path $alignmentRepo ('artifacts/alignment/run-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
[void](New-Item -ItemType Directory -Path $alignmentRun)
$alignmentIssues = [Collections.Generic.List[string]]::new()
$alignmentSkipped = [Collections.Generic.List[object]]::new()
$alignmentLegacy = [Collections.Generic.List[object]]::new()
$alignmentReport = [ordered]@{
    status = 'running'; started_utc = [DateTime]::UtcNow.ToString('o'); core_source = $alignmentCore
    build_tags = $alignmentTags; require_all_runtime = [bool]$RequireAllRuntime
    scope = 'Seven supported outbound protocols and 25 associated option groups; configuration conversion and construction, without network handshakes.'
    output_directory = $alignmentRun
}

function Invoke-AlignmentProcess([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory, [int]$TimeoutSeconds = 600) {
    Write-Host "[$Name]"
    $alignmentStart = [Diagnostics.ProcessStartInfo]::new()
    $alignmentStart.FileName = $Executable
    $alignmentStart.WorkingDirectory = $WorkingDirectory
    $alignmentStart.UseShellExecute = $false
    $alignmentStart.CreateNoWindow = $true
    $alignmentStart.RedirectStandardOutput = $true
    $alignmentStart.RedirectStandardError = $true
    foreach ($alignmentArg in $Arguments) { $alignmentStart.ArgumentList.Add($alignmentArg) }
    $alignmentStart.Environment['CGO_ENABLED'] = '0'
    $alignmentStart.Environment['GOTOOLCHAIN'] = 'local'
    $alignmentStart.Environment['SUB_PARSER_ALIGNMENT_DOTNET'] = $alignmentDotNet
    $alignmentProcess = [Diagnostics.Process]::new()
    $alignmentProcess.StartInfo = $alignmentStart
    try {
        [void]$alignmentProcess.Start()
        $alignmentOut = $alignmentProcess.StandardOutput.ReadToEndAsync()
        $alignmentErr = $alignmentProcess.StandardError.ReadToEndAsync()
        if (!$alignmentProcess.WaitForExit($TimeoutSeconds * 1000)) {
            $alignmentProcess.Kill($true)
            throw "Timed out: $Name"
        }
        $alignmentStdout = $alignmentOut.GetAwaiter().GetResult()
        $alignmentStderr = $alignmentErr.GetAwaiter().GetResult()
        Set-Content -LiteralPath (Join-Path $alignmentRun "$Name.stdout.log") -Value $alignmentStdout -NoNewline
        Set-Content -LiteralPath (Join-Path $alignmentRun "$Name.stderr.log") -Value $alignmentStderr -NoNewline
        return [pscustomobject]@{ ExitCode = $alignmentProcess.ExitCode; Stdout = $alignmentStdout; Stderr = $alignmentStderr }
    } finally { $alignmentProcess.Dispose() }
}
function Invoke-AlignmentRequired([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$Directory) {
    $alignmentResult = Invoke-AlignmentProcess $Name $Executable $Arguments $Directory
    if ($alignmentResult.ExitCode -ne 0) { throw "$Name failed ($($alignmentResult.ExitCode)). $($alignmentResult.Stderr) $($alignmentResult.Stdout)" }
    return $alignmentResult
}
function Get-AlignmentManifest([string]$Root, [string[]]$Globs) {
    $alignmentRgArgs = @('--files')
    foreach ($alignmentGlob in $Globs) { $alignmentRgArgs += @('-g', $alignmentGlob) }
    $alignmentPaths = & rg @alignmentRgArgs $Root
    if ($LASTEXITCODE -ne 0) { throw "Cannot enumerate source files: $Root (requires rg)" }
    $alignmentManifest = foreach ($alignmentPath in ($alignmentPaths | Sort-Object)) {
        [pscustomobject]@{ path = [IO.Path]::GetRelativePath($Root, $alignmentPath).Replace('\','/'); sha256 = (Get-FileHash -LiteralPath $alignmentPath -Algorithm SHA256).Hash }
    }
    return @($alignmentManifest)
}
function Get-AlignmentDigest($Manifest) {
    $alignmentBytes = [Text.Encoding]::UTF8.GetBytes(($Manifest | ConvertTo-Json -Depth 4 -Compress))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($alignmentBytes))
}

try {
    $alignmentCoreGlobs = @('*.go','go.mod','go.sum')
    $alignmentParserGlobs = @('*.cs','*.csproj','*.props','*.targets','global.json','nuget.config','SingboxContract.json','*.ps1','*.go','*.pem')
    $alignmentCoreManifest = Get-AlignmentManifest $alignmentCore $alignmentCoreGlobs
    $alignmentParserManifest = Get-AlignmentManifest $alignmentRepo $alignmentParserGlobs
    $alignmentReport.core_source_sha256 = Get-AlignmentDigest $alignmentCoreManifest
    $alignmentReport.parser_source_sha256 = Get-AlignmentDigest $alignmentParserManifest
    $alignmentCoreManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $alignmentRun 'core-source-manifest.json')
    $alignmentParserManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $alignmentRun 'parser-source-manifest.json')
    $alignmentReport.parser_git_head = (& git -C $alignmentRepo rev-parse HEAD).Trim()
    $alignmentReport.parser_git_status = @(& git -C $alignmentRepo status --short)
    $alignmentReport.dotnet_version = (Invoke-AlignmentRequired 'dotnet-version' $alignmentDotNet @('--version') $alignmentRepo).Stdout.Trim()
    $alignmentReport.go_version = (Invoke-AlignmentRequired 'go-version' $alignmentGo @('version') $alignmentCore).Stdout.Trim()

    $alignmentParserOutput = Join-Path $alignmentRun 'parser'
    $alignmentProbeOutput = Join-Path $alignmentRun 'probe'
    [void](Invoke-AlignmentRequired 'build-parser' $alignmentDotNet @('build',(Join-Path $alignmentRepo 'SubParser.csproj'),'-o',$alignmentParserOutput,'--nologo') $alignmentRepo)
    [void](Invoke-AlignmentRequired 'build-model-probe' $alignmentDotNet @('build',(Join-Path $PSScriptRoot 'alignment/AlignmentProbe.csproj'),'-o',$alignmentProbeOutput,'--nologo') $alignmentRepo)
    $alignmentCoreProbe = Join-Path $alignmentRun 'core-probe.exe'
    $alignmentKernel = Join-Path $alignmentRun 'sing-box.exe'
    [void](Invoke-AlignmentRequired 'build-core-probe' $alignmentGo @('build','-tags',$alignmentTags,'-o',$alignmentCoreProbe,(Join-Path $PSScriptRoot 'alignment/core_probe.go')) $alignmentCore)
    [void](Invoke-AlignmentRequired 'build-sing-box' $alignmentGo @('build','-tags',$alignmentTags,'-o',$alignmentKernel,'./cmd/sing-box') $alignmentCore)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'alignment/fixtures/test-cert.pem'),(Join-Path $PSScriptRoot 'alignment/fixtures/test-key.pem'),(Join-Path $PSScriptRoot 'alignment/fixtures/test-ech.pem') -Destination $alignmentRun
    $alignmentSchemaPath = Join-Path $alignmentRun 'core-schema.json'
    [void](Invoke-AlignmentRequired 'extract-core-schema' $alignmentCoreProbe @('schema',$alignmentCore,$alignmentSchemaPath) $alignmentRepo)
    $alignmentModel = Invoke-AlignmentProcess 'check-models' $alignmentDotNet @((Join-Path $alignmentProbeOutput 'AlignmentProbe.dll'),$alignmentSchemaPath,$alignmentRun) $alignmentRepo
    $alignmentModelReport = Get-Content -LiteralPath (Join-Path $alignmentRun 'model-report.json') -Raw | ConvertFrom-Json -AsHashtable
    foreach ($alignmentIssue in $alignmentModelReport.issues) { $alignmentIssues.Add($alignmentIssue) }
    if ($alignmentModel.ExitCode -ne 0 -and $alignmentModelReport.issues.Count -eq 0) { $alignmentIssues.Add('Model checker exited without diagnostics') }
    [void](Invoke-AlignmentRequired 'check-fields-with-core' $alignmentCoreProbe @('check',(Join-Path $alignmentRun 'field-cases.json'),(Join-Path $alignmentRun 'field-results.json')) $alignmentRepo)
    $alignmentFields = @(Get-Content -LiteralPath (Join-Path $alignmentRun 'field-results.json') -Raw | ConvertFrom-Json -AsHashtable)
    if ($alignmentFields.Count -ne $alignmentModelReport.case_count -or $alignmentFields.Count -eq 0) { $alignmentIssues.Add('Field result count does not match generated cases') }
    foreach ($alignmentField in $alignmentFields) {
        if (!$alignmentField.passed) { $alignmentIssues.Add("Field: $($alignmentField.name): $($alignmentField.error)") }
        elseif ($alignmentField.schema_only -and !$alignmentField.rejection) { $alignmentSkipped.Add(@{ name=$alignmentField.name; reason=$alignmentField.schema_only }) }
    }

    foreach ($alignmentSuite in @('audit','edge-cases','model-cases','brutal-default-cases','advanced-cases','ech-scalar-cases','mapping-cases','mark-cases')) {
        $alignmentResult = Invoke-AlignmentProcess "regression-$alignmentSuite" $alignmentPwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot "alignment/regressions/$alignmentSuite.ps1"),'-AuditDir',$alignmentRun) $alignmentRepo
        if ($alignmentResult.ExitCode -ne 0) { $alignmentIssues.Add("Regression suite $alignmentSuite crashed: $($alignmentResult.Stderr)"); continue }
        $alignmentResultsPath = Join-Path $alignmentRun 'results.json'
        Copy-Item -LiteralPath $alignmentResultsPath -Destination (Join-Path $alignmentRun "$alignmentSuite.results.json")
        foreach ($alignmentCase in @(Get-Content -LiteralPath $alignmentResultsPath -Raw | ConvertFrom-Json -AsHashtable)) {
            $alignmentCase.suite = $alignmentSuite
            $alignmentCase.passed = $alignmentCase.parser_exit -eq 0 -and $alignmentCase.preserves_requested_semantics -and !$alignmentCase.parser_error
            if ($alignmentCase.kernel_exit -ne $null -and $alignmentCase.kernel_exit -ne 0) {
                if ($IsWindows -and $alignmentSuite -eq 'mark-cases' -and $alignmentCase.kernel_message -match 'only supported on Linux') {
                    $alignmentSkipped.Add(@{ name="$alignmentSuite/$($alignmentCase.name)"; reason=$alignmentCase.kernel_message })
                } else { $alignmentCase.passed = $false }
            }
            if (!$alignmentCase.passed) { $alignmentIssues.Add("Regression: $alignmentSuite/$($alignmentCase.name): $($alignmentCase.parser_error) $($alignmentCase.kernel_message)") }
            $alignmentLegacy.Add($alignmentCase)
        }
    }
    $alignmentHttp = Invoke-AlignmentProcess 'regression-http-input' $alignmentPwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'alignment/regressions/http-input-probe.ps1'),'-AuditDir',$alignmentRun) $alignmentRepo
    if ($alignmentHttp.ExitCode -ne 0) { $alignmentIssues.Add("HTTP subscription regression crashed: $($alignmentHttp.Stderr)") }
    else {
        $alignmentHttpCase = Get-Content -LiteralPath (Join-Path $alignmentRun 'http-input.results.json') -Raw | ConvertFrom-Json -AsHashtable
        $alignmentHttpCase.name = 'http-subscription'; $alignmentHttpCase.suite = 'http-input'
        $alignmentHttpCase.passed = $alignmentHttpCase.parser_exit -eq 0 -and $alignmentHttpCase.node_count -eq 1 -and $alignmentHttpCase.tls_enabled -and $alignmentHttpCase.correct_user_agent -and $alignmentHttpCase.kernel_exit -eq 0 -and !$alignmentHttpCase.parser_error
        if (!$alignmentHttpCase.passed) { $alignmentIssues.Add('HTTP subscription regression failed') }
        $alignmentLegacy.Add($alignmentHttpCase)
    }
    $alignmentReport.model_groups = $alignmentModelReport.coverage.Count
    $alignmentReport.covered_fields = @($alignmentModelReport.coverage.Values | ForEach-Object { $_ }).Count
    $alignmentReport.field_cases = $alignmentFields.Count
    $alignmentReport.field_cases_passed = @($alignmentFields | Where-Object passed).Count
    $alignmentReport.core_constructor_cases = @($alignmentFields | Where-Object runtime_checked).Count
    $alignmentReport.core_negative_cases = @($alignmentFields | Where-Object rejection).Count
    $alignmentReport.parser_rejected_cases = @($alignmentFields | Where-Object parser_rejected).Count
    $alignmentReport.checker_self_tests = @($alignmentFields | Where-Object detected_mismatch).Count
    $alignmentReport.core_marshal_fallbacks = @($alignmentFields | Where-Object core_marshal_error).Count
    $alignmentReport.regression_cases = $alignmentLegacy.Count
    $alignmentReport.regression_cases_passed = @($alignmentLegacy | Where-Object passed).Count
    $alignmentReport.schema_only_cases = $alignmentSkipped.Count
    $alignmentReport.coverage = $alignmentModelReport.coverage
    $alignmentReport.schema_only = @($alignmentSkipped)
    $alignmentReport.regressions = @($alignmentLegacy)
    if ($RequireAllRuntime -and $alignmentSkipped.Count -gt 0) { $alignmentIssues.Add("RequireAllRuntime: $($alignmentSkipped.Count) cases have not undergone core construction on this host") }
    if ((Get-AlignmentDigest (Get-AlignmentManifest $alignmentCore $alignmentCoreGlobs)) -ne $alignmentReport.core_source_sha256) { $alignmentIssues.Add('Core source changed during the run; results are stale') }
    if ((Get-AlignmentDigest (Get-AlignmentManifest $alignmentRepo $alignmentParserGlobs)) -ne $alignmentReport.parser_source_sha256) { $alignmentIssues.Add('Parser/checker source changed during the run; results are stale') }
} catch {
    $alignmentIssues.Add($_.Exception.Message)
} finally {
    $alignmentReport.finished_utc = [DateTime]::UtcNow.ToString('o')
    $alignmentReport.issues = @($alignmentIssues)
    $alignmentReport.status = if ($alignmentIssues.Count -gt 0) { 'failed' } elseif ($alignmentSkipped.Count -gt 0) { 'passed_with_runtime_limits' } else { 'passed' }
    $alignmentReportPath = Join-Path $alignmentRun 'report.json'
    $alignmentReport | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $alignmentReportPath
    Write-Host "Status: $($alignmentReport.status); field cases: $($alignmentReport.field_cases_passed)/$($alignmentReport.field_cases); regressions: $($alignmentReport.regression_cases_passed)/$($alignmentReport.regression_cases); runtime limits: $($alignmentSkipped.Count)"
    foreach ($alignmentIssue in $alignmentIssues) { Write-Host "FAIL: $alignmentIssue" }
    Write-Host "Report: $alignmentReportPath"
}
if ($alignmentIssues.Count -gt 0) { exit 1 }
exit 0
