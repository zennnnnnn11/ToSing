$taskResults = [System.Collections.Generic.List[object]]::new()
foreach ($taskCase in $taskCases) {
    if ($CaseFilter -and $taskCase.Name -ne $CaseFilter) { continue }
    $taskInputPath = Join-Path $AuditDir ($taskCase.Name + '.input.txt')
    Set-Content -LiteralPath $taskInputPath -Value $taskCase.InputText -Encoding utf8
    $taskParsed = Invoke-AuditProcess $taskDotnet @($taskParser, $taskInputPath)
    $taskNodes = @()
    $taskParseError = ''
    try { $taskNodes = @($taskParsed.Stdout | ConvertFrom-Json -AsHashtable) } catch { $taskParseError = $_.Exception.Message }
    $taskPreserved = $false
    try { $taskPreserved = [bool](& $taskCase.Preserves $taskNodes) } catch { $taskParseError += $_.Exception.Message }
    $taskCheck = if ($taskNodes.Count -gt 0) { Invoke-ConfigCheck $taskNodes $taskCase.Name } else { $null }
    $taskReference = $null
    if ($taskCase.ReferencePatch) {
        $taskReferenceNodes = @(& $taskCase.ReferencePatch $taskNodes)
        if ($taskReferenceNodes.Count -eq 1 -and $taskReferenceNodes[0] -is [array]) { $taskReferenceNodes = $taskReferenceNodes[0] }
        $taskReference = Invoke-ConfigCheck $taskReferenceNodes ($taskCase.Name + '.reference')
    }
    $taskResult = [ordered]@{
        name = $taskCase.Name
        parser_exit = $taskParsed.ExitCode
        node_count = $taskNodes.Count
        preserves_requested_semantics = $taskPreserved
        kernel_exit = if ($taskCheck) { $taskCheck.ExitCode } else { $null }
        kernel_message = if ($taskCheck) { ($taskCheck.Stderr + $taskCheck.Stdout).Trim() } else { '' }
        reference_kernel_exit = if ($taskReference) { $taskReference.ExitCode } else { $null }
        reference_message = if ($taskReference) { ($taskReference.Stderr + $taskReference.Stdout).Trim() } else { '' }
        parser_error = $taskParseError + $taskParsed.Stderr
    }
    $taskResults.Add($taskResult)
    Write-Output ($taskResult | ConvertTo-Json -Depth 5 -Compress)
}
$taskResultName = if ($CaseFilter) { $CaseFilter + '.results.json' } else { 'results.json' }
$taskResults | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $AuditDir $taskResultName) -Encoding utf8

