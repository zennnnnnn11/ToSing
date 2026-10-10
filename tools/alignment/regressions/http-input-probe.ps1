param([string]$AuditDir = $PSScriptRoot)
. (Join-Path $PSScriptRoot 'helpers.ps1') -AuditDir $AuditDir
$taskListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$taskListener.Start()
$taskPort = $taskListener.LocalEndpoint.Port
$taskAccepted = $taskListener.AcceptTcpClientAsync()
$taskStart = [Diagnostics.ProcessStartInfo]::new()
$taskStart.FileName = $taskDotnet
$taskStart.UseShellExecute = $false
$taskStart.CreateNoWindow = $true
$taskStart.RedirectStandardOutput = $true
$taskStart.RedirectStandardError = $true
$taskStart.ArgumentList.Add($taskParser)
$taskStart.ArgumentList.Add("http://127.0.0.1:$taskPort/subscription")
$taskProcess = [Diagnostics.Process]::new()
$taskProcess.StartInfo = $taskStart
try {
    [void]$taskProcess.Start()
    $taskStdout = $taskProcess.StandardOutput.ReadToEndAsync()
    $taskStderr = $taskProcess.StandardError.ReadToEndAsync()
    if (!$taskAccepted.Wait(10000)) { throw 'HTTP client did not connect' }
    $taskSocket = $taskAccepted.GetAwaiter().GetResult()
    $taskStream = $taskSocket.GetStream()
    $taskStream.ReadTimeout = 5000
    $taskReader = [IO.StreamReader]::new($taskStream, [Text.Encoding]::UTF8, $false, 1024, $true)
    $taskRequest = [Collections.Generic.List[string]]::new()
    while ($null -ne ($taskLine = $taskReader.ReadLine())) {
        if ($taskLine.Length -eq 0) { break }
        $taskRequest.Add($taskLine)
    }
    $taskPayload = [Text.Encoding]::UTF8.GetBytes(('vless://' + $taskUuid + '@127.0.0.1:443?security=tls#http-input'))
    $taskHeader = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($taskPayload.Length)`r`nConnection: close`r`n`r`n")
    $taskStream.Write($taskHeader)
    $taskStream.Write($taskPayload)
    $taskStream.Flush()
    $taskReader.Dispose()
    $taskSocket.Dispose()
    if (!$taskProcess.WaitForExit(10000)) { throw 'HTTP-input parser timed out' }
    $taskNodes = @($taskStdout.GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable)
    $taskCheck = Invoke-ConfigCheck $taskNodes 'http-input'
    $taskResult = [ordered]@{
        parser_exit = $taskProcess.ExitCode
        node_count = $taskNodes.Count
        tls_enabled = $taskNodes[0].tls.enabled
        correct_user_agent = @($taskRequest | Where-Object {$_ -ceq 'User-Agent: clash.meta'}).Count -eq 1
        kernel_exit = $taskCheck.ExitCode
        parser_error = $taskStderr.GetAwaiter().GetResult()
    }
    $taskResult | ConvertTo-Json | Tee-Object -FilePath (Join-Path $AuditDir 'http-input.results.json')
} finally {
    $taskListener.Stop()
    if ($taskProcess.Id -and !$taskProcess.HasExited) { $taskProcess.Kill($true) }
    $taskProcess.Dispose()
}
