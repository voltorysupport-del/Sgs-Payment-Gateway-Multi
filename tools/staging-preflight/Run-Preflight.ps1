# Windows PowerShell 5.1 / PowerShell 7. No execution-policy or certificate bypass.
[CmdletBinding()]
param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$script:privateUrl = $null
$script:payload = $null
$script:child = $null
$script:inputBytes = $null
$exitCode = 2
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Unsupported platform' }
    # Prevent inherited Node debug/loader options from logging or executing extra code.
    if ($env:NODE_OPTIONS -or $env:NODE_DEBUG -or $env:NODE_DEBUG_NATIVE -or $env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0') { throw 'Unsafe Node options' }
    $node = (Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
    $version = & $node --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw 'Node.js 24 required' }
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.PSObject.Properties) {
        $file = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $entry.Name))
        $root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
        if (-not $file.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest' }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'Package mismatch' }
    }
    if ($ValidateOnly) {
        $script:payload = @{mode='self-test'; sentinel=([string][char]0x20ac + [string][char]0x03bb)} | ConvertTo-Json -Compress
    } else {
        Write-Host 'READ-ONLY check only. No operator or key will be created.'
        $approval = Read-Host 'Type READONLY to authorize the staging connection, or Enter to stop'
        if ($approval -cne 'READONLY') { throw 'Approval missing' }
        $hostName = Read-Host 'Independently verified FULL EXTERNAL staging hostname (not a URL)'
        $login = Read-Host 'Independently verified authenticated PostgreSQL login'
        $script:privateUrl = Read-Host 'Private EXTERNAL staging URL (hidden; never send it to chat)' -AsSecureString
        $script:payload = @{
            approveReadOnly=$true
            expectedHost=$hostName.Trim()
            expectedLogin=$login.Trim()
            databaseUrl=[Net.NetworkCredential]::new('', $script:privateUrl).Password
        } | ConvertTo-Json -Compress
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $node
    $start.Arguments = '"' + (Join-Path $PSScriptRoot 'preflight.js') + '"'
    $start.WorkingDirectory = $PSScriptRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    # Child output contains only fixed check labels, booleans and sanitized errors.
    $script:child = [Diagnostics.Process]::Start($start)
    $script:inputBytes = [Text.Encoding]::UTF8.GetBytes($script:payload)
    $script:child.StandardInput.BaseStream.Write($script:inputBytes, 0, $script:inputBytes.Length)
    [Array]::Clear($script:inputBytes, 0, $script:inputBytes.Length)
    $script:inputBytes = $null
    $script:child.StandardInput.Close()
    $script:payload = $null
    if (-not $script:child.WaitForExit(180000)) {
        $script:child.Kill()
        throw 'Preflight timeout'
    }
    $exitCode = $script:child.ExitCode
} catch {
    Write-Host 'STOP: prerequisite, package verification, consent or launcher failure. No error details printed.'
    Write-Host 'Use Node.js 24. Keep package files together. Do not bypass company script policy or TLS verification.'
} finally {
    $script:payload = $null
    if ($script:inputBytes) { [Array]::Clear($script:inputBytes, 0, $script:inputBytes.Length) }
    if ($script:privateUrl) { $script:privateUrl.Dispose(); $script:privateUrl = $null }
    if ($script:child) { $script:child.Dispose() }
}
exit $exitCode
