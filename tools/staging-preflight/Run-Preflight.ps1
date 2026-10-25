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
$stage = 'prerequisites'
try {
    $stage = 'windows-platform'
    if ($env:OS -ne 'Windows_NT') { throw 'Unsupported platform' }
    # Prevent inherited Node debug/loader options from logging or executing extra code.
    $stage = 'runtime-options'
    if ($env:NODE_OPTIONS -or $env:NODE_DEBUG -or $env:NODE_DEBUG_NATIVE -or $env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0') { throw 'Unsafe Node options' }
    $stage = 'node-discovery'
    # ApplicationInfo.Path is the executable path on Windows PowerShell 5.1;
    # Source is not a reliable invocation path across PowerShell versions.
    $nodeCommand = Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $node = [string]$nodeCommand.Path
    if (-not [IO.File]::Exists($node)) { throw 'Node executable missing' }
    $stage = 'node-version'
    $version = & $node --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw 'Node.js 24 required' }
    $stage = 'integrity'
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.PSObject.Properties) {
        $file = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $entry.Name))
        $root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
        if (-not $file.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest' }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'Package mismatch' }
    }
    $stage = 'consent-and-input'
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
    $stage = 'child-start'
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $node
    $start.Arguments = '"' + (Join-Path $PSScriptRoot 'preflight.js') + '"'
    $start.WorkingDirectory = $PSScriptRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    # Child output contains only fixed check labels, booleans and sanitized errors.
    $script:child = [Diagnostics.Process]::Start($start)
    $stage = 'private-pipe'
    $script:inputBytes = [Text.Encoding]::UTF8.GetBytes($script:payload)
    $script:child.StandardInput.BaseStream.Write($script:inputBytes, 0, $script:inputBytes.Length)
    [Array]::Clear($script:inputBytes, 0, $script:inputBytes.Length)
    $script:inputBytes = $null
    # Close the raw stream: disposing its unused StreamWriter can append a BOM
    # on .NET Framework after the UTF-8 JSON has already been written.
    $script:child.StandardInput.BaseStream.Flush()
    $script:child.StandardInput.BaseStream.Close()
    $stage = 'child-completion'
    $script:payload = $null
    if (-not $script:child.WaitForExit(180000)) {
        $script:child.Kill()
        throw 'Preflight timeout'
    }
    $exitCode = $script:child.ExitCode
} catch {
    $command = [string]$_.TargetObject
    if ($command -notin @('Get-Content','ConvertFrom-Json','Get-FileHash','Join-Path','New-Object','Select-Object','Get-Command')) { $command = 'not-allowlisted' }
    Write-Host ('STOP: launcher stage=' + $stage + '; type=' + $_.Exception.GetType().Name + '; command=' + $command + '. No error details printed.')
    Write-Host 'Use Node.js 24. Keep package files together. Do not bypass company script policy or TLS verification.'
} finally {
    $script:payload = $null
    if ($script:inputBytes) { [Array]::Clear($script:inputBytes, 0, $script:inputBytes.Length) }
    if ($script:privateUrl) { $script:privateUrl.Dispose(); $script:privateUrl = $null }
    if ($script:child) { $script:child.Dispose() }
}
exit $exitCode
