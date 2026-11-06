#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $RepoRoot,
    [string] $CandidateSourcePath,
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $BaseSha = '5cc8f3f50aa57ed694dfda928e4467593e073656',
    [switch] $BaselineOnly,
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$runId = [Guid]::NewGuid().ToString('N')
$work = $null
$workCreated = $false
$outputCreated = $false
$userCreated = $false
$secretsCreated = $false
$summary = [ordered]@{
    schemaVersion = 1
    mode = $(if ($BaselineOnly) { 'baseline-preflight' } else { 'comparison' })
    baseSha = $BaseSha
    os = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    requestedRunner = 'windows-2022'
    limitation = 'Windows Server 2022 is not the originally reported Windows Server 2019 environment.'
    status = 'infrastructure-failure'
    phase = 'prerequisites'
    exitCode = 3
    sourceHashes = [ordered]@{}
    builds = @()
    error = $null
    cleanup = [ordered]@{ userRemoved = $false; temporaryWorkspaceRemoved = $false; environmentCleared = $false; errors = @() }
}

function Get-SafeError($ErrorRecord) {
    # Deliberately exclude Message, stack, command text, paths and account names.
    return [ordered]@{
        type = $ErrorRecord.Exception.GetType().FullName
        hresult = ('0x{0:X8}' -f $ErrorRecord.Exception.HResult)
        scriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        innerType = $ErrorRecord.Exception.InnerException?.GetType().FullName
    }
}

function Assert-OutsideRepo([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $repo = $script:RepoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($full.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Builds and outputs must be outside RepoRoot.'
    }
}

function Invoke-Child {
    param([string] $Executable, [string[]] $Arguments, [string] $Directory,
          [int] $TimeoutSeconds = 240, [string] $RawOutputFile)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $Directory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Suppress SDK first-run certificate/global tool-path setup and keep CLI state private.
    $start.Environment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'
    $start.Environment['DOTNET_ADD_GLOBAL_TOOLS_TO_PATH'] = 'false'
    $start.Environment['DOTNET_NOLOGO'] = 'true'
    $start.Environment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
    $start.Environment['DOTNET_CLI_HOME'] = Join-Path $script:work 'dotnet-home'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $file = $null
    $started = $false
    try {
        if (-not $process.Start()) { throw 'Child process did not start.' }
        $started = $true
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($RawOutputFile) {
            $file = [IO.File]::Create($RawOutputFile)
            $stdout = $process.StandardOutput.BaseStream.CopyToAsync($file)
        } else {
            $stdout = $process.StandardOutput.ReadToEndAsync()
        }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) { throw 'Child process could not be reaped after termination; runner must be discarded.' }
            throw 'Child process deadline exceeded; process tree terminated and reaped.'
        }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) {
            throw 'Child output drain deadline exceeded.'
        }
        $text = if ($RawOutputFile) { $stdout.GetAwaiter().GetResult() | Out-Null; $null } else { $stdout.GetAwaiter().GetResult() }
        $stderr.GetAwaiter().GetResult() | Out-Null
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text }
    } finally {
        # No detached builds/tests. A failure anywhere still terminates and reaps the child.
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) { throw 'Child process cleanup failed; runner must be discarded.' }
        }
        if ($file) { $file.Dispose() }
        $process.Dispose()
    }
}

function Set-PrivateDirectory([string] $Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $runner = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        foreach ($sid in @($runner.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
                            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    } finally { $runner.Dispose() }
}

try {
    if (-not $IsWindows -or -not [Environment]::Is64BitProcess) { throw 'Requires 64-bit PowerShell on Windows.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires an elevated disposable runner.' }
    } finally { $identity.Dispose() }

    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
    foreach ($name in @('GARNET2349_USER', 'GARNET2349_PASSWORD', 'GARNET2349_PFX_PASSWORD', 'GARNET2349_SID')) {
        if ([Environment]::GetEnvironmentVariable($name, 'Process')) { throw 'Reserved harness environment is already populated.' }
    }
    if (-not $BaselineOnly) {
        if (-not $CandidateSourcePath) { throw 'CandidateSourcePath is required unless BaselineOnly is set.' }
        $CandidateSourcePath = (Resolve-Path -LiteralPath $CandidateSourcePath).Path
    }
    $dotnet = (@(Get-Command dotnet -CommandType Application)[0]).Source
    $git = (@(Get-Command git -CommandType Application)[0]).Source
    $tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $work = Join-Path $tempRoot "garnet2349-work-$runId"
    Assert-OutsideRepo $work
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path $tempRoot "garnet2349-results-$runId" }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    Assert-OutsideRepo $OutputDirectory
    # Fresh output prevents stale JSON from being mistaken for this run's results.
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory must not already exist.' }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $outputCreated = $true
    New-Item -ItemType Directory -Path $work | Out-Null
    $workCreated = $true
    Set-PrivateDirectory $work
    $sdk = Invoke-Child $dotnet @('--version') $work -TimeoutSeconds 30
    if ($sdk.ExitCode -ne 0 -or $sdk.Output.Trim() -notmatch '^10\.0\.') { throw 'Select an installed .NET 10 SDK before running.' }
    $summary['dotnetSdk'] = $sdk.Output.Trim()

    # Both builds use identical harness inputs. No repository build props, targets, packages,
    # global.json or NuGet settings are inherited. No external packages or network restore.
    $labels = if ($BaselineOnly) { @('baseline') } else { @('baseline', 'candidate') }
    foreach ($label in $labels) {
        $summary.phase = "$label-build"
        $buildDir = Join-Path $work $label
        New-Item -ItemType Directory -Path $buildDir | Out-Null
        foreach ($asset in @('Validation.csproj', 'Program.cs', 'NuGet.Config')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $asset) -Destination (Join-Path $buildDir $asset)
        }
        $source = Join-Path $buildDir 'CertificateUtils.cs'
        if ($label -eq 'baseline') {
            # Binary stdout copy preserves exact git blob bytes (including any BOM/line endings).
            $export = Invoke-Child $git @('-C', $RepoRoot, 'show', "${BaseSha}:libs/server/TLS/CertificateUtils.cs") $work -RawOutputFile $source
            if ($export.ExitCode -ne 0) { throw 'git show failed. The requested base object must be available locally.' }
        } else {
            Copy-Item -LiteralPath $CandidateSourcePath -Destination $source
        }
        $summary.sourceHashes[$label] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $build = Invoke-Child $dotnet @('build', 'Validation.csproj', '--configuration', 'Release', '--nologo',
            '--disable-build-servers', '-p:ImportDirectoryBuildProps=false', '-p:ImportDirectoryBuildTargets=false',
            '-p:NuGetAudit=false', '-p:RestoreConfigFile=NuGet.Config') $buildDir
        if ($build.ExitCode -ne 0) { throw 'Standalone .NET 10 build failed.' }
    }
    $summary['programSha256'] = (Get-FileHash -LiteralPath (Join-Path $work 'baseline/Program.cs') -Algorithm SHA256).Hash
    $summary['projectSha256'] = (Get-FileHash -LiteralPath (Join-Path $work 'baseline/Validation.csproj') -Algorithm SHA256).Hash

    # Synthetic values live only in process memory/environment; no command-line arguments,
    # GITHUB_ENV/GITHUB_OUTPUT, transcripts, credentials files, or persisted secrets.
    $summary.phase = 'temporary-account'
    $secretsCreated = $true
    $env:GARNET2349_USER = 'g2349_' + $runId.Substring(0, 12)
    $env:GARNET2349_PASSWORD = 'Aa9!' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $env:GARNET2349_PFX_PASSWORD = 'Pfx9!' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    if ($env:GITHUB_ACTIONS -eq 'true') {
        # GitHub's masking protocol consumes these values and redacts subsequent occurrences.
        Write-Output "::add-mask::$env:GARNET2349_USER"
        Write-Output "::add-mask::$env:GARNET2349_PASSWORD"
        Write-Output "::add-mask::$env:GARNET2349_PFX_PASSWORD"
    }
    $securePassword = ConvertTo-SecureString $env:GARNET2349_PASSWORD -AsPlainText -Force
    try {
        $account = New-LocalUser -Name $env:GARNET2349_USER -Password $securePassword -Description 'Disposable Garnet TLS validation' -AccountNeverExpires
        $userCreated = $true
        $env:GARNET2349_SID = $account.SID.Value
        $summary['temporarySid'] = $env:GARNET2349_SID
        # Only ordinary Users membership; no Administrators membership or logon-policy edit.
        $usersGroupSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        if (-not (Get-LocalGroupMember -SID $usersGroupSid | Where-Object { $_.SID.Value -eq $account.SID.Value })) {
            Add-LocalGroupMember -SID $usersGroupSid -Member $account
        }
    } finally { $securePassword.Dispose(); $securePassword = $null }

    $summary.phase = 'fixtures'
    $fixtures = Join-Path $work 'fixtures'
    $baselineDll = Join-Path $work 'baseline/bin/Release/net10.0/Validation.dll'
    $generate = Invoke-Child $dotnet @($baselineDll, 'generate', $fixtures) $work -TimeoutSeconds 60
    if ($generate.ExitCode -ne 0) { throw 'Fixture generation failed.' }

    $fixtureSid = [Security.Principal.SecurityIdentifier]::new($env:GARNET2349_SID)
    $acl = Get-Acl -LiteralPath $fixtures
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($fixtureSid, 'ReadAndExecute', 'Allow'))
    Set-Acl -LiteralPath $fixtures -AclObject $acl
    foreach ($file in Get-ChildItem -LiteralPath $fixtures -File) {
        $acl = Get-Acl -LiteralPath $file.FullName
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($fixtureSid, 'Read', 'Allow'))
        Set-Acl -LiteralPath $file.FullName -AclObject $acl
    }

    $caseNames = @('encrypted-pfx', 'separate-pem', 'combined-pem', 'pem-renamed-pfx',
        'missing-file', 'wrong-password', 'malformed-pfx', 'mismatched-pem-key')
    foreach ($label in $labels) {
        $summary.phase = "$label-tests"
        $buildDir = Join-Path $work $label
        $source = Join-Path $buildDir 'CertificateUtils.cs'
        $dll = Join-Path $buildDir 'bin/Release/net10.0/Validation.dll'
        $runs = @()
        foreach ($context in @('normal', 'profileless')) {
            foreach ($caseName in $caseNames) {
                # One fresh process per case prevents SslStream credential-cache reuse across
                # identities or formats. Fixtures and compiled source are identical across runs.
                $report = Join-Path $work "$label-$context-$caseName.json"
                $run = Invoke-Child $dotnet @($dll, 'run', $label, $context, $caseName, $source, $fixtures, $report) $work -TimeoutSeconds 60
                if (-not (Test-Path -LiteralPath $report)) { throw 'Harness exited without a summary; no validation claim is possible.' }
                $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
                if ($run.ExitCode -ne $result.exitCode -or $result.sourceSha256 -ne $summary.sourceHashes[$label] -or
                    $result.programSha256 -ne $summary.programSha256 -or $result.build -ne $label -or
                    $result.identity -ne $context -or $result.case -ne $caseName) { throw 'Summary/process/hash mismatch.' }
                $runs += $result
                # Preserve completed, safe results even if a later process fails/times out.
                ConvertTo-Json -InputObject $runs -Depth 20 | Set-Content -LiteralPath (Join-Path $OutputDirectory "$label.json") -Encoding utf8NoBOM
                Write-Output "$label / $context / $caseName : $($result.status)"
            }
        }
        $runCodes = @($runs | ForEach-Object { $_.exitCode })
        $code = if ($runCodes -contains 3) { 3 } elseif ($runCodes -contains 1) { 1 } elseif ($runCodes -contains 2) { 2 } else { 0 }
        $summary.builds += [ordered]@{ build = $label; exitCode = $code; caseCount = $runs.Count; sourceSha256 = $summary.sourceHashes[$label] }
    }
    $codes = @($summary.builds | ForEach-Object { $_.exitCode })
    if ($codes -contains 3) {
        $summary.status = 'infrastructure-failure'; $summary.exitCode = 3
    } elseif ($codes -contains 1) {
        $summary.status = 'validation-failed'; $summary.exitCode = 1
    } elseif ($codes -contains 2) {
        $summary.status = 'inconclusive-baseline-not-reproduced'; $summary.exitCode = 2
    } else {
        $summary.status = if ($BaselineOnly) { 'baseline-reproduced-candidate-not-tested' } else { 'validated-on-this-runner' }
        $summary.exitCode = 0
    }
    $summary.phase = 'finished-tests'
} catch {
    $summary.error = Get-SafeError $_
    $summary.status = 'infrastructure-failure'
    $summary.exitCode = 3
} finally {
    if ($userCreated) {
        try {
            Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($env:GARNET2349_SID))
            if (Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($env:GARNET2349_SID)) -ErrorAction SilentlyContinue) {
                throw 'Temporary account still exists.'
            }
            $summary.cleanup.userRemoved = $true
        } catch { $summary.cleanup.errors += Get-SafeError $_ }
    } else { $summary.cleanup.userRemoved = $true }
    if ($workCreated -and (Test-Path -LiteralPath $work)) {
        try {
            Remove-Item -LiteralPath $work -Recurse -Force
            if (Test-Path -LiteralPath $work) { throw 'Temporary workspace still exists.' }
            $summary.cleanup.temporaryWorkspaceRemoved = $true
        } catch { $summary.cleanup.errors += Get-SafeError $_ }
    } else { $summary.cleanup.temporaryWorkspaceRemoved = $true }
    if ($secretsCreated) {
        foreach ($name in @('GARNET2349_USER', 'GARNET2349_PASSWORD', 'GARNET2349_PFX_PASSWORD', 'GARNET2349_SID')) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    $account = $null
    $summary.cleanup.environmentCleared = $true
    if ($summary.cleanup.errors.Count -gt 0) { $summary.status = 'cleanup-failed'; $summary.exitCode = 3 }
}

if ($outputCreated) {
    $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding utf8NoBOM
}
Write-Output ($summary | ConvertTo-Json -Depth 12)
exit $summary.exitCode
