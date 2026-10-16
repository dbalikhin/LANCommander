param([switch]$Restore)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repoName = ($env:GITHUB_REPOSITORY -split '/')[1]
$solutions = @{ btcpayserver='btcpayserver.sln'; LANCommander='LANCommander.slnx'; OrchardCore='OrchardCore.slnx'; Remotely='Benchmark.slnx'; 'the-most-vulnerable-dotnet-app'='DotnetSecurityFailures.slnx' }
$solution = $solutions[$repoName]
New-Item -ItemType Directory -Force benchmark-evidence | Out-Null
if ($repoName -eq 'Remotely') {
    $extra = @('Desktop.Core/Desktop.Core.csproj', 'Tests/Desktop.Win.Tests/Desktop.Win.Tests.csproj')
    $paths = @(git ls-files '*.csproj' | Where-Object { $_ -notin $extra })
    ('<Solution>' + (($paths | ForEach-Object { '<Project Path="' + $_ + '" />' }) -join '') + '</Solution>') | Set-Content $solution
    @{ included=$paths; extra_projects=$extra; excluded_non_csharp=@('docker-compose/docker-compose.dcproj') } | ConvertTo-Json -Depth 5 | Set-Content benchmark-evidence/build-scope.json
}
if ($Restore) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    dotnet restore $solution 2>&1 | Tee-Object benchmark-evidence/restore.log
    $restoreExit = $LASTEXITCODE
    if ($restoreExit -eq 0 -and $repoName -eq 'LANCommander' -and $env:PROFILE -ne 'dotnetarium-max') {
        npm.cmd ci --prefix LANCommander.UI
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm.cmd ci --prefix LANCommander.Server
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    @{restore_seconds=$timer.Elapsed.TotalSeconds; exit_code=$restoreExit} | ConvertTo-Json | Set-Content benchmark-evidence/restore-timing.json
    exit $restoreExit
}
$timer = [Diagnostics.Stopwatch]::StartNew()
$common = @('--no-restore', '--no-incremental', '--disable-build-servers', '--configuration', 'Release', '-m:2', '-p:UseSharedCompilation=false', '-p:LibraryRestore=false', '-p:TypeScriptCompileBlocked=true', '-v:minimal')
dotnet build $solution @common 2>&1 | Tee-Object benchmark-evidence/build.log
$buildExit = $LASTEXITCODE
$failed = @()
if ($buildExit -ne 0) { $failed += $solution }
if ($repoName -eq 'Remotely' -and $buildExit -eq 0) {
    $extraCommon = @($common | Where-Object { $_ -ne '--no-restore' })
    foreach ($entry in @(@{path='Desktop.Core/Desktop.Core.csproj';tfm='net8.0'}, @{path='Tests/Desktop.Win.Tests/Desktop.Win.Tests.csproj';tfm='net8.0-windows'})) {
        dotnet build $entry.path @extraCommon "-p:TargetFramework=$($entry.tfm)" "-p:TargetFrameworks=$($entry.tfm)" 2>&1 | Tee-Object -Append benchmark-evidence/build.log
        if ($LASTEXITCODE -ne 0) { $failed += $entry.path; $buildExit=1 }
    }
}
@{build_with_extraction_seconds=$timer.Elapsed.TotalSeconds; exit_code=$buildExit; failed_projects=$failed} | ConvertTo-Json | Set-Content benchmark-evidence/build-timing.json
exit $buildExit
