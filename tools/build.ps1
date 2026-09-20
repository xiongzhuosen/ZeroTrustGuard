param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($path) { return $path }
    }
    throw "MSBuild not found. Install Visual Studio 2022 with C++ workload."
}

function Test-Wdk {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $false }
    $install = & $vswhere -latest -property installationPath
    if (-not $install) { return $false }
    $wdkProps = Join-Path $install "MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.props"
    $wdkProps2 = Join-Path $install "MSBuild\Microsoft\VC\v160\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.props"
    return (Test-Path $wdkProps) -or (Test-Path $wdkProps2)
}

$msbuild = Find-MSBuild
Write-Host "MSBuild: $msbuild"
Write-Host "Root:    $Root"

$appProj = Join-Path $Root "src\app\ZeroTrustGuard.vcxproj"
$drvProj = Join-Path $Root "src\drv\ZeroTrustGuardDrv.vcxproj"
$nuget = Get-Command nuget -ErrorAction SilentlyContinue
if ($nuget) {
    Write-Host "Restoring NuGet packages..."
    & nuget restore (Join-Path $Root "ZeroTrustGuard.sln") -NonInteractive
}

Write-Host "Building user-mode application..."
& $msbuild $appProj /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /m /v:m
if ($LASTEXITCODE -ne 0) { throw "User-mode build failed" }

$outDir = Join-Path $Root "out\$Platform\$Configuration"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item (Join-Path $Root "src\drv\ZeroTrustGuard.inf") -Destination $outDir -Force
Copy-Item (Join-Path $Root "res\32.ico") -Destination $outDir -Force

if (Test-Wdk) {
    Write-Host "WDK toolset found. Building kernel driver..."
    & $msbuild $drvProj /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /m /v:m
    if ($LASTEXITCODE -ne 0) { throw "Driver build failed" }
} else {
    Write-Host "WDK toolset not found. Skipping kernel driver."
    Write-Host "Install Windows Driver Kit and the VS Driver Kit component, then re-run."
}

Write-Host "Artifacts:"
Get-ChildItem $outDir -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName)" }
