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
        $install = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($install) {
            $amd64 = Join-Path $install "MSBuild\Current\Bin\amd64\MSBuild.exe"
            if (Test-Path $amd64) { return $amd64 }
        }
        $path = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($path) { return $path }
    }
    throw "MSBuild not found. Install Visual Studio 2022 with C++ workload."
}

function Complete-WdkHostTools {
    $pkgRoot = Join-Path $Root "packages"
    if (-not (Test-Path $pkgRoot)) { return }
    Get-ChildItem $pkgRoot -Directory -Filter "Microsoft.Windows.WDK.*" | ForEach-Object {
        $binRoot = Join-Path $_.FullName "c\bin"
        if (-not (Test-Path $binRoot)) { return }
        Get-ChildItem $binRoot -Directory | ForEach-Object {
            $verDir = $_.FullName
            $x86 = Join-Path $verDir "x86"
            $x64 = Join-Path $verDir "x64"
            if (-not (Test-Path $x64)) { return }
            New-Item -ItemType Directory -Force -Path $x86 | Out-Null
            Get-ChildItem $x64 -File | Where-Object { $_.Extension -eq ".exe" -or $_.Extension -eq ".dll" } | ForEach-Object {
                $dest = Join-Path $x86 $_.Name
                if (-not (Test-Path $dest)) {
                    Copy-Item $_.FullName -Destination $dest -Force
                    Write-Host "WDK shim: $($_.Name) -> x86"
                }
            }
        }
    }
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
    Complete-WdkHostTools
    & $msbuild $drvProj /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /m /v:m
    if ($LASTEXITCODE -ne 0) { throw "Driver build failed" }
} else {
    Write-Host "WDK toolset not found. Skipping kernel driver."
    Write-Host "Install Windows Driver Kit and the VS Driver Kit component, then re-run."
}

Write-Host "Artifacts:"
Get-ChildItem $outDir -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName)" }
