[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$GhidraRoot,
    [string]$ZipPath,
    [switch]$Build,
    [switch]$StopGhidra
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[deploy] $Message"
}

function Get-JarInfo {
    param([string]$JarPath)
    if (Test-Path $JarPath) {
        return Get-Item $JarPath | Select-Object FullName, Length, LastWriteTime
    }
    return $null
}

function Remove-DirectoryIfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        if ($PSCmdlet.ShouldProcess($Path, "Remove directory recursively")) {
            Remove-Item -Path $Path -Recurse -Force
        }
    }
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$resolvedGhidraRoot = (Resolve-Path $GhidraRoot).Path
$installName = Split-Path -Leaf $resolvedGhidraRoot

if (-not $ZipPath) {
    $ZipPath = Join-Path $scriptRoot "target\GhidraMCP-1.0-SNAPSHOT.zip"
}

$installExtRoot = Join-Path $resolvedGhidraRoot "Extensions\Ghidra"
$installPluginDir = Join-Path $installExtRoot "GhidraMCP"
$userExtRoot = Join-Path $env:APPDATA ("ghidra\{0}\Extensions" -f $installName)
$userPluginDir = Join-Path $userExtRoot "GhidraMCP"

if ($Build) {
    Write-Step "Building extension zip with Maven"
    if ($PSCmdlet.ShouldProcess($scriptRoot, "Run mvn clean package assembly:single")) {
        Push-Location $scriptRoot
        try {
            mvn clean package assembly:single
        }
        finally {
            Pop-Location
        }
    }
}

if (-not (Test-Path $ZipPath)) {
    throw "Zip not found: $ZipPath"
}

$runningGhidra = Get-Process javaw -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "CodeBrowser*" }
if ($runningGhidra) {
    if ($StopGhidra) {
        Write-Step "Stopping running Ghidra CodeBrowser processes"
        foreach ($proc in $runningGhidra) {
            if ($PSCmdlet.ShouldProcess("PID $($proc.Id)", "Stop-Process")) {
                Stop-Process -Id $proc.Id -Force
            }
        }
    }
    else {
        $ids = ($runningGhidra | Select-Object -ExpandProperty Id) -join ", "
        throw "Ghidra is running (PID(s): $ids). Close Ghidra or re-run with -StopGhidra."
    }
}

Write-Step "Removing install-level extension directory"
Remove-DirectoryIfExists -Path $installPluginDir

Write-Step "Removing user-level extension directory (prevents stale override)"
Remove-DirectoryIfExists -Path $userPluginDir

if (-not (Test-Path $installExtRoot)) {
    throw "Install extension root missing: $installExtRoot"
}

Write-Step "Expanding zip to install-level extension root"
if ($PSCmdlet.ShouldProcess($installExtRoot, "Expand-Archive $ZipPath")) {
    Expand-Archive -Path $ZipPath -DestinationPath $installExtRoot -Force
}

Write-Step "Copying deployed extension to user-level extension root"
if ($PSCmdlet.ShouldProcess($userExtRoot, "Copy GhidraMCP directory")) {
    New-Item -Path $userExtRoot -ItemType Directory -Force | Out-Null
    Copy-Item -Path $installPluginDir -Destination $userPluginDir -Recurse -Force
}

$installJar = Join-Path $installPluginDir "lib\GhidraMCP.jar"
$userJar = Join-Path $userPluginDir "lib\GhidraMCP.jar"
$installInfo = Get-JarInfo -JarPath $installJar
$userInfo = Get-JarInfo -JarPath $userJar

if (-not $installInfo) {
    throw "Install-level jar missing after deploy: $installJar"
}
if (-not $userInfo) {
    throw "User-level jar missing after deploy: $userJar"
}

Write-Step "Deployment complete"
Write-Host ""
Write-Host "Install-level jar:"
$installInfo | Format-List
Write-Host "User-level jar:"
$userInfo | Format-List

if ($installInfo.Length -ne $userInfo.Length) {
    throw "Jar size mismatch between install/user locations; deploy is inconsistent."
}

Write-Step "Jar sizes match. Safe to start Ghidra."
