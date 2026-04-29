param(
  [switch]$SkipAssets,
  [switch]$SkipBuild,
  [string]$BrandText = "SecretSafe",
  [string]$SourcePng = "icons/icon.png",
  [string]$OutputDir = "dist/installers"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcTauriDir = Split-Path -Parent $scriptDir
$repoRoot = Split-Path -Parent $srcTauriDir

$configPath = Join-Path $srcTauriDir "tauri.conf.json"
if (-not (Test-Path $configPath)) {
  throw "No se encontro tauri.conf.json en $srcTauriDir."
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json
$productName = $config.productName
$version = $config.version
$safeName = ($productName -replace "[^A-Za-z0-9]+", "-").Trim("-")

if (-not $SkipAssets) {
  Write-Host "Regenerando assets de instalador..."
  $assetsScript = Join-Path $scriptDir "generate-installer-assets.ps1"
  $resolvedSourcePng = if ([System.IO.Path]::IsPathRooted($SourcePng)) { $SourcePng } else { Join-Path $srcTauriDir $SourcePng }
  & powershell -ExecutionPolicy Bypass -File $assetsScript -SourcePng $resolvedSourcePng -BrandText $BrandText
  if ($LASTEXITCODE -ne 0) {
    throw "Fallo la generacion de assets del instalador."
  }
}

if (-not $SkipBuild) {
  Write-Host "Compilando bundles NSIS/MSI..."
  Push-Location $repoRoot
  try {
    & cargo tauri build --bundles nsis,msi
  } finally {
    Pop-Location
  }
}

$bundleDir = Join-Path $repoRoot "target/release/bundle"
if (-not (Test-Path $bundleDir)) {
  throw "No existe $bundleDir. Asegura que el build se haya ejecutado correctamente."
}

if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
  $OutputDir = Join-Path $repoRoot $OutputDir
}

if (-not (Test-Path $OutputDir)) {
  New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

$nsisExe = Get-ChildItem "$bundleDir/nsis" -Filter "*.exe" -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$msiPkg = Get-ChildItem "$bundleDir/msi" -Filter "*.msi" -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($null -eq $nsisExe -and $null -eq $msiPkg) {
  throw "No se encontraron artefactos .exe/.msi en $bundleDir."
}

if ($null -ne $nsisExe) {
  $nsisOut = Join-Path $OutputDir "$safeName-setup.exe"
  Copy-Item $nsisExe.FullName $nsisOut -Force
  Write-Host "NSIS listo: $nsisOut"
}

if ($null -ne $msiPkg) {
  $msiOut = Join-Path $OutputDir "$safeName-corporate.msi"
  Copy-Item $msiPkg.FullName $msiOut -Force
  Write-Host "MSI corporativo listo: $msiOut"
}

Write-Host "Release de instaladores completado."
