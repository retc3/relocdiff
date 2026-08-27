param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [string]$OutputDirectory = "winget"
)

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerPath).Hash
$url = "https://github.com/$Repository/releases/download/v$Version/relocdiff-x86_64-pc-windows-msvc.exe"
$directory = Join-Path $OutputDirectory "retc3.relocdiff"
New-Item -ItemType Directory -Force -Path $directory | Out-Null

@"
PackageIdentifier: retc3.relocdiff
PackageVersion: $Version
PackageLocale: en-US
Publisher: retc3
PublisherUrl: https://github.com/retc3
PackageName: relocdiff
PackageUrl: https://github.com/$Repository
License: MIT OR Apache-2.0
ShortDescription: Find matching x86-64 functions across PE32+ builds.
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"@ | Set-Content -Encoding utf8 (Join-Path $directory "retc3.relocdiff.locale.en-US.yaml")

@"
PackageIdentifier: retc3.relocdiff
PackageVersion: $Version
Installers:
  - Architecture: x64
    InstallerType: portable
    InstallerUrl: $url
    InstallerSha256: $hash
ManifestType: installer
ManifestVersion: 1.6.0
"@ | Set-Content -Encoding utf8 (Join-Path $directory "retc3.relocdiff.installer.yaml")

@"
PackageIdentifier: retc3.relocdiff
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@ | Set-Content -Encoding utf8 (Join-Path $directory "retc3.relocdiff.yaml")

Write-Host "Wrote $directory"
