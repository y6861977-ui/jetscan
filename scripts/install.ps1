# jetscan installer for Windows: downloads a GitHub release, checks its SHA-256
# against the release's SHA256SUMS, installs jetscan.exe to %LOCALAPPDATA%\jetscan\bin.
# No administrator rights needed.
#   irm https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.ps1 | iex
# Env: JETSCAN_REPO (owner/jetscan), JETSCAN_VERSION (v0.1.0; default: latest release).
#
# ASCII only and NO BOM, unlike the other .ps1 files: `irm | iex` keeps a BOM and
# then fails on the first line; pure ASCII reads the same in PowerShell 5.1 and 7.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# throw, not exit: under `irm | iex`, exit would close the user's PowerShell window.
function Fail([string]$msg) {
    throw "jetscan install: $msg"
}

$repo = if ($env:JETSCAN_REPO) { $env:JETSCAN_REPO } else { 'y6861977-ui/jetscan' }
if ($repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') { Fail 'JETSCAN_REPO must look like owner/jetscan' }

$version = if ($env:JETSCAN_VERSION) { $env:JETSCAN_VERSION } else { 'latest' }
if ($version -eq 'latest') {
    $version = (Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$repo/releases/latest").tag_name
}
if ($version -notmatch '^v[0-9][A-Za-z0-9._-]*$') { Fail "bad version '$version'" }

# x86_64 build only; Windows on ARM64 runs it through x64 emulation.
$target = 'x86_64-pc-windows-msvc'
$name = "jetscan-$version-$target"
$base = "https://github.com/$repo/releases/download/$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("jetscan-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "jetscan install: downloading $name"
    $zip = Join-Path $tmp "$name.zip"
    $sums = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name.zip" -OutFile $zip
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

    $expected = $null
    foreach ($line in Get-Content $sums) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq "$name.zip") { $expected = $parts[0].ToLower() }
    }
    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { Fail 'checksum mismatch - nothing was installed' }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $dest = Join-Path $env:LOCALAPPDATA 'jetscan\bin'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Force (Join-Path $tmp "$name\jetscan.exe") (Join-Path $dest 'jetscan.exe')

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $dest)) {
        $newPath = if ($userPath) { "$userPath;$dest" } else { $dest }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "jetscan install: added $dest to your user PATH (open a new terminal)"
    }
    $installed = & (Join-Path $dest 'jetscan.exe') --version
    Write-Host "jetscan install: $installed -> $dest\jetscan.exe" -ForegroundColor Green
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
