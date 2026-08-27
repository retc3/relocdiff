param([switch]$SkipBuild)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $repo "target\e2e"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Put([byte[]]$buffer, [int]$offset, [byte[]]$value) {
    [Buffer]::BlockCopy($value, 0, $buffer, $offset, $value.Length)
}

function Put-U16([byte[]]$buffer, [int]$offset, [uint16]$value) {
    Put $buffer $offset ([BitConverter]::GetBytes($value))
}

function Put-U32([byte[]]$buffer, [int]$offset, [uint32]$value) {
    Put $buffer $offset ([BitConverter]::GetBytes($value))
}

function Put-U64([byte[]]$buffer, [int]$offset, [uint64]$value) {
    Put $buffer $offset ([BitConverter]::GetBytes($value))
}

function New-Code([uint32]$rip, [uint32]$call, [byte]$constant) {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($value in [byte[]]@(0x48, 0x8b, 0x05)) { [void]$bytes.Add($value) }
    foreach ($value in [BitConverter]::GetBytes($rip)) { [void]$bytes.Add($value) }
    [void]$bytes.Add(0xe8)
    foreach ($value in [BitConverter]::GetBytes($call)) { [void]$bytes.Add($value) }
    foreach ($value in [byte[]]@(0x83, 0xf8, $constant, 0x75, 0x00, 0xc3)) { [void]$bytes.Add($value) }
    $bytes.ToArray()
}

function New-Second-Code([byte]$constant) {
    [byte[]]@(0x48, 0xb8, 0x20, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xb8, $constant, 0x00, 0x00, 0x00, 0xc3)
}

function New-Section([byte[]]$buffer, [int]$offset, [string]$name, [uint32]$rva, [uint32]$size, [uint32]$raw, [uint32]$characteristics) {
    Put $buffer $offset ([Text.Encoding]::ASCII.GetBytes($name))
    Put-U32 $buffer ($offset + 8) $size
    Put-U32 $buffer ($offset + 12) $rva
    Put-U32 $buffer ($offset + 16) $size
    Put-U32 $buffer ($offset + 20) $raw
    Put-U32 $buffer ($offset + 36) $characteristics
}

function New-Pe([byte[]]$first, [byte[]]$second) {
    $buffer = [byte[]]::new(0x800)
    Put $buffer 0 ([Text.Encoding]::ASCII.GetBytes("MZ"))
    Put-U32 $buffer 0x3c 0x80
    Put $buffer 0x80 ([byte[]]@(0x50, 0x45, 0x00, 0x00))
    $coff = 0x84
    Put-U16 $buffer $coff 0x8664
    Put-U16 $buffer ($coff + 2) 2
    Put-U16 $buffer ($coff + 16) 0xf0
    $optional = $coff + 20
    Put-U16 $buffer $optional 0x20b
    Put-U32 $buffer ($optional + 16) 0x1000
    Put-U64 $buffer ($optional + 24) 0x140000000
    Put-U32 $buffer ($optional + 56) 0x3000
    Put-U32 $buffer ($optional + 108) 16
    $exception = $optional + 112 + 3 * 8
    Put-U32 $buffer $exception 0x2000
    Put-U32 $buffer ($exception + 4) 24
    $sections = $optional + 0xf0
    New-Section $buffer $sections ".text" 0x1000 0x200 0x200 0x60000020
    New-Section $buffer ($sections + 40) ".pdata" 0x2000 0x100 0x400 0x40000040
    Put $buffer 0x200 $first
    Put $buffer (0x200 + 0x20) $second
    Put-U32 $buffer 0x400 0x1000
    Put-U32 $buffer 0x404 0x1012
    Put-U32 $buffer 0x40c 0x1020
    Put-U32 $buffer 0x410 0x1030
    $buffer
}

$old = Join-Path $out "old.exe"
$new = Join-Path $out "new.exe"
[IO.File]::WriteAllBytes($old, (New-Pe (New-Code 0x20 0x100 0x2a) (New-Second-Code 5)))
[IO.File]::WriteAllBytes($new, (New-Pe (New-Code 0x80 0x125 0x2a) (New-Second-Code 6)))

if (-not $SkipBuild) {
    cargo build --locked --release --package relocdiff
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

$exe = Join-Path $repo "target\release\relocdiff.exe"
if (-not (Test-Path -LiteralPath $exe)) { throw "missing executable: $exe" }

$jsonText = (& $exe find $old $new --address 0x140001000 --top 2 --json | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "find command failed" }
$result = $jsonText | ConvertFrom-Json
if (@($result.matches).Count -lt 1) { throw "find returned no matches" }
if ([double]$result.matches[0].confidence -lt 99.9) { throw "best match score is too low" }
if ($result.matches[0].address -ne "0x140001000") { throw "wrong best match address" }

$inspect = (& $exe inspect $old --rva 0x1000 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "inspect command failed" }
if ($inspect -notmatch "ripmem:8" -or $inspect -notmatch "scalar:0x2a") { throw "inspect output missed normalized operands" }

$missing = Join-Path $out "missing.exe"
$errorFile = Join-Path $out "error.txt"
& $exe inspect $missing --rva 0x1000 1>$null 2>$errorFile
if ($LASTEXITCODE -ne 2) { throw "invalid input did not return exit code 2" }
if ((Get-Content -Raw $errorFile) -notmatch "^error: ") { throw "invalid input did not write a useful error" }

Write-Host "e2e ok: relocated match, normalization, JSON, and exit code checks passed"
exit 0
