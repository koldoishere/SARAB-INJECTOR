# =============================================================================
# SARAB Source-Level Signature Randomizer
# =============================================================================
# Created by: Koldo | Discord: @Koldo1
#
# Randomizes compile-time identifiers in protocol.h BEFORE building.
# Each compiled binary will have unique:
#   - Shared memory object names
#   - Magic handshake values
#   - Pool tags
#
# Usage:
#   .\source_randomizer.ps1 -ProjectRoot "..\src"
#   .\source_randomizer.ps1 -ProjectRoot "..\src" -Restore
# =============================================================================

param(
    [string]$ProjectRoot = (Join-Path $PSScriptRoot "..\src"),
    [switch]$Restore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$protocolFile = Join-Path $ProjectRoot "shared\protocol.h"

if (-not (Test-Path $protocolFile)) {
    Write-Host "[ERROR] Cannot find shared\protocol.h at: $protocolFile" -ForegroundColor Red
    exit 1
}

function Get-RandomHex([int]$Bytes) {
    $b = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    $rng.Dispose()
    return ($b | ForEach-Object { '{0:X2}' -f $_ }) -join ''
}

function Get-RandomAlpha([int]$Length) {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Get-RandomPoolTag {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $tag = -join (1..4 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return "'$($tag[3])$($tag[2])$($tag[1])$($tag[0])'"
}

Write-Host ""
Write-Host "  ███████╗ █████╗ ██████╗  █████╗ ██████╗" -ForegroundColor Cyan
Write-Host "  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗" -ForegroundColor Cyan
Write-Host "  ███████╗███████║██████╔╝███████║██████╔╝" -ForegroundColor Cyan
Write-Host "  ╚════██║██╔══██║██╔══██╗██╔══██║██╔══██╗" -ForegroundColor Cyan
Write-Host "  ███████║██║  ██║██║  ██║██║  ██║██████╔╝" -ForegroundColor Cyan
Write-Host "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝" -ForegroundColor Cyan
Write-Host "       Source-Level Randomizer v1.0" -ForegroundColor DarkGray
Write-Host "       by Koldo | Discord: @Koldo1" -ForegroundColor DarkGray
Write-Host ""

# ─── Backup / Restore ───
$backupFile = "$protocolFile.original"
if ($Restore) {
    if (Test-Path $backupFile) {
        Copy-Item $backupFile $protocolFile -Force
        Write-Host "  [OK] Restored original protocol.h" -ForegroundColor Green
    } else {
        Write-Host "  [!] No backup found to restore" -ForegroundColor Yellow
    }
    exit 0
}

if (-not (Test-Path $backupFile)) {
    Copy-Item $protocolFile $backupFile -Force
    Write-Host "  [>] Original protocol.h backed up" -ForegroundColor Cyan
}

# ─── Generate random values ───
$newShmSuffix = Get-RandomAlpha 8
$newShmNameKM = "\\BaseNamedObjects\\Global\\$newShmSuffix"   # display value
$newShmNameUM = "Global\\$newShmSuffix"                        # display value
$newMagic = "0x$(Get-RandomHex 4)"
$newPoolTag = Get-RandomPoolTag

# For C source: each path separator needs to be \\ (two chars in the file)
# In PS double-quoted strings, \\ is literally two backslash characters (no escape processing)
$newShmKM_C = "\\BaseNamedObjects\\Global\\$newShmSuffix"  # \\=two literal backslashes in PS
$newShmUM_C = "Global\\$newShmSuffix"                       # UM only has one \\ separator

Write-Host "  ─── New Identifiers ─────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  [>] SharedMem (KM): $newShmNameKM" -ForegroundColor Cyan
Write-Host "  [>] SharedMem (UM): $newShmNameUM" -ForegroundColor Cyan
Write-Host "  [>] Magic Value:    $newMagic" -ForegroundColor Cyan
Write-Host "  [>] Pool Tag:       $newPoolTag" -ForegroundColor Cyan
Write-Host ""

# ─── Read and replace ───
$content = Get-Content $protocolFile -Raw

# KM name: L"\\BaseNamedObjects\\Global\\SarabShm" — \\\\ in regex matches \\ in file
$content = $content -replace '(?<=SARAB_SHM_NAME\s+L")\\\\BaseNamedObjects\\\\Global\\\\[^"]+', $newShmKM_C
# UM name: "Global\\SarabShm" — no L prefix, uses \\ in the C file for a single backslash
$content = $content -replace '(?<=SARAB_SHM_NAME_UM\s+")[^"]+', $newShmUM_C
$content = $content -replace '(?<=SARAB_MAGIC\s+)0x[0-9A-Fa-f]+', $newMagic
$content = $content -replace "(?<=SARAB_POOL_TAG\s+)'[^']+'\s*//[^\n]*", "$newPoolTag   // Randomized tag"
$content = $content -replace "(?<=SARAB_POOL_TAG\s+)'[^']+'", $newPoolTag

Set-Content -Path $protocolFile -Value $content -NoNewline
Write-Host "  [OK] protocol.h updated with randomized identifiers" -ForegroundColor Green
Write-Host ""
