# =============================================================================
# SARAB Signature Randomizer — Full Binary Mutation Engine
# =============================================================================
# Created by: Koldo | Discord: @Koldo1
#
# Randomizes every detectable signature in driver.sys and sarab.exe
# so each build produces a completely unique binary fingerprint.
#
# Mutations:
#   1. PE TimeDateStamp        6. Linker Version
#   2. PE Checksum             7. OS Version
#   3. Rich Header (MSVC)      8. Polymorphic junk injection
#   4. Section names           9. Build GUID watermark
#   5. Debug directory/PDB    10. DOS stub randomization
#
# Usage:
#   .\signature_randomizer.ps1 -TargetFile "driver.sys"
#   .\signature_randomizer.ps1 -TargetFile "sarab.exe"
#   .\signature_randomizer.ps1 -TargetFile "driver.sys" -DetailedLog
#   .\signature_randomizer.ps1 -TargetFile "sarab.exe" -DryRun
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFile,

    [switch]$DryRun,
    [switch]$DetailedLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# Helpers
# =============================================================================

function Write-Banner {
    $banner = @"

  ███████╗ █████╗ ██████╗  █████╗ ██████╗
  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗
  ███████╗███████║██████╔╝███████║██████╔╝
  ╚════██║██╔══██║██╔══██╗██╔══██║██╔══██╗
  ███████║██║  ██║██║  ██║██║  ██║██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
       Signature Randomizer v1.0
       by Koldo | Discord: @Koldo1

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Get-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return $bytes
}

function Get-RandomUInt32 {
    $bytes = Get-RandomBytes 4
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Get-RandomUInt16 {
    $bytes = Get-RandomBytes 2
    return [BitConverter]::ToUInt16($bytes, 0)
}

function Get-RandomAlphaNum([int]$Length) {
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    $result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $result
}

function Write-Status([string]$Message, [string]$Level = "info") {
    switch ($Level) {
        "ok"      { Write-Host "  [OK]  $Message" -ForegroundColor Green }
        "info"    { Write-Host "  [>]   $Message" -ForegroundColor Cyan }
        "warn"    { Write-Host "  [!]   $Message" -ForegroundColor Yellow }
        "error"   { Write-Host "  [X]   $Message" -ForegroundColor Red }
        "detail"  { if ($DetailedLog) { Write-Host "        $Message" -ForegroundColor DarkGray } }
    }
}

# =============================================================================
# PE Header Parsing
# =============================================================================

function Read-UInt32([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Read-UInt16([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Write-UInt32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Copy($bytes, 0, $Data, $Offset, 4)
}

function Write-UInt16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Copy($bytes, 0, $Data, $Offset, 2)
}

# =============================================================================
# MUTATIONS
# =============================================================================

function Mutate-TimeDateStamp([byte[]]$pe, [int]$peOffset) {
    $tsOffset = $peOffset + 8
    $oldTS = Read-UInt32 $pe $tsOffset
    $minEpoch = [uint32]1577836800
    $maxEpoch = [uint32]1767225600
    $newTS = [uint32](Get-Random -Minimum $minEpoch -Maximum $maxEpoch)
    Write-UInt32 $pe $tsOffset $newTS
    Write-Status "TimeDateStamp: 0x$('{0:X8}' -f $oldTS) -> 0x$('{0:X8}' -f $newTS)" "ok"
}

function Mutate-Checksum([byte[]]$pe, [int]$peOffset, [int]$optHeaderOffset) {
    $checksumOffset = $optHeaderOffset + 64
    $oldChecksum = Read-UInt32 $pe $checksumOffset
    $newChecksum = Get-RandomUInt32
    Write-UInt32 $pe $checksumOffset $newChecksum
    Write-Status "Checksum: 0x$('{0:X8}' -f $oldChecksum) -> 0x$('{0:X8}' -f $newChecksum)" "ok"
}

function Mutate-RichHeader([byte[]]$pe, [int]$peSignatureOffset) {
    $found = $false
    $richEnd = -1
    for ($i = $peSignatureOffset - 4; $i -ge 0x80; $i--) {
        if ($pe[$i] -eq 0x52 -and $pe[$i+1] -eq 0x69 -and $pe[$i+2] -eq 0x63 -and $pe[$i+3] -eq 0x68) {
            $richEnd = $i
            $found = $true
            break
        }
    }
    if (-not $found) {
        Write-Status "Rich Header: Not found (stripped)" "warn"
        return
    }
    [uint32]$xorKey = Read-UInt32 $pe ($richEnd + 4)
    [byte]$b0 = 0x44 -bxor ([int]($xorKey -band 0xFF))
    [byte]$b1 = 0x61 -bxor ([int](($xorKey -shr 8) -band 0xFF))
    [byte]$b2 = 0x6E -bxor ([int](($xorKey -shr 16) -band 0xFF))
    [byte]$b3 = 0x53 -bxor ([int](($xorKey -shr 24) -band 0xFF))
    $dansMarker = @($b0, $b1, $b2, $b3)
    $richStart = 0x80
    for ($i = 0x80; $i -lt $richEnd; $i++) {
        if ($pe[$i] -eq $dansMarker[0] -and $pe[$i+1] -eq $dansMarker[1] -and
            $pe[$i+2] -eq $dansMarker[2] -and $pe[$i+3] -eq $dansMarker[3]) {
            $richStart = $i
            break
        }
    }
    $newXorKey = Get-RandomUInt32
    $richLength = $richEnd - $richStart
    $randomFill = Get-RandomBytes $richLength
    [Array]::Copy($randomFill, 0, $pe, $richStart, $richLength)
    $pe[$richEnd]   = 0x52
    $pe[$richEnd+1] = 0x69
    $pe[$richEnd+2] = 0x63
    $pe[$richEnd+3] = 0x68
    Write-UInt32 $pe ($richEnd + 4) $newXorKey
    Write-Status "Rich Header: Randomized $richLength bytes" "ok"
}

function Mutate-SectionNames([byte[]]$pe, [int]$peOffset) {
    $numSections = Read-UInt16 $pe ($peOffset + 6)
    $sizeOfOptHeader = Read-UInt16 $pe ($peOffset + 20)
    $sectionStart = $peOffset + 24 + $sizeOfOptHeader
    $sectionNameMap = @{
        ".text"   = @(".code", ".exec", ".txts", ".scode")
        ".rdata"  = @(".rodat", ".cnst", ".ronly")
        ".data"   = @(".bss", ".datas", ".heap", ".vars")
        ".pdata"  = @(".xdata", ".pdat", ".ehfrm")
        ".reloc"  = @(".fixup", ".rloc", ".rbase")
        ".rsrc"   = @(".res", ".rsrcs", ".asset")
        "INIT"    = @("SETUP", "START", "BOOT", "ENTRY")
        "PAGE"    = @("PAGED", "SWAP", "VMEM", "PGMEM")
    }
    for ($s = 0; $s -lt $numSections; $s++) {
        $nameOffset = $sectionStart + ($s * 40)
        $oldNameBytes = $pe[$nameOffset..($nameOffset + 7)]
        $oldName = [System.Text.Encoding]::ASCII.GetString($oldNameBytes).TrimEnd([char]0)
        $newName = $null
        foreach ($key in $sectionNameMap.Keys) {
            if ($oldName -eq $key) {
                $alternatives = $sectionNameMap[$key]
                $newName = $alternatives[(Get-Random -Maximum $alternatives.Count)]
                break
            }
        }
        if ($null -eq $newName) {
            $newName = "." + (Get-RandomAlphaNum 4)
        }
        $newNameBytes = [System.Text.Encoding]::ASCII.GetBytes($newName)
        $paddedName = New-Object byte[] 8
        [Array]::Copy($newNameBytes, 0, $paddedName, 0, [Math]::Min($newNameBytes.Length, 8))
        [Array]::Copy($paddedName, 0, $pe, $nameOffset, 8)
        Write-Status "Section[$s]: '$oldName' -> '$newName'" "ok"
    }
}

function Mutate-DebugDirectory([byte[]]$pe, [int]$peOffset, [int]$optHeaderOffset) {
    $magic = Read-UInt16 $pe $optHeaderOffset
    $debugDirRVA_Offset = if ($magic -eq 0x20B) { $optHeaderOffset + 144 } else { $optHeaderOffset + 128 }
    $debugRVA = Read-UInt32 $pe $debugDirRVA_Offset
    $debugSize = Read-UInt32 $pe ($debugDirRVA_Offset + 4)
    if ($debugRVA -eq 0 -or $debugSize -eq 0) {
        Write-Status "Debug Directory: Not present (clean)" "ok"
        return
    }
    $numSections = Read-UInt16 $pe ($peOffset + 6)
    $sizeOfOptHeader = Read-UInt16 $pe ($peOffset + 20)
    $sectionStart = $peOffset + 24 + $sizeOfOptHeader
    $debugFileOffset = -1
    for ($s = 0; $s -lt $numSections; $s++) {
        $secBase = $sectionStart + ($s * 40)
        $secVA = Read-UInt32 $pe ($secBase + 12)
        $secVSize = Read-UInt32 $pe ($secBase + 8)
        $secRawOff = Read-UInt32 $pe ($secBase + 20)
        if ($debugRVA -ge $secVA -and $debugRVA -lt ($secVA + $secVSize)) {
            $debugFileOffset = $secRawOff + ($debugRVA - $secVA)
            break
        }
    }
    if ($debugFileOffset -lt 0) {
        Write-UInt32 $pe $debugDirRVA_Offset 0
        Write-UInt32 $pe ($debugDirRVA_Offset + 4) 0
        Write-Status "Debug Directory: Zeroed pointer (could not resolve)" "warn"
        return
    }
    $numEntries = [int]($debugSize / 28)
    for ($e = 0; $e -lt $numEntries; $e++) {
        $entryOff = $debugFileOffset + ($e * 28)
        Write-UInt32 $pe ($entryOff + 4) (Get-RandomUInt32)
        $debugDataSize = Read-UInt32 $pe ($entryOff + 16)
        $debugDataRawOff = Read-UInt32 $pe ($entryOff + 24)
        if ($debugDataRawOff -gt 0 -and $debugDataSize -gt 0 -and ($debugDataRawOff + $debugDataSize) -le $pe.Length) {
            $wipeBytes = Get-RandomBytes $debugDataSize
            [Array]::Copy($wipeBytes, 0, $pe, $debugDataRawOff, $debugDataSize)
            Write-Status "Debug entry[$e]: Wiped $debugDataSize bytes" "ok"
        }
    }
    Write-UInt32 $pe $debugDirRVA_Offset 0
    Write-UInt32 $pe ($debugDirRVA_Offset + 4) 0
    Write-Status "Debug Directory: Fully stripped" "ok"
}

function Mutate-LinkerVersion([byte[]]$pe, [int]$optHeaderOffset) {
    $pe[$optHeaderOffset + 2] = [byte](Get-Random -Minimum 10 -Maximum 15)
    $pe[$optHeaderOffset + 3] = [byte](Get-Random -Minimum 0 -Maximum 40)
    Write-Status "Linker Version: $($pe[$optHeaderOffset + 2]).$($pe[$optHeaderOffset + 3])" "ok"
}

function Mutate-OSVersion([byte[]]$pe, [int]$optHeaderOffset) {
    $majorOS = [uint16](Get-Random -Minimum 6 -Maximum 11)
    $minorOS = [uint16](Get-Random -Minimum 0 -Maximum 4)
    Write-UInt16 $pe ($optHeaderOffset + 40) $majorOS
    Write-UInt16 $pe ($optHeaderOffset + 42) $minorOS
    Write-Status "OS Version: $majorOS.$minorOS" "ok"
}

function Inject-PolymorphicJunk([byte[]]$pe, [int]$peOffset) {
    $numSections = Read-UInt16 $pe ($peOffset + 6)
    $sizeOfOptHeader = Read-UInt16 $pe ($peOffset + 20)
    $sectionStart = $peOffset + 24 + $sizeOfOptHeader
    $totalJunk = 0
    for ($s = 0; $s -lt $numSections; $s++) {
        $secBase = $sectionStart + ($s * 40)
        $secRawOff = Read-UInt32 $pe ($secBase + 20)
        $secRawSize = Read-UInt32 $pe ($secBase + 16)
        $secVSize = Read-UInt32 $pe ($secBase + 8)
        if ($secRawSize -gt $secVSize -and $secVSize -gt 0) {
            $padStart = $secRawOff + $secVSize
            $padLength = [Math]::Min($secRawSize - $secVSize, 512)
            if ($padStart -gt 0 -and ($padStart + $padLength) -le $pe.Length -and $padLength -gt 4) {
                $junk = Get-RandomBytes $padLength
                [Array]::Copy($junk, 0, $pe, $padStart, $padLength)
                $totalJunk += $padLength
            }
        }
    }
    if ($pe.Length -gt 0x40) {
        $dosJunkLen = [Math]::Min(0x3A, $pe.Length - 2)
        $dosJunk = Get-RandomBytes $dosJunkLen
        [Array]::Copy($dosJunk, 0, $pe, 2, $dosJunkLen)
        $totalJunk += $dosJunkLen
    }
    Write-Status "Polymorphic junk: $totalJunk bytes injected" "ok"
}

function Stamp-BuildGUID([byte[]]$pe) {
    $guid = [Guid]::NewGuid()
    $guidBytes = $guid.ToByteArray()
    $peOffset = Read-UInt32 $pe 0x3C
    $stampOffset = 0x40
    if ($stampOffset + 16 -lt $peOffset -and $stampOffset + 16 -lt $pe.Length) {
        [Array]::Copy($guidBytes, 0, $pe, $stampOffset, 16)
        Write-Status "Build GUID: $guid" "ok"
    } else {
        Write-Status "Build GUID: Not enough space" "warn"
    }
}

# =============================================================================
# MAIN
# =============================================================================

Write-Banner

if (-not (Test-Path $TargetFile)) {
    Write-Status "File not found: $TargetFile" "error"
    exit 1
}

$fileInfo = Get-Item $TargetFile
Write-Status "Target: $($fileInfo.FullName)" "info"
Write-Status "Size: $($fileInfo.Length) bytes" "info"
Write-Host ""

$peData = [System.IO.File]::ReadAllBytes($fileInfo.FullName)

if ($peData[0] -ne 0x4D -or $peData[1] -ne 0x5A) {
    Write-Status "Not a valid PE file (missing MZ header)" "error"
    exit 1
}

$peSignatureOffset = Read-UInt32 $peData 0x3C
$peSignature = Read-UInt32 $peData $peSignatureOffset
if ($peSignature -ne 0x00004550) {
    Write-Status "Not a valid PE file (bad PE signature)" "error"
    exit 1
}

$optHeaderOffset = $peSignatureOffset + 24
Write-Status "PE Signature at: 0x$('{0:X}' -f $peSignatureOffset)" "detail"
Write-Host ""

# Backup
$backupPath = "$($fileInfo.FullName).bak"
Copy-Item $fileInfo.FullName $backupPath -Force
Write-Status "Backup: $backupPath" "info"
Write-Host ""

Write-Host "  --- Mutation Pipeline ---" -ForegroundColor DarkGray
Write-Host ""

if (-not $DryRun) {
    Mutate-TimeDateStamp $peData $peSignatureOffset
    Mutate-Checksum $peData $peSignatureOffset $optHeaderOffset
    Mutate-RichHeader $peData $peSignatureOffset
    Mutate-SectionNames $peData $peSignatureOffset
    Mutate-DebugDirectory $peData $peSignatureOffset $optHeaderOffset
    Mutate-LinkerVersion $peData $optHeaderOffset
    Mutate-OSVersion $peData $optHeaderOffset
    Inject-PolymorphicJunk $peData $peSignatureOffset
    Stamp-BuildGUID $peData

    Write-Host ""
    [System.IO.File]::WriteAllBytes($fileInfo.FullName, $peData)
    Write-Status "Mutated binary written: $($fileInfo.FullName)" "ok"

    $hash = (Get-FileHash $fileInfo.FullName -Algorithm SHA256).Hash
    Write-Status "New SHA256: $hash" "ok"
} else {
    Write-Status "DRY RUN — no changes written" "warn"
}

Write-Host ""
Write-Host "  Signature randomization complete!" -ForegroundColor Green
Write-Host ""
