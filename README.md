<p align="center">
  <img src="https://img.shields.io/badge/STATUS-UNDETECTED-00ff41?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/ENGINE-KERNEL%20MANUAL%20MAP-7b2ff7?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/SIGNATURES-RANDOMIZED-ff6b35?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/GTA%20ONLINE-PUBLIC%20SESSIONS-00d4ff?style=for-the-badge&labelColor=0d1117" />
</p>

<h1 align="center">
  ███████╗ █████╗ ██████╗  █████╗ ██████╗<br>
  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗<br>
  ███████╗███████║██████╔╝███████║██████╔╝<br>
  ╚════██║██╔══██║██╔══██╗██╔══██║██╔══██╗<br>
  ███████║██║  ██║██║  ██║██║  ██║██████╔╝<br>
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝<br>
</h1>

<h3 align="center">🔮 Kernel Manual Map Injector — Dual-Layer Signature Randomization</h3>
<p align="center">
  <b>Created by Koldo</b> &nbsp;|&nbsp; Discord: <b>@Koldo1</b><br>
  <sub>Every build is unique. Every hash is different. Every session is undetected.</sub>
</p>

---

## 🔥 What is SARAB?

**SARAB** (_"The Mirage" — السراب_) is a **ring-0 kernel manual map** DLL injection engine. Everything — PE parsing, relocations, import resolution, memory protection, and `DllMain` execution — happens **entirely in kernel mode**. The usermode component (`sarab.exe`) touches **zero injection APIs**. It only reads the DLL from disk and writes it to shared memory. The kernel driver does the rest.

> **Bottom line:** Anti-cheat sees nothing because there's nothing to see.

### ⚔️ SARAB vs. Everything Else

| | **SARAB** | **Standard Injectors** |
|:---:|:---:|:---:|
| Injection API calls in usermode | **❌ Zero** | ✅ VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| Detection surface | **👻 Ghost** | 🎯 Flagged & logged |
| Binary uniqueness per build | **✅ Automatic** (2-layer randomization) | ❌ Same hash every time |
| Full kernel manual map | **✅ Complete** (all PE ops in ring 0) | ❌ Partial or none |
| IPC method | **✅ SharedMemory** (no IOCTLs, no device objects) | ❌ IOCTLs / DeviceIoControl (flagged) |
| GTA Online public sessions | **✅ Tested & working** | ⚠️ High detection risk |
| Console UI | **🎨 Fusion RGB gradient** | Plain text |

---

## ✨ Features at a Glance

| Feature | Description |
|---------|-------------|
| 🧠 **Full Kernel Manual Map** | PE parsing, section mapping, relocations, import resolution, entry point — all executed in ring 0 |
| 🔒 **SharedMemory IPC** | No IOCTLs, no device objects — just a named kernel section. Invisible to API monitors |
| 🎭 **2-Layer Signature Engine** | Source-level mutation (pre-build) + binary PE mutation (post-build) = unique fingerprint every single time |
| 🎨 **Fusion RGB Gradient UI** | 24-bit TrueColor console with animated gradient banner, progress bars, and themed output |
| 👻 **Ghost Mode** | Zero usermode injection APIs called — zero traces left behind |
| ⚡ **Instant Injection** | Full manual map injection completes in milliseconds |
| 🌐 **GTA Online Ready** | Tested and working in public GTA Online sessions |
| 📦 **YimMenu Included** | Custom-built YimMenu DLL in `payload/` — works out of the box |

---

## 🔴 CRITICAL — Use ONLY the Included YimMenu DLL

> **⚠️ THE NORMAL / STANDARD YimMenu DLL WILL NOT WORK WITH SARAB.**
>
> SARAB uses **kernel-mode manual mapping**, which is a fundamentally different injection method than standard injectors. The normal YimMenu DLL downloaded from the official YimMenu GitHub/nightly releases is built and tested for standard usermode injection (LoadLibrary, manual map from usermode, etc.).
>
> **Only the `YimMenu.dll` included in the `payload/` folder of this release is built to work with SARAB's kernel injection engine.**
>
> Do **NOT** replace it with a random YimMenu download — it will crash or fail to inject.

| DLL | Works with SARAB? | Why? |
|-----|:-:|------|
| `payload/YimMenu.dll` (included) | ✅ **YES** | Built & tested specifically for kernel manual map injection |
| Normal YimMenu nightly DLL | ❌ **NO** | Not compatible with kernel-mode manual mapping |
| Random DLLs from the internet | ❌ **NO** | Untested, likely incompatible, possibly malware |

---

## 📁 Project Structure

```
SARAB/
│
├── 🔨 build_release.bat           ← Full 5-step build pipeline (compile + spoof)
├── ⚡ quick_spoof.bat              ← One-click re-spoof without rebuilding
├── 📖 README.md                    ← You are here
├── 🚫 .gitignore                   ← Keeps compiled outputs out of git
│
├── 📂 src/                         ← Full source code
│   ├── usermode/
│   │   └── sarab.cpp               ← Injector with Fusion gradient theme (580 lines)
│   ├── driver/
│   │   └── driver.cpp              ← Kernel manual map engine (1950 lines)
│   └── shared/
│       └── protocol.h              ← Shared IPC protocol header
│
├── 🛠️ tools/                       ← Signature randomization tools
│   ├── signature_randomizer.ps1    ← Binary PE mutation engine (10 mutations, 381 lines)
│   └── source_randomizer.ps1       ← Source-level identifier randomizer
│
├── 📦 payload/                     ← DLL payloads
│   └── YimMenu.dll                 ← ⚠️ USE ONLY THIS DLL (custom-built for kernel injection)
│
└── 📤 output/                      ← Compiled binaries appear here after build
    ├── driver.sys                   (generated — ~29.5 KB)
    └── sarab.exe                    (generated — ~140 KB)
```

---

## ⚙️ Requirements

<table>
<tr>
<td>

> **🔴 EVERYTHING REQUIRES ADMINISTRATOR**
>
> Building, loading the driver, and running the injector **ALL** require elevated privileges.
>
> **Right-click → Run as administrator** on CMD / PowerShell / Terminal.

</td>
</tr>
</table>

| Requirement | Details | Install |
|:---|:---|:---|
| **Windows 10/11 x64** | Target OS | — |
| **Administrator** | Required for everything | Right-click → Run as administrator |
| **Visual Studio 2022** | Community, Pro, or Enterprise — with **"Desktop development with C++"** | [Download](https://visualstudio.microsoft.com/downloads/) |
| **Windows Driver Kit 10** | Kernel driver compilation | [Download WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| **PowerShell 7+ (pwsh)** | Source randomizer requires regex lookbehinds | [Install](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows) |
| **kdmapper** | Maps driver.sys into kernel (vulnerable Intel driver exploit) | [GitHub](https://github.com/TheCruZ/kdmapper) |

<details>
<summary><b>📋 Detailed Installation Guide</b> (click to expand)</summary>

### Visual Studio 2022 + WDK

1. Download and install **Visual Studio 2022** (Community edition is free)
2. In the VS Installer → Workloads → check **"Desktop development with C++"**
3. Download and install the **Windows Driver Kit (WDK)** matching your Windows SDK version
4. Verify: Open **"x64 Native Tools Command Prompt for VS 2022"** from Start Menu

### PowerShell 7

```powershell
# Option 1: Microsoft Store (easiest)
# Search "PowerShell" in Microsoft Store → Install

# Option 2: winget
winget install --id Microsoft.PowerShell --source winget

# Option 3: Direct download
# https://github.com/PowerShell/PowerShell/releases
```

Verify: `pwsh --version` → should show `PowerShell 7.x.x`

### kdmapper

1. Go to [kdmapper releases](https://github.com/TheCruZ/kdmapper/releases) or build from source
2. Download `kdmapper.exe`
3. Place it somewhere easy to access (e.g., same folder as SARAB's `output/`)

> **What is kdmapper?** It exploits a vulnerable signed Intel driver (`iqvw64e.sys`) to load unsigned kernel drivers without needing test signing mode or boot configuration changes.

</details>

---

## 🚀 Usage — Step by Step

### 📌 The Order Matters

```
BUILD  →  MAP DRIVER  →  LAUNCH GAME  →  INJECT  →  PRESS INSERT
```

Do **NOT** change this order. Each step depends on the previous one.

---

### 1️⃣ Build Your Unique Binaries

> ⚠️ **Admin CMD / PowerShell required**

```batch
cd SARAB
build_release.bat
```

The 5-step pipeline runs automatically:

| Step | What Happens | Why |
|:---:|---|---|
| **1/5** | 🎭 Source randomizer | Mutates shared memory names, magic values, pool tags in `protocol.h` |
| **2/5** | 🔧 Compile `driver.sys` | Kernel driver built with YOUR unique randomized identifiers |
| **3/5** | 🔧 Compile `sarab.exe` | Usermode injector built with matching identifiers |
| **4/5** | 🔄 Restore source | `protocol.h` reverts to original (clean for git) |
| **5/5** | 🎭 Binary spoofer | 10 PE mutations on both binaries |

**Result:** `output/driver.sys` + `output/sarab.exe` — completely unique to this build.

> 💡 **Each time you run `build_release.bat`, both binaries get completely new SHA256 hashes.** No two builds are ever the same.

---

### 2️⃣ Map the Driver with kdmapper

> ⚠️ **Admin CMD required**

```batch
kdmapper.exe "C:\path\to\SARAB\output\driver.sys"
```

**Expected output:**
```
[+] Device \\.\Nal found
[+] Vulnerable driver loaded
[+] Image base has been allocated at 0xFFFFF80712340000
[+] Driver mapped successfully
[+] Cleanup complete
```

✅ `Driver mapped successfully` = the kernel driver is live and shared memory is created.

> ⚠️ **Don't close this terminal. Don't reboot. The driver stays loaded until you reboot.**

---

### 3️⃣ Launch GTA V

1. Open GTA V (Steam / Epic / Rockstar Launcher)
2. Wait until you're **fully loaded** into Story Mode or an Online public session
3. Game **MUST** be running before you inject

---

### 4️⃣ Inject the DLL

> ⚠️ **Open a NEW Admin CMD** (keep the kdmapper terminal open)

```batch
cd SARAB\output
sarab.exe GTA5.exe ..\payload\YimMenu.dll
```

Or use **interactive mode** (no arguments):
```batch
sarab.exe
```
```
TARGET PROCESS > GTA5.exe
DLL PATH > ..\payload\YimMenu.dll
```

**Success output:**
```
  ╔═══════════════════════════════════════╗
  ║      SARAB — Kernel Manual Map        ║
  ║         Made by Koldo | @Koldo1       ║
  ╚═══════════════════════════════════════╝

  [OK] Process found — PID 12345
  [OK] DLL loaded — 11402240 bytes
  [OK] Connected to kernel driver
  [OK] Driver alive — response in 2ms

  [==============================>] 100% Done

  [OK] Injection complete!
  [>]  Mapped at: 0x7FF612340000

  ======== INJECTION SUCCESSFUL ========
```

---

### 5️⃣ Use YimMenu In-Game

1. Go back to GTA V
2. Press **`INSERT`** to open the YimMenu overlay
3. Navigate and enable features
4. Press **`INSERT`** again to close

> 🟢 **Works in GTA Online public sessions.** The included YimMenu DLL is specifically built for kernel injection and tested in public lobbies.

---

### ⚡ Optional: Re-Spoof Without Rebuilding

Want fresh signatures instantly? No compilation needed:

```batch
cd SARAB
quick_spoof.bat
```

This re-mutates the existing binaries with new PE signatures in seconds. New hash, same functionality.

---

## 📋 Quick Reference Card

```
 ╔══════════════════════════════════════════════════════════════════╗
 ║                                                                  ║
 ║   ███████╗ █████╗ ██████╗  █████╗ ██████╗   QUICK GUIDE         ║
 ║   ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗                      ║
 ║   ███████╗███████║██████╔╝███████║██████╔╝  by Koldo | @Koldo1  ║
 ║   ╚════██║██╔══██║██╔══██╗██╔══██║██╔══██╗                      ║
 ║   ███████║██║  ██║██║  ██║██║  ██║██████╔╝                      ║
 ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                      ║
 ║                                                                  ║
 ║  ⚠️  ALL STEPS REQUIRE RUN AS ADMINISTRATOR  ⚠️                  ║
 ║                                                                  ║
 ║  1. BUILD ──────────► build_release.bat                          ║
 ║  2. MAP DRIVER ─────► kdmapper.exe output\driver.sys             ║
 ║  3. LAUNCH GAME ────► Open GTA V → load into session             ║
 ║  4. INJECT ─────────► sarab.exe GTA5.exe ..\payload\YimMenu.dll  ║
 ║  5. OPEN MENU ──────► Press INSERT in-game                       ║
 ║                                                                  ║
 ║  RE-SPOOF ──────────► quick_spoof.bat  (no rebuild needed)       ║
 ║                                                                  ║
 ║  ⚠️  USE ONLY THE INCLUDED YimMenu.dll — NORMAL ONES DON'T WORK  ║
 ║                                                                  ║
 ╚══════════════════════════════════════════════════════════════════╝
```

---

## 🎭 Signature Randomization Engine

Every build produces a **completely unique binary**. Anti-cheat cannot signature-match because there is no static signature.

### 🔹 Layer 1 — Source-Level Mutation (Pre-Compilation)

Runs **before** `cl.exe` — mutates identifiers in `protocol.h` so the compiled machine code itself is fundamentally different:

| Identifier | Original Value | Example After Randomization |
|:---|:---|:---|
| Shared memory name (kernel) | `\\BaseNamedObjects\\Global\\SarabShm` | `\\BaseNamedObjects\\Global\\xKpLmNqR` |
| Shared memory name (usermode) | `Global\\SarabShm` | `Global\\xKpLmNqR` |
| Magic handshake value | `0x53415242` | `0xA7F3B2C1` |
| Kernel pool tag | `'barS'` | `'qZxW'` |

### 🔹 Layer 2 — Binary PE Mutation (Post-Compilation)

10 mutations applied to the compiled `.sys` and `.exe` files:

| # | Mutation | Effect |
|:---:|:---|:---|
| 1 | **TimeDateStamp** | Randomizes PE compile timestamp |
| 2 | **Checksum** | Randomizes PE checksum field |
| 3 | **Rich Header** | Destroys MSVC build fingerprint — compiler versions, object counts, all randomized |
| 4 | **Section Names** | `.text`→`.code`, `.rdata`→`.cnst`, `.data`→`.heap`, etc. |
| 5 | **Debug Directory** | Wipes PDB paths, CodeView GUIDs, and all debug metadata |
| 6 | **Linker Version** | Fakes the MSVC linker version number |
| 7 | **OS Version** | Randomizes minimum OS version in PE header |
| 8 | **Polymorphic Junk** | Fills code caves + DOS stub padding with cryptographic random bytes |
| 9 | **Build GUID** | Stamps a unique 128-bit watermark per build |
| 10 | **DOS Stub** | Randomizes unused bytes in the DOS header area |

### 🔹 Proof — SHA256 Changes Every Time

```
Spoof 1:  CFD54215EF00E743182950F050182E95D11056487E7B0C2F4B00294E7800777A
Spoof 2:  2BA928715B4795075D802702B730F7476F4B425295B4C0D4B11B7E1906923C56
Spoof 3:  0F53D2E9CE5D91283A2AB63695F87FB002B391EB1B0EE13D8061223CC5FFEE0A
```

Every single spoof = completely different hash. Verified and tested.

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────────────────┐
                    │              SHARED MEMORY SECTION (16MB)           │
                    │  ┌──────────────────────────────────────────────┐   │
                    │  │  Magic | CmdState | OpType | PID | DllSize  │   │
                    │  │  Result | Progress | MappedBase | StatusMsg  │   │
                    │  │  DllData[0 ... 16MB]                        │   │
                    │  └──────────────────────────────────────────────┘   │
                    └─────────────────┬───────────────────┬───────────────┘
                                      │                   │
              ┌───────────────────────┘                   └────────────────────────┐
              │                                                                    │
              ▼                                                                    ▼
┌──────────────────────────┐                                 ┌──────────────────────────────┐
│    sarab.exe (Ring 3)     │                                 │     driver.sys (Ring 0)       │
│    ─────────────────────  │                                 │     ──────────────────────    │
│                           │                                 │                                │
│  ► Find target process    │     Write DLL bytes + PID       │  ► Parse PE headers            │
│  ► Read DLL from disk     │  ──────────────────────────►    │  ► Allocate kernel memory      │
│  ► Copy to shared memory  │                                 │  ► Map PE sections             │
│  ► Wait for result        │     Return status + base addr   │  ► Apply relocations           │
│  ► Display Fusion UI      │  ◄──────────────────────────    │  ► Resolve imports (ntoskrnl)  │
│  ► Show progress bar      │                                 │  ► Set page protections        │
│                           │                                 │  ► Execute DllMain             │
│  API calls: OpenFileMap-  │                                 │  ► Report result + base addr   │
│  pingA, MapViewOfFile     │                                 │                                │
│  (100% normal Windows)    │                                 │  Zero usermode artifacts       │
└──────────────────────────┘                                 └──────────────────────────────┘
```

### Why This Design Is Invisible

| Anti-Cheat Check | Result |
|:---|:---|
| Scan for `VirtualAllocEx` calls | ❌ Not called — memory allocated from kernel |
| Scan for `WriteProcessMemory` calls | ❌ Not called — sections mapped from kernel |
| Scan for `CreateRemoteThread` / `NtCreateThreadEx` | ❌ Not called — entry point invoked from kernel |
| Scan for IOCTL traffic | ❌ None — no device objects, no `DeviceIoControl` |
| Scan for suspicious handles | ❌ Only `OpenFileMappingA` — a completely normal Win32 API |
| Scan for loaded module list entries | ❌ Manual map = no module list entry |
| Hash-match binary signatures | ❌ Every build has a unique hash |

---

## 🔧 Troubleshooting

<details>
<summary><b>🔨 Build Errors</b> (click to expand)</summary>

| Error | Fix |
|:---|:---|
| `Visual Studio 2022 not found!` | Install VS2022 with **"Desktop development with C++"** workload |
| `Windows Driver Kit not found!` | Install [WDK 10](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) matching your Windows SDK |
| `pwsh not found` | Install PowerShell 7: `winget install Microsoft.PowerShell` |
| `'cl.exe' is not recognized` | The build script auto-loads vcvars64. If it fails, run from **"x64 Native Tools Command Prompt for VS 2022"** |
| `ExAllocatePoolWithTag deprecated` | ⚠️ **Warning only** — build succeeds normally |
| `macro name '_KERNEL_MODE' is reserved` | ⚠️ **Warning only** — build succeeds normally |

</details>

<details>
<summary><b>🔌 Driver Loading Errors (kdmapper)</b> (click to expand)</summary>

| Error | Fix |
|:---|:---|
| `Access denied` | **Run CMD as Administrator** — this is the #1 issue |
| `Device \\.\Nal not found` | kdmapper can't load the Intel driver — disable AV, try different kdmapper version |
| `Failed to load vulnerable driver` | Antivirus blocking `iqvw64e.sys` — add exclusion or temporarily disable AV |
| `Driver already loaded` | **Reboot PC** — you can't re-map without a fresh boot |
| `Secure Boot violation` | Disable Secure Boot in BIOS/UEFI |
| `Blue screen (BSOD)` | WDK version mismatch with Windows — also check for conflicting drivers |
| `Image base allocation failed` | Reboot and try again — kernel address space conflict |

</details>

<details>
<summary><b>💉 Injection Errors (sarab.exe)</b> (click to expand)</summary>

| Error | Fix |
|:---|:---|
| `Cannot connect to kernel driver` | Driver isn't loaded — run kdmapper first |
| `Shared memory not found` | Driver crashed or wasn't mapped — **reboot** + re-map |
| `Driver not responding (dead)` | Driver loaded but not functioning — **reboot** + re-map |
| `Process not found` | GTA V must be **running and fully loaded** before injecting |
| `Invalid PE file` | DLL is corrupted — make sure you're using the included `payload/YimMenu.dll` |
| `Injection failed — error 4` | Memory allocation failed — restart GTA V and try again |
| `Injection failed — error 6` | Import resolution failed — DLL may be incompatible with game version |
| `Injection timed out` | Driver is stuck — **reboot**, re-map, try again |

</details>

<details>
<summary><b>💡 Pro Tips</b> (click to expand)</summary>

| Tip | Details |
|:---|:---|
| 🔴 **Always run as admin** | Building, mapping, injecting — everything needs elevation |
| 🔄 **Rebuild before each session** | `build_release.bat` = fresh unique binaries |
| ⚡ **Quick re-spoof** | `quick_spoof.bat` = new signatures in seconds, no rebuild |
| 🛡️ **Disable antivirus temporarily** | Defender may flag kdmapper and driver.sys |
| 🔁 **Reboot between sessions** | Clean kernel state — never re-map without rebooting |
| 📁 **Never share your compiled binaries** | Each build is unique to YOU — sharing defeats the signature randomization |
| 🎮 **Game first, then inject** | Launch GTA V → fully loaded → then run sarab.exe |
| ⏰ **Order matters** | Build → Map → Game → Inject → INSERT |
| ⚠️ **Only use included YimMenu** | Normal/nightly YimMenu DLL will NOT work with kernel injection |

</details>

---

## 📜 Credits

<table>
<tr>
<td align="center">
<h3>👤 Koldo</h3>
<b>Creator & Developer</b><br>
Discord: <b>@Koldo1</b><br>
<sub>Architecture • Kernel Driver • Usermode Injector • Signature Engine • UI</sub>
</td>
</tr>
</table>

---

## ⚖️ Disclaimer

This project is provided for **educational and research purposes only**. The author is not responsible for any misuse. Use at your own risk and in compliance with applicable laws and terms of service.

---

<p align="center">
  <b>SARAB</b> — السراب — <i>The Mirage</i><br>
  <sub>You can't detect what doesn't exist.</sub><br><br>
  Made with 💜 by <b>Koldo</b>
</p>
