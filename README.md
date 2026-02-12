<p align="center">
  <img src="https://img.shields.io/badge/STATUS-UNDETECTED-00ff41?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/ENGINE-KERNEL%20MANUAL%20MAP-7b2ff7?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/SIGNATURES-RANDOMIZED-ff6b35?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/GTA%20ONLINE-PUBLIC%20SESSIONS-00d4ff?style=for-the-badge&labelColor=0d1117" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=800&size=36&duration=3000&pause=1000&color=7B2FF7&center=true&vCenter=true&width=500&lines=S+A+R+A+B;The+Mirage;Kernel+Manual+Map;Undetected+%F0%9F%91%BB" alt="SARAB Typing Animation" />
</p>

<h3 align="center">
  <code>
    ╔═══════════════════════════════════════════════════════════╗<br>
    ║&nbsp;&nbsp;&nbsp;░██████╗░█████╗░██████╗░░█████╗░██████╗░&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;╚█████╗░███████║██████╔╝███████║██████╦╝&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;░╚═══██╗██╔══██║██╔══██╗██╔══██║██╔══██╗&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;██████╔╝██║&nbsp;&nbsp;██║██║&nbsp;&nbsp;██║██║&nbsp;&nbsp;██║██████╦╝&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;╚═════╝&nbsp;╚═╝&nbsp;&nbsp;╚═╝╚═╝&nbsp;&nbsp;╚═╝╚═╝&nbsp;&nbsp;╚═╝╚═════╝&nbsp;&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ring-0 Kernel Injection &bull; Dual-Layer Spoofing&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║<br>
    ╚═══════════════════════════════════════════════════════════╝
  </code>
</h3>

<p align="center">
  <b>Created by Koldo</b> &nbsp;•&nbsp; Discord: <b>@Koldo1</b><br>
  <sub>Every build is unique &nbsp;|&nbsp; Every hash is different &nbsp;|&nbsp; Every session is undetected</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-00599C?style=flat&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows%20Driver%20Kit-0078D4?style=flat&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/x64-Kernel%20Mode-red?style=flat" />
</p>

---

## 🔥 What is SARAB?

**SARAB** is a **ring-0 kernel manual map** DLL injection engine built from the ground up for stealth. The entire injection process — PE header parsing, section mapping, base relocations, import resolution, memory protection, and `DllMain` execution — happens **entirely inside the Windows kernel**. 

The usermode component (`sarab.exe`) does only two things: reads the DLL file from disk and writes it to a shared memory section. That's it. **Zero injection APIs are ever called from usermode.** The kernel driver handles everything else invisibly.

> _You can't detect what doesn't exist._

### ⚔️ SARAB vs. Standard Injectors

| | **SARAB** | **Standard Injectors** |
|:---|:---:|:---:|
| Injection API calls from usermode | **❌ Zero** | ✅ VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| Detection surface | **👻 None** | 🎯 Flagged & logged |
| Binary uniqueness per build | **✅ Fully automatic** | ❌ Same hash every time |
| PE operations location | **Ring 0** (kernel) | Ring 3 (usermode) |
| IPC method | **SharedMemory** (invisible) | IOCTLs / DeviceIoControl (flagged) |
| GTA Online public sessions | **✅ Tested & working** | ⚠️ High detection risk |
| Console UI | **🎨 Fusion RGB gradient** | Plain text |

---

## ✨ Features

| | Feature | Description |
|:---:|:---|:---|
| 🧠 | **Full Kernel Manual Map** | PE parsing, section mapping, relocations, import resolution, entry point — all in ring 0 |
| 🔒 | **SharedMemory IPC** | No IOCTLs, no device objects — just a named kernel section. Invisible to API monitors |
| 🎭 | **2-Layer Signature Engine** | Source-level mutation + binary PE mutation = unique fingerprint every single build |
| 🎨 | **Fusion RGB Gradient UI** | 24-bit TrueColor console with animated gradient banner and progress bars |
| 👻 | **Ghost Mode** | Zero usermode injection APIs — zero traces |
| ⚡ | **Instant Injection** | Full manual map completes in milliseconds |
| 🌐 | **GTA Online Ready** | Tested and working in public online sessions |
| 📦 | **YimMenu Included** | Custom-built DLL in `payload/` — works out of the box |

---

## 🔴 CRITICAL — Only Use the Included YimMenu DLL

<table>
<tr>
<td>

> **⛔ THE NORMAL / STANDARD YimMenu DLL WILL NOT WORK WITH SARAB**
>
> SARAB uses **kernel-mode manual mapping** — a fundamentally different injection method. The normal YimMenu DLL from the official GitHub releases is built for standard usermode injection (`LoadLibrary`, usermode manual map, etc.) and **will crash or fail** if used with SARAB.
>
> **Only use the `YimMenu.dll` included in the `payload/` folder.** It was specifically built and tested for SARAB's kernel injection engine.

</td>
</tr>
</table>

| DLL | Compatible? | Reason |
|:---|:---:|:---|
| **`payload/YimMenu.dll`** (included) | ✅ **Works** | Built & tested for kernel manual map injection |
| Normal YimMenu nightly | ❌ **Crashes** | Designed for usermode injection — not compatible |
| Random DLLs from internet | ❌ **Don't** | Untested, incompatible, potentially dangerous |

---

## 📁 Project Structure

```
SARAB/
│
├── 🔨  build_release.bat            Full 5-step build pipeline
├── ⚡  quick_spoof.bat               One-click binary re-spoof
├── 📖  README.md                     Documentation
├── 🚫  .gitignore                    Excludes compiled outputs
│
├── src/
│   ├── driver/
│   │   └── driver.cpp               Kernel manual map engine          [1950 lines]
│   ├── usermode/
│   │   └── sarab.cpp                Injector + Fusion gradient UI     [580 lines]
│   └── shared/
│       └── protocol.h               IPC protocol header
│
├── tools/
│   ├── signature_randomizer.ps1     Binary PE mutation engine         [381 lines, 10 mutations]
│   └── source_randomizer.ps1        Source-level randomizer
│
├── payload/
│   └── YimMenu.dll                  ⚠️ USE ONLY THIS (kernel-compatible)
│
└── output/                          ← Generated after build
    ├── driver.sys                    ~29.5 KB
    └── sarab.exe                    ~140 KB
```

---

## ⚙️ Requirements

<table>
<tr>
<td>

### 🔴 ADMINISTRATOR REQUIRED FOR EVERYTHING

Building, loading the driver, and running the injector **all** require elevated privileges.

**Right-click your terminal → Run as administrator**

</td>
</tr>
</table>

| Requirement | Details | Get It |
|:---|:---|:---|
| **Windows 10/11 x64** | Target OS | — |
| **Administrator** | Everything needs elevation | Right-click → Run as admin |
| **Visual Studio 2022** | With **"Desktop development with C++"** | [Download](https://visualstudio.microsoft.com/downloads/) |
| **Windows Driver Kit 10** | Kernel compilation | [Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| **PowerShell 7+ (pwsh)** | Regex lookbehind support | [Install](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows) |
| **kdmapper** | Kernel driver loader | [GitHub](https://github.com/TheCruZ/kdmapper) |

<details>
<summary><b>📋 Detailed Installation Guide</b></summary>

### Visual Studio 2022 + WDK

1. Install **Visual Studio 2022** (Community is free)
2. In VS Installer → Workloads → check **"Desktop development with C++"**
3. Install the **Windows Driver Kit (WDK)** matching your Windows SDK version
4. Verify: Open **"x64 Native Tools Command Prompt for VS 2022"**

### PowerShell 7

```powershell
# Easiest: Microsoft Store → search "PowerShell" → Install
# Or: winget install --id Microsoft.PowerShell --source winget
```

Verify: `pwsh --version` → `PowerShell 7.x.x`

### kdmapper

1. [kdmapper releases](https://github.com/TheCruZ/kdmapper/releases) — download `kdmapper.exe`
2. Place in the same folder as SARAB's `output/`

</details>

---

## 🚀 Usage Guide

### 📌 Follow This Exact Order

```
  ① BUILD  →  ② MAP DRIVER  →  ③ LAUNCH GAME  →  ④ INJECT  →  ⑤ INSERT KEY
```

Each step depends on the previous. **Do not change the order.**

---

### ① Build Your Unique Binaries

> ⚠️ Admin terminal required

```batch
cd SARAB
build_release.bat
```

| Step | What Happens |
|:---:|:---|
| **1/5** | 🎭 Randomizes identifiers in source code |
| **2/5** | 🔧 Compiles `driver.sys` with unique values |
| **3/5** | 🔧 Compiles `sarab.exe` with matching values |
| **4/5** | 🔄 Restores source to original |
| **5/5** | 🎭 Applies 10 PE mutations to both binaries |

**Result:** `output/driver.sys` + `output/sarab.exe` with completely unique SHA256 hashes.

> 💡 Every run = different machine code + different binary signatures. No two builds are ever the same.

---

### ② Load the Driver with kdmapper

> ⚠️ Admin CMD required

```batch
kdmapper.exe output\driver.sys
```

**Look for:** `[+] Driver mapped successfully` → ✅ driver is live

> ⚠️ Don't close this terminal. Don't reboot. Driver stays loaded until reboot.

---

### ③ Launch GTA V

Open GTA V → wait until **fully loaded** into Story Mode or Online public session.

---

### ④ Inject the DLL

> ⚠️ Open a **new** Admin CMD

```batch
cd SARAB\output
sarab.exe GTA5.exe ..\payload\YimMenu.dll
```

Or interactive mode: just run `sarab.exe` and follow the prompts.

**Look for:** `INJECTION SUCCESSFUL` + mapped base address → ✅ done

---

### ⑤ Open YimMenu

Press **`INSERT`** in-game to toggle the menu overlay.

> 🟢 **Works in GTA Online public sessions.** Tested and confirmed.

---

### ⚡ Re-Spoof Without Rebuilding

```batch
quick_spoof.bat
```

Instantly re-mutates binaries with new signatures — no recompilation needed.

---

## 📋 Quick Reference

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ░██████╗░█████╗░██████╗░░█████╗░██████╗░                       ║
║   ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗   QUICK GUIDE         ║
║   ╚█████╗░███████║██████╔╝███████║██████╦╝   by Koldo | @Koldo1  ║
║   ░╚═══██╗██╔══██║██╔══██╗██╔══██║██╔══██╗                       ║
║   ██████╔╝██║  ██║██║  ██║██║  ██║██████╦╝                       ║
║   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                       ║
║                                                                   ║
║   ⚠️  ALL STEPS REQUIRE RUN AS ADMINISTRATOR  ⚠️                   ║
║                                                                   ║
║   ①  BUILD ──────────►  build_release.bat                         ║
║   ②  MAP DRIVER ─────►  kdmapper.exe output\driver.sys            ║
║   ③  LAUNCH GAME ────►  Open GTA V → load into session            ║
║   ④  INJECT ─────────►  sarab.exe GTA5.exe ..\payload\YimMenu.dll ║
║   ⑤  OPEN MENU ──────►  Press INSERT in-game                      ║
║                                                                   ║
║   RE-SPOOF ──────────►  quick_spoof.bat                            ║
║                                                                   ║
║   ⚠️  USE ONLY THE INCLUDED YimMenu.dll                            ║
║   ⚠️  NORMAL YimMenu DLL WILL NOT WORK                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 🎭 Signature Randomization Engine

### Layer 1 — Source Mutation (Before Compilation)

Mutates identifiers in `protocol.h` before `cl.exe` compiles, making the actual machine code different:

| What Gets Randomized | Example |
|:---|:---|
| Shared memory name (KM) | `\\BaseNamedObjects\\Global\\SarabShm` → `\\BaseNamedObjects\\Global\\xKpLmNqR` |
| Shared memory name (UM) | `Global\\SarabShm` → `Global\\xKpLmNqR` |
| Magic handshake | `0x53415242` → `0xA7F3B2C1` |
| Pool tag | `'barS'` → `'qZxW'` |

### Layer 2 — Binary PE Mutation (After Compilation)

10 mutations applied to the compiled `.sys` and `.exe`:

| # | Mutation | What It Does |
|:---:|:---|:---|
| 1 | **TimeDateStamp** | Randomizes compile timestamp |
| 2 | **Checksum** | Randomizes PE checksum |
| 3 | **Rich Header** | Destroys MSVC fingerprint (64-96 random bytes) |
| 4 | **Section Names** | `.text`→`.code`, `.rdata`→`.cnst`, etc. |
| 5 | **Debug Directory** | Wipes all PDB paths and CodeView GUIDs |
| 6 | **Linker Version** | Fakes MSVC linker version |
| 7 | **OS Version** | Randomizes minimum OS version |
| 8 | **Polymorphic Junk** | Fills code caves with random bytes (1300+ bytes) |
| 9 | **Build GUID** | Stamps unique 128-bit watermark |
| 10 | **DOS Stub** | Randomizes unused DOS header bytes |

### Proof — Every Spoof = Different Hash

```
Run 1:  CFD54215EF00E743182950F050182E95D11056487E7B0C2F4B00294E7800777A
Run 2:  2BA928715B4795075D802702B730F7476F4B425295B4C0D4B11B7E1906923C56
Run 3:  0F53D2E9CE5D91283A2AB63695F87FB002B391EB1B0EE13D8061223CC5FFEE0A
```

---

## 🏗️ Architecture

```
  ┌─────────────────────┐                              ┌──────────────────────────┐
  │                     │    Shared Memory (16MB)       │                          │
  │   sarab.exe         │ ════════════════════════════► │   driver.sys             │
  │   Ring 3 / User     │   DLL bytes + target PID      │   Ring 0 / Kernel        │
  │                     │ ◄════════════════════════════ │                          │
  │  • Find process     │   Status + Progress + Base    │  • Parse PE headers      │
  │  • Read DLL         │                              │  • Allocate memory       │
  │  • Write to SHM     │                              │  • Map sections          │
  │  • Display UI       │                              │  • Fix relocations       │
  │                     │                              │  • Resolve imports       │
  │  APIs used:         │                              │  • Set protections       │
  │  OpenFileMappingA   │                              │  • Call DllMain          │
  │  MapViewOfFile      │                              │  • Return result         │
  │  (normal Windows)   │                              │                          │
  └─────────────────────┘                              └──────────────────────────┘
```

### Why Anti-Cheat Can't See It

| Check | Result |
|:---|:---|
| `VirtualAllocEx` calls | ❌ Not called |
| `WriteProcessMemory` calls | ❌ Not called |
| `CreateRemoteThread` calls | ❌ Not called |
| IOCTL / DeviceIoControl | ❌ None |
| Suspicious handles | ❌ Only `OpenFileMappingA` (normal API) |
| Module list entries | ❌ Manual map = no entry |
| Binary hash matching | ❌ Unique hash every build |

---

## 🔧 Troubleshooting

<details>
<summary><b>🔨 Build Errors</b></summary>

| Error | Fix |
|:---|:---|
| `Visual Studio 2022 not found!` | Install VS2022 + **"Desktop development with C++"** workload |
| `Windows Driver Kit not found!` | Install [WDK 10](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| `pwsh not found` | `winget install Microsoft.PowerShell` |
| `'cl.exe' not recognized` | Build script auto-loads vcvars. Try **"x64 Native Tools Command Prompt"** |
| `ExAllocatePoolWithTag deprecated` | ⚠️ Warning only — build succeeds |
| `_KERNEL_MODE reserved` | ⚠️ Warning only — build succeeds |

</details>

<details>
<summary><b>🔌 Driver Loading (kdmapper)</b></summary>

| Error | Fix |
|:---|:---|
| `Access denied` | **Run as Administrator** |
| `Device \\.\Nal not found` | Disable AV, try another kdmapper version |
| `Failed to load vulnerable driver` | AV blocking `iqvw64e.sys` — add exclusion |
| `Driver already loaded` | **Reboot** — can't re-map without reboot |
| `Secure Boot violation` | Disable Secure Boot in BIOS |
| `BSOD` | WDK version mismatch or driver conflict |

</details>

<details>
<summary><b>💉 Injection (sarab.exe)</b></summary>

| Error | Fix |
|:---|:---|
| `Cannot connect to driver` | Run kdmapper first |
| `Shared memory not found` | Driver crashed — **reboot** + re-map |
| `Process not found` | GTA V must be running and fully loaded |
| `Invalid PE file` | Use only the **included** `payload/YimMenu.dll` |
| `Injection failed — error 4` | Restart GTA V |
| `Injection failed — error 6` | DLL incompatible with game version |
| `Injection timed out` | **Reboot** + re-map + try again |

</details>

<details>
<summary><b>💡 Pro Tips</b></summary>

| Tip | Details |
|:---|:---|
| 🔴 **Always admin** | Everything needs elevation |
| 🔄 **Rebuild each session** | Fresh unique binaries |
| ⚡ **Quick re-spoof** | `quick_spoof.bat` — seconds, no rebuild |
| 🛡️ **Disable AV temporarily** | Defender may flag driver + kdmapper |
| 🔁 **Reboot between sessions** | Clean kernel state |
| 📁 **Never share binaries** | Each build is unique to YOU |
| ⚠️ **Only included YimMenu** | Normal DLL won't work |
| ⏰ **Order matters** | Build → Map → Game → Inject → INSERT |

</details>

---

## 📜 Credits

<table>
<tr>
<td align="center">
  
### 👤 Koldo

**Creator & Developer**<br>
Discord: **@Koldo1**

<sub>Architecture • Kernel Driver • Usermode Injector • Signature Engine • UI Design</sub>

</td>
</tr>
</table>

---

## ⚖️ Disclaimer

This project is for **educational and research purposes only**. The author is not responsible for any misuse. Use at your own risk and in compliance with applicable laws and terms of service.

---

<p align="center">
  <b>S A R A B</b><br>
  <sub><i>The Mirage — You can't detect what doesn't exist</i></sub><br><br>
  <img src="https://img.shields.io/badge/Made%20with-💜-7b2ff7?style=flat&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/by-Koldo-00ff41?style=flat&labelColor=0d1117" />
</p>
