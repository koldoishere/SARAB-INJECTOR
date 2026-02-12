@echo off
REM ============================================================================
REM SARAB ? Full Release Build Pipeline
REM ============================================================================
REM Created by: Koldo | Discord: @Koldo1
REM
REM Pipeline:
REM   1. Randomize source identifiers (shared mem names, magic, pool tag)
REM   2. Build kernel driver (driver.sys)
REM   3. Build usermode injector (sarab.exe)
REM   4. Restore source to original (clean git)
REM   5. Apply binary signature randomization (PE mutations)
REM
REM Each run produces binaries with completely unique signatures.
REM ============================================================================

setlocal

echo.
echo  SARAB ? Release Builder + Signature Spoof
echo  by Koldo / Discord: @Koldo1
echo ============================================================================
echo.

set "RELEASE_DIR=%~dp0"
set "SRC_DIR=%RELEASE_DIR%src"
set "TOOLS_DIR=%RELEASE_DIR%tools"
set "OUTPUT_DIR=%RELEASE_DIR%output"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM ============================================================================
REM Find Visual Studio 2022 (using short paths to avoid x86 parenthesis issues)
REM ============================================================================
set "VSVAR="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VSVAR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VSVAR if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" set "VSVAR=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not defined VSVAR if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" set "VSVAR=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not defined VSVAR if exist "C:\PROGRA~2\MICROS~2\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat" set "VSVAR=C:\PROGRA~2\MICROS~2\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat"

if not defined VSVAR (
    echo [ERROR] Visual Studio 2022 not found!
    pause
    exit /b 1
)

echo [*] VS2022: %VSVAR%

call "%VSVAR%" >nul 2>&1

REM ============================================================================
REM WDK Paths (auto-detect version, using short paths)
REM ============================================================================
set "WDK_BASE=C:\PROGRA~2\WI3CF2~1\10"
set "WDK_VER=10.0.22621.0"
if not exist "%WDK_BASE%\Include\%WDK_VER%\km" set "WDK_VER=10.0.19041.0"
if not exist "%WDK_BASE%\Include\%WDK_VER%\km" set "WDK_VER=10.0.18362.0"
if not exist "%WDK_BASE%\Include\%WDK_VER%\km" (
    echo [ERROR] Windows Driver Kit not found!
    pause
    exit /b 1
)

echo [*] WDK: %WDK_VER%
echo.

set "WDK_INC=%WDK_BASE%\Include\%WDK_VER%"
set "WDK_LIB=%WDK_BASE%\Lib\%WDK_VER%"
set "KM_INC=%WDK_INC%\km"
set "KM_CRT=%WDK_INC%\km\crt"
set "SHARED_INC=%WDK_INC%\shared"
set "KM_LIB=%WDK_LIB%\km\x64"

REM ============================================================================
REM Detect PowerShell 7 (pwsh) ? required for regex lookbehind support
REM ============================================================================
set "PWSH=pwsh"
where pwsh >nul 2>&1
if errorlevel 1 (
    echo [WARN] pwsh not found, trying powershell.exe...
    set "PWSH=powershell"
)
echo [*] PowerShell: %PWSH%
echo.

REM ============================================================================
REM STEP 1: Source-Level Randomization
REM ============================================================================
echo ============================================================================
echo [STEP 1/5] Randomizing source-level identifiers...
echo ============================================================================
echo.

%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\source_randomizer.ps1" -ProjectRoot "%SRC_DIR%"
echo.

REM ============================================================================
REM STEP 2: Build Kernel Driver
REM ============================================================================
echo ============================================================================
echo [STEP 2/5] Building kernel driver...
echo ============================================================================
echo.

cl.exe /c /Zi /W3 /WX- /Ox /Ob2 /Oi /GF /Gs999999 /GR- /Gy /D "_AMD64_" /D "_WIN64" /D "NTDDI_VERSION=0x0A000007" /D "_KERNEL_MODE" /D "_WINDLL" /D "DEPRECATE_DDK_FUNCTIONS=1" /I "%KM_INC%" /I "%KM_CRT%" /I "%SHARED_INC%" /I "%SRC_DIR%\shared" /std:c++17 /kernel /Zc:wchar_t /Zc:forScope /Zc:inline /Fo"%OUTPUT_DIR%\driver.obj" "%SRC_DIR%\driver\driver.cpp"

if errorlevel 1 (
    echo [ERROR] Driver compilation failed!
    %PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\source_randomizer.ps1" -ProjectRoot "%SRC_DIR%" -Restore
    pause
    exit /b 1
)

link.exe /OUT:"%OUTPUT_DIR%\driver.sys" /MACHINE:X64 /SUBSYSTEM:NATIVE /DRIVER:WDM /ENTRY:DriverEntry /NODEFAULTLIB /RELEASE /OPT:REF /OPT:ICF /MERGE:.rdata=.text /MERGE:.pdata=.text /INTEGRITYCHECK "%OUTPUT_DIR%\driver.obj" "%KM_LIB%\ntoskrnl.lib" "%KM_LIB%\hal.lib" "%KM_LIB%\wdmsec.lib" "%KM_LIB%\ntstrsafe.lib" "%KM_LIB%\BufferOverflowFastFailK.lib"

if errorlevel 1 (
    echo [ERROR] Driver linking failed!
    %PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\source_randomizer.ps1" -ProjectRoot "%SRC_DIR%" -Restore
    pause
    exit /b 1
)

echo.
echo [OK] driver.sys built successfully
echo.

REM ============================================================================
REM STEP 3: Build Usermode Injector
REM ============================================================================
echo ============================================================================
echo [STEP 3/5] Building usermode injector...
echo ============================================================================
echo.

cl.exe /nologo /O2 /GS- /EHsc /I "%SRC_DIR%\shared" /Fo"%OUTPUT_DIR%\sarab.obj" /Fd"%OUTPUT_DIR%\sarab.pdb" /Fe:"%OUTPUT_DIR%\sarab.exe" "%SRC_DIR%\usermode\sarab.cpp" kernel32.lib user32.lib advapi32.lib

if errorlevel 1 (
    echo [ERROR] Usermode build failed!
    %PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\source_randomizer.ps1" -ProjectRoot "%SRC_DIR%" -Restore
    pause
    exit /b 1
)

echo.
echo [OK] sarab.exe built successfully
echo.

REM ============================================================================
REM STEP 4: Restore Source
REM ============================================================================
echo ============================================================================
echo [STEP 4/5] Restoring original source...
echo ============================================================================
echo.

%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\source_randomizer.ps1" -ProjectRoot "%SRC_DIR%" -Restore
echo.

REM ============================================================================
REM STEP 5: Binary Signature Randomization
REM ============================================================================
echo ============================================================================
echo [STEP 5/5] Applying binary signature randomization...
echo ============================================================================
echo.

%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\signature_randomizer.ps1" -TargetFile "%OUTPUT_DIR%\driver.sys"
echo.
%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%\signature_randomizer.ps1" -TargetFile "%OUTPUT_DIR%\sarab.exe"

REM Clean up intermediate files
del /q "%OUTPUT_DIR%\driver.obj" 2>nul
del /q "%OUTPUT_DIR%\sarab.obj" 2>nul
del /q "%OUTPUT_DIR%\*.pdb" 2>nul
del /q "%OUTPUT_DIR%\*.bak" 2>nul
del /q "%RELEASE_DIR%\*.obj" 2>nul
del /q "%RELEASE_DIR%\*.pdb" 2>nul

echo.
echo ============================================================================
echo  BUILD COMPLETE ? Signature-Spoofed Binaries Ready
echo ============================================================================
echo.
echo  Output:
echo    %OUTPUT_DIR%\driver.sys
echo    %OUTPUT_DIR%\sarab.exe
echo.
echo  Usage:
echo    1. Load driver.sys via kdmapper or test signing
echo    2. Run: sarab.exe GTA5.exe payload\YimMenu.dll
echo.
echo  Created by Koldo / Discord: @Koldo1
echo ============================================================================
echo.

cd /d "%RELEASE_DIR%"
pause
