// ============================================================================
// SARAB Usermode Controller — Fusion RGB Gradient Theme
// ============================================================================
// Created by: Koldo | Discord: @Koldo1
//
// This program ONLY does:
// 1. Reads DLL file from disk
// 2. Finds target process PID
// 3. Sends raw DLL bytes + PID to the kernel driver via shared memory
// 4. Displays injection progress with Fusion RGB gradient UI
//
// ALL injection work (PE mapping, relocations, imports, DllMain) is done
// in the kernel driver. Zero detection surface from usermode.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "../shared/protocol.h"

// ============================================================================
// Fusion RGB Gradient Engine — 24-bit TrueColor
// ============================================================================

struct Color { int r, g, b; };

// Fusion Palette Anchors
static const Color COL_CYBER_BLUE  = {   0, 150, 255 };
static const Color COL_VOID_PURPLE = { 180,  50, 255 };
static const Color COL_PHANTOM_RED = { 255,  50,  80 };

// Static ANSI macros
#define RESET       "\033[0m"
#define CLR_CYAN    "\033[38;2;0;255;255m"
#define CLR_GREEN   "\033[38;2;0;255;100m"
#define CLR_GOLD    "\033[38;2;255;215;0m"
#define CLR_GRAY    "\033[38;2;80;80;80m"
#define CLR_WHITE   "\033[38;2;220;220;220m"
#define CLR_DIM     "\033[38;2;60;60;60m"
#define CLR_RED     "\033[38;2;255;50;50m"

static char _ansi_buf[64];

static const char* RgbAnsi(Color c) {
    sprintf_s(_ansi_buf, "\033[38;2;%d;%d;%dm", c.r, c.g, c.b);
    return _ansi_buf;
}

static Color LerpColor(Color a, Color b, float t) {
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    return { (int)(a.r + (b.r - a.r) * t),
             (int)(a.g + (b.g - a.g) * t),
             (int)(a.b + (b.b - a.b) * t) };
}

static Color GetFusionGradient(float pct) {
    if (pct < 0.0f) pct = 0.0f;
    if (pct > 1.0f) pct = 1.0f;
    if (pct < 0.5f)
        return LerpColor(COL_CYBER_BLUE, COL_VOID_PURPLE, pct * 2.0f);
    else
        return LerpColor(COL_VOID_PURPLE, COL_PHANTOM_RED, (pct - 0.5f) * 2.0f);
}

// Print a string with fusion gradient (char-by-char)
static void PrintGradientLine(const char* text) {
    int len = (int)strlen(text);
    if (len == 0) return;
    for (int i = 0; i < len; i++) {
        float pct = (float)i / (float)(len > 1 ? len - 1 : 1);
        Color c = GetFusionGradient(pct);
        printf("\033[38;2;%d;%d;%dm%c", c.r, c.g, c.b, text[i]);
    }
    printf(RESET "\n");
}

// ============================================================================
// Console setup
// ============================================================================

static void EnableConsoleColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, mode);
    }
    DWORD inMode = 0;
    if (GetConsoleMode(hIn, &inMode)) {
        inMode |= ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT;
        SetConsoleMode(hIn, inMode);
    }
    Sleep(30);
    fflush(stdout);
}

static void ShowCursor(bool visible) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci = {};
    if (GetConsoleCursorInfo(hOut, &ci)) {
        ci.bVisible = visible ? TRUE : FALSE;
        SetConsoleCursorInfo(hOut, &ci);
    }
}

// ============================================================================
// Banner with glitch animation + Fusion gradient
// ============================================================================

static void PrintBanner() {
    // Clear screen
    printf("\033[2J\033[H");
    fflush(stdout);
    Sleep(10);

    srand((unsigned)time(NULL));

    const char* art[] = {
        "                                                                     ",
        " \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97    \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97 \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97 \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97  \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97 \\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x96\\x88\\xe2\\x95\\x97",
        NULL
    };
    // Use direct UTF-8 block art instead
    printf("\n");

    // Direct gradient block letters
    const char* lines[] = {
        "                                                                     ",
        " ##*    ####### #####  ######  #####  ######",
        " ##*    ##     ##   ## ##   ## ##   ## ##   ##",
        "  ##*   ####### ###### ######  ###### ######",
        "  ##*      ## ##   ## ##   ## ##   ## ##   ##",
        " ##*    ####### ##  ## ##  ## ##  ## ######",
        " **     ****** **  ** **  ** **  ** *****",
        "                                                                     ",
        NULL
    };

    // Actually use the proper UTF-8 box art
    const char* logo[] = {
        " \xe2\x96\x88\xe2\x96\x88\xe2\x95\x97    \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97  \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 ",
        " \xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97   \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97",
        "  \xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97  \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d",
        "  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97",
        " \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d   \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d",
        " \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d    \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d ",
        NULL
    };

    ShowCursor(false);

    printf("\n");
    for (int i = 0; logo[i]; i++) {
        const char* line = logo[i];
        int len = (int)strlen(line);
        int ci = 0;  // character index for gradient
        for (int j = 0; j < len; ) {
            float pct = (float)ci / (float)(len > 1 ? len - 1 : 1);
            Color c = GetFusionGradient(pct);

            unsigned char ch = (unsigned char)line[j];
            int bytes = 1;
            if ((ch & 0xE0) == 0xC0) bytes = 2;
            else if ((ch & 0xF0) == 0xE0) bytes = 3;
            else if ((ch & 0xF8) == 0xF0) bytes = 4;

            printf("\033[38;2;%d;%d;%dm", c.r, c.g, c.b);
            for (int b = 0; b < bytes && j < len; b++, j++)
                putchar(line[j]);
            ci++;
        }
        printf("\n");
        Sleep(8);
    }

    printf(RESET "\n");
    PrintGradientLine("          Kernel Manual Map Injector v3.0");
    PrintGradientLine("             Made by Koldo | @Koldo1");
    printf("\n");

    ShowCursor(true);
}

// ============================================================================
// HUD Dashboard
// ============================================================================

static void PrintDashboard() {
    char username[256] = {};
    DWORD ulen = sizeof(username);
    GetEnvironmentVariableA("USERNAME", username, ulen);

    printf(CLR_GRAY "  %s" RESET "\n",
        "+=== IDENTITY ==========================+=== TELEMETRY ===================+");
    printf(CLR_GRAY "  |" RESET "  MEANING: " CLR_CYAN "The Mirage (Illusion)" RESET
        "       " CLR_GRAY "|" RESET "  ENGINE: " CLR_WHITE "Kernel MM v3" RESET "       " CLR_GRAY "|\n" RESET);
    printf(CLR_GRAY "  |" RESET "  STATUS:  " CLR_GREEN "UNDETECTED" RESET
        "                " CLR_GRAY "|" RESET "  MODE:   " CLR_WHITE "Ghost" RESET "            " CLR_GRAY "|\n" RESET);
    printf(CLR_GRAY "  |" RESET "  USER:    " CLR_CYAN "%s" RESET, username);
    // Padding
    int pad1 = 26 - (int)strlen(username);
    for (int i = 0; i < pad1; i++) putchar(' ');
    printf(CLR_GRAY "|" RESET "  IPC:    " CLR_WHITE "SharedMem" RESET "        " CLR_GRAY "|\n" RESET);
    printf(CLR_GRAY "  %s" RESET "\n\n",
        "+======================================+===================================+");
}

// ============================================================================
// Status + Progress helpers
// ============================================================================

static void PrintStatus(const char* msg, int level) {
    const char* prefix;
    const char* color;
    switch (level) {
        case 0: prefix = "[>]  "; color = CLR_CYAN;  break;
        case 1: prefix = "[OK] "; color = CLR_GREEN; break;
        case 2: prefix = "[!]  "; color = CLR_GOLD;  break;
        case 3: prefix = "[X]  "; color = CLR_RED;   break;
        default: prefix = "[*]  "; color = CLR_WHITE; break;
    }
    printf("  %s%s" RESET CLR_WHITE "%s" RESET "\n", color, prefix, msg);
}

static void ShowFusionProgress(int progress, const char* msg) {
    int barWidth = 30;
    int filled = (progress * barWidth) / 100;

    printf("\r  ");
    Color mid = GetFusionGradient(0.5f);
    printf("\033[38;2;%d;%d;%dm[", mid.r, mid.g, mid.b);

    for (int i = 0; i < barWidth; i++) {
        float pct = (float)i / (float)barWidth;
        Color c = GetFusionGradient(pct);
        printf("\033[38;2;%d;%d;%dm", c.r, c.g, c.b);
        if (i < filled)
            putchar('=');
        else if (i == filled)
            putchar('>');
        else
            putchar(' ');
    }
    printf("\033[38;2;%d;%d;%dm] %3d%% " CLR_DIM "%s" RESET "    ",
           mid.r, mid.g, mid.b, progress, msg);
    fflush(stdout);
}

static void PrintInputBox(const char* label) {
    printf(CLR_DIM "  +--- %s " RESET, label);
    int dashLen = 60 - (int)strlen(label);
    for (int i = 0; i < dashLen; i++) putchar('-');
    printf(CLR_DIM "+" RESET "\n");
    printf(CLR_DIM "  | " CLR_RED "> " RESET);
}

// ============================================================================
// Find process PID by name
// ============================================================================

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ============================================================================
// Read file into buffer
// ============================================================================

static unsigned char* ReadFileToBuffer(const char* path, DWORD* outSize) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char buf[512];
        sprintf_s(buf, "Cannot open file: %s", path);
        PrintStatus(buf, 3);
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE || fileSize > SARAB_MAX_DLL_SIZE) {
        char buf[256];
        sprintf_s(buf, "Invalid file size: %u bytes (max %u)", fileSize, SARAB_MAX_DLL_SIZE);
        PrintStatus(buf, 3);
        CloseHandle(hFile);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        PrintStatus("Memory allocation failed", 3);
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        PrintStatus("Failed to read file", 3);
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *outSize = fileSize;
    return buffer;
}

// ============================================================================
// Connect to kernel driver via shared memory
// ============================================================================

static PSARAB_SHARED_DATA ConnectToDriver() {
    HANDLE hMap = NULL;
    for (int retry = 0; retry < 5; retry++) {
        hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SARAB_SHM_NAME_UM);
        if (hMap) break;
        Sleep(200);
    }

    if (!hMap) {
        PrintStatus("Cannot connect to kernel driver (shared memory not found)", 3);
        PrintStatus("Make sure driver.sys is loaded first", 2);
        return NULL;
    }

    PSARAB_SHARED_DATA shm = (PSARAB_SHARED_DATA)MapViewOfFile(
        hMap, FILE_MAP_ALL_ACCESS, 0, 0, SARAB_SHM_SIZE);
    if (!shm) {
        char buf[128];
        sprintf_s(buf, "MapViewOfFile failed: %u", GetLastError());
        PrintStatus(buf, 3);
        CloseHandle(hMap);
        return NULL;
    }

    if (shm->Magic != SARAB_MAGIC) {
        PrintStatus("Shared memory exists but driver is not active (stale)", 3);
        PrintStatus("Reboot or reload the driver", 2);
        UnmapViewOfFile(shm);
        CloseHandle(hMap);
        return NULL;
    }

    return shm;
}

// ============================================================================
// Driver liveness check
// ============================================================================

static bool PingDriver(PSARAB_SHARED_DATA shm) {
    InterlockedExchange(&shm->CmdState, SARAB_CMD_NONE);
    Sleep(50);

    shm->OpType    = SARAB_OP_PING;
    shm->TargetPID = 0;
    shm->DllSize   = 0;
    shm->Result    = -1;
    InterlockedExchange(&shm->CmdState, SARAB_CMD_READY);

    for (int i = 0; i < 3000; i++) {
        if (shm->CmdState == SARAB_CMD_DONE) {
            char buf[64];
            sprintf_s(buf, "Driver alive — response in %dms", i);
            PrintStatus(buf, 1);
            return true;
        }
        Sleep(1);
    }

    PrintStatus("Driver not responding (dead — no reply after 3s)", 3);
    return false;
}

// ============================================================================
// Injection
// ============================================================================

static bool InjectDll(PSARAB_SHARED_DATA shm, DWORD pid, unsigned char* dllData, DWORD dllSize) {
    char buf[256];
    sprintf_s(buf, "Starting injection — PID: %u | DLL: %u bytes", pid, dllSize);
    PrintStatus(buf, 0);
    printf("\n");

    shm->OpType    = SARAB_OP_INJECT;
    shm->TargetPID = (int)pid;
    shm->DllSize   = (int)dllSize;
    shm->Result    = -1;
    shm->Progress  = 0;
    shm->MappedBase = 0;
    memset(shm->StatusMsg, 0, sizeof(shm->StatusMsg));
    memcpy(shm->DllData, dllData, dllSize);

    InterlockedExchange(&shm->CmdState, SARAB_CMD_READY);

    int lastProgress = -1;
    for (int waitMs = 0; waitMs < 30000; waitMs++) {
        if (shm->CmdState == SARAB_CMD_DONE) {
            ShowFusionProgress(shm->Progress, shm->StatusMsg);
            printf("\n\n");

            if (shm->Result == SARAB_OK) {
                PrintStatus("Injection complete!", 1);
                if (shm->MappedBase) {
                    sprintf_s(buf, "Mapped at: 0x%llX", shm->MappedBase);
                    PrintStatus(buf, 0);
                }
                return true;
            } else {
                sprintf_s(buf, "Injection failed — error code: %d", shm->Result);
                PrintStatus(buf, 3);
                PrintStatus(shm->StatusMsg, 3);
                return false;
            }
        }

        if (shm->Progress != lastProgress) {
            lastProgress = shm->Progress;
            ShowFusionProgress(shm->Progress, shm->StatusMsg);
        }
        Sleep(1);
    }

    printf("\n\n");
    PrintStatus("Injection timed out after 30 seconds", 3);
    InterlockedExchange(&shm->CmdState, SARAB_CMD_NONE);
    return false;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    EnableConsoleColors();
    PrintBanner();
    PrintDashboard();

    // ─── Parse arguments or interactive mode ───
    char processName[256] = {0};
    char dllPath[MAX_PATH] = {0};

    if (argc >= 3) {
        strncpy_s(processName, argv[1], sizeof(processName) - 1);
        strncpy_s(dllPath, argv[2], sizeof(dllPath) - 1);
    } else {
        PrintInputBox("TARGET PROCESS");
        fgets(processName, sizeof(processName), stdin);
        char* nl = strchr(processName, '\n'); if (nl) *nl = 0;
        nl = strchr(processName, '\r'); if (nl) *nl = 0;

        PrintInputBox("DLL PATH");
        fgets(dllPath, sizeof(dllPath), stdin);
        nl = strchr(dllPath, '\n'); if (nl) *nl = 0;
        nl = strchr(dllPath, '\r'); if (nl) *nl = 0;
    }

    if (processName[0] == 0 || dllPath[0] == 0) {
        printf("\n");
        PrintStatus("Usage: sarab.exe <process_name> <dll_path>", 2);
        PrintStatus("Example: sarab.exe GTA5.exe payload\\YimMenu.dll", 0);
        return 1;
    }

    printf("\n");
    PrintGradientLine("  ======== Injection Pipeline ========");
    printf("\n");

    // Step 1: Find process
    char buf[512];
    sprintf_s(buf, "Finding process '%s'...", processName);
    PrintStatus(buf, 0);

    DWORD pid = 0;
    for (int attempt = 0; attempt < 10; attempt++) {
        pid = FindProcess(processName);
        if (pid) break;
        Sleep(500);
    }

    if (!pid) {
        PrintStatus("Process not found — make sure it is running", 3);
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }
    sprintf_s(buf, "Process found — PID %u", pid);
    PrintStatus(buf, 1);

    // Step 2: Read DLL
    PrintStatus("Reading DLL file...", 0);

    DWORD dllSize = 0;
    unsigned char* dllData = ReadFileToBuffer(dllPath, &dllSize);
    if (!dllData) {
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }

    if (dllSize < sizeof(IMAGE_DOS_HEADER) ||
        ((PIMAGE_DOS_HEADER)dllData)->e_magic != IMAGE_DOS_SIGNATURE) {
        PrintStatus("Invalid PE file", 3);
        free(dllData);
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }

    sprintf_s(buf, "DLL loaded — %u bytes", dllSize);
    PrintStatus(buf, 1);

    // Step 3: Connect to driver
    PrintStatus("Connecting to kernel driver...", 0);

    PSARAB_SHARED_DATA shm = ConnectToDriver();
    if (!shm) {
        free(dllData);
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }
    PrintStatus("Connected to kernel driver", 1);

    // Ping
    if (!PingDriver(shm)) {
        free(dllData);
        printf("\n  Press Enter to exit...");
        getchar();
        return 1;
    }

    // Step 4: Inject
    printf("\n");
    PrintGradientLine("  ======== Injecting ========");
    printf("\n");

    bool success = InjectDll(shm, pid, dllData, dllSize);
    free(dllData);

    printf("\n");
    if (success) {
        PrintGradientLine("  ======== INJECTION SUCCESSFUL ========");
    } else {
        PrintStatus("=== INJECTION FAILED ===", 3);
    }

    printf("\n  Press Enter to exit...");
    fflush(stdout);
    getchar();
    if (argc < 3) getchar();

    return success ? 0 : 1;
}
