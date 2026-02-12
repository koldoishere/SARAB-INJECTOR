// ============================================================================
// SARAB Kernel Driver — Full Kernel-Mode Manual Map Injection Engine
// ============================================================================
// All PE mapping, relocation, import resolution, and DllMain execution
// happens entirely in kernel mode. Usermode only sends raw DLL bytes + PID.
// ============================================================================

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>

// We include protocol.h for shared data structures
#include "../shared/protocol.h"

// ============================================================================
// Forward declarations for kernel functions not in standard headers
// ============================================================================
extern "C" {

NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS(NTAPI* fn_ZwCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

// RtlCreateUserThread is documented and exported on all Windows versions
typedef NTSTATUS(NTAPI* fn_RtlCreateUserThread)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits OPTIONAL,
    IN OUT PULONG StackReserved OPTIONAL,
    IN OUT PULONG StackCommit OPTIONAL,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle OPTIONAL,
    OUT PCLIENT_ID ClientId OPTIONAL);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(IN PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(
    IN PEPROCESS FromProcess, IN PVOID FromAddress,
    IN PEPROCESS ToProcess, OUT PVOID ToAddress,
    IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied);

NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(
    IN PVOID PcValue, OUT PVOID* BaseOfImage);

} // extern "C"

// Function pointer type for RtlInsertInvertedFunctionTable (unexported)
typedef NTSTATUS(NTAPI* fn_RtlInsertInvertedFunctionTable)(PVOID ImageBase, ULONG SizeOfImage);

// ============================================================================
// PEB / LDR structures for import resolution
// ============================================================================
typedef struct _PEB_LDR_DATA_K {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_K, *PPEB_LDR_DATA_K;

typedef struct _LDR_DATA_TABLE_ENTRY_K {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    LIST_ENTRY     HashLinks;
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_K, *PLDR_DATA_TABLE_ENTRY_K;

typedef struct _PEB_K {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA_K Ldr;
    // ... more fields we don't need
} PEB_K, *PPEB_K;

// ============================================================================
// Debug trace macro
// ============================================================================
#define TRACE(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[SARAB] " fmt "\n", ##__VA_ARGS__)

// ============================================================================
// Global state
// ============================================================================
static PVOID              g_SharedMem      = NULL;
static HANDLE             g_SectionHandle  = NULL;
static PVOID              g_SectionObject  = NULL;
static KEVENT             g_StopEvent;
static fn_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;
static fn_RtlCreateUserThread g_pRtlCreateUserThread = NULL;
static fn_RtlInsertInvertedFunctionTable g_pRtlInsertInvFuncTable = NULL;

// ============================================================================
// Helper: Set status message in shared memory
// ============================================================================
static void SetStatus(PSARAB_SHARED_DATA shm, int progress, const char* msg) {
    if (!shm) return;
    shm->Progress = progress;
    RtlStringCbCopyA(shm->StatusMsg, sizeof(shm->StatusMsg), msg);
    TRACE("Progress %d%%: %s", progress, msg);
}

// ============================================================================
// PE PARSER — Validate and parse PE image from raw file bytes
// ============================================================================

static BOOLEAN ValidatePE(PVOID RawImage, ULONG ImageSize) {
    if (ImageSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)RawImage;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ImageSize)
        return FALSE;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)RawImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return FALSE;

    return TRUE;
}

static PIMAGE_NT_HEADERS64 GetNtHeaders(PVOID RawImage) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)RawImage;
    return (PIMAGE_NT_HEADERS64)((PUCHAR)RawImage + dos->e_lfanew);
}

static PIMAGE_SECTION_HEADER GetFirstSection(PIMAGE_NT_HEADERS64 nt) {
    return IMAGE_FIRST_SECTION(nt);
}

// ============================================================================
// KERNEL MANUAL MAPPER — Core injection engine
// ============================================================================

// Forward declarations for mutual recursion between export resolution and forwarding
static PVOID ResolveForwardedExport(PEPROCESS Process, PVOID ModuleBase, ULONG exportDirRva, ULONG exportDirSize, ULONG funcRva);
static PVOID GetModuleExportByOrdinal(PEPROCESS Process, PVOID ModuleBase, USHORT Ordinal);
static NTSTATUS CreateUserThreadWrapper(HANDLE ProcHandle, PVOID StartAddress, PVOID Parameter, PHANDLE ThreadHandle);

// Find a loaded module in target process by walking PEB->Ldr
static PVOID FindModuleInProcess(PEPROCESS Process, const char* ModuleName) {
    PPEB_K peb = (PPEB_K)PsGetProcessPeb(Process);
    if (!peb) return NULL;

    __try {
        PPEB_LDR_DATA_K ldr = peb->Ldr;
        if (!ldr) return NULL;

        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY current = head->Flink;

        while (current != head) {
            PLDR_DATA_TABLE_ENTRY_K entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_K, InLoadOrderLinks);
            
            if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
                // Convert module name to ANSI for comparison
                ANSI_STRING ansiName;
                NTSTATUS cvt = RtlUnicodeStringToAnsiString(&ansiName, &entry->BaseDllName, TRUE);
                if (NT_SUCCESS(cvt)) {
                    if (_stricmp(ansiName.Buffer, ModuleName) == 0) {
                        PVOID base = entry->DllBase;
                        RtlFreeAnsiString(&ansiName);
                        return base;
                    }
                    RtlFreeAnsiString(&ansiName);
                }
            }
            current = current->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception in FindModuleInProcess: 0x%X", GetExceptionCode());
    }

    return NULL;
}

// Get export address from a module loaded in the target process
static PVOID GetModuleExport(PEPROCESS Process, PVOID ModuleBase, const char* FuncName) {
    if (!ModuleBase || !FuncName) return NULL;

    __try {
        // Read DOS header
        IMAGE_DOS_HEADER dos;
        RtlCopyMemory(&dos, ModuleBase, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        // Read NT headers
        IMAGE_NT_HEADERS64 nt;
        RtlCopyMemory(&nt, (PUCHAR)ModuleBase + dos.e_lfanew, sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exportDirRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportDirSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportDirRva || !exportDirSize) return NULL;

        IMAGE_EXPORT_DIRECTORY exportDir;
        RtlCopyMemory(&exportDir, (PUCHAR)ModuleBase + exportDirRva, sizeof(exportDir));

        PULONG nameRvas = (PULONG)((PUCHAR)ModuleBase + exportDir.AddressOfNames);
        PUSHORT ordinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir.AddressOfNameOrdinals);
        PULONG funcRvas = (PULONG)((PUCHAR)ModuleBase + exportDir.AddressOfFunctions);

        for (ULONG i = 0; i < exportDir.NumberOfNames; i++) {
            ULONG nameRva = 0;
            RtlCopyMemory(&nameRva, &nameRvas[i], sizeof(ULONG));
            
            char name[256] = {0};
            RtlCopyMemory(name, (PUCHAR)ModuleBase + nameRva, min((ULONG)255, exportDirSize));
            name[255] = 0;

            if (strcmp(name, FuncName) == 0) {
                USHORT ordinal = 0;
                RtlCopyMemory(&ordinal, &ordinals[i], sizeof(USHORT));

                ULONG funcRva = 0;
                RtlCopyMemory(&funcRva, &funcRvas[ordinal], sizeof(ULONG));

                // Check for forwarded export
                if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize) {
                    TRACE("Export %s is forwarded, resolving...", FuncName);
                    return ResolveForwardedExport(Process, ModuleBase, exportDirRva, exportDirSize, funcRva);
                }

                return (PVOID)((PUCHAR)ModuleBase + funcRva);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception in GetModuleExport: 0x%X", GetExceptionCode());
    }

    return NULL;
}

// ============================================================================
// ORDINAL EXPORT RESOLUTION — resolve export by ordinal number
// ============================================================================
static PVOID GetModuleExportByOrdinal(PEPROCESS Process, PVOID ModuleBase, USHORT Ordinal) {
    if (!ModuleBase) return NULL;
    __try {
        IMAGE_DOS_HEADER dos;
        RtlCopyMemory(&dos, ModuleBase, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        IMAGE_NT_HEADERS64 nt;
        RtlCopyMemory(&nt, (PUCHAR)ModuleBase + dos.e_lfanew, sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exportDirRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportDirSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportDirRva || !exportDirSize) return NULL;

        IMAGE_EXPORT_DIRECTORY exportDir;
        RtlCopyMemory(&exportDir, (PUCHAR)ModuleBase + exportDirRva, sizeof(exportDir));

        USHORT index = Ordinal - (USHORT)exportDir.Base;
        if (index >= exportDir.NumberOfFunctions) return NULL;

        PULONG funcRvas = (PULONG)((PUCHAR)ModuleBase + exportDir.AddressOfFunctions);
        ULONG funcRva = 0;
        RtlCopyMemory(&funcRva, &funcRvas[index], sizeof(ULONG));
        if (!funcRva) return NULL;

        // Check for forwarded export
        if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize) {
            return ResolveForwardedExport(Process, ModuleBase, exportDirRva, exportDirSize, funcRva);
        }

        return (PVOID)((PUCHAR)ModuleBase + funcRva);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

// ============================================================================
// API SET SCHEMA REDIRECTION — resolve api-ms-win-* virtual DLLs
// ============================================================================
static BOOLEAN ResolveApiSetName(const char* apiSetName, char* resolvedName, ULONG resolvedMaxLen) {
    // api-ms-win-crt-runtime-l1-1-0.dll -> ucrtbase.dll
    // api-ms-win-crt-*.dll             -> ucrtbase.dll
    // api-ms-win-core-*.dll            -> kernelbase.dll / kernel32.dll / ntdll.dll

    if (_strnicmp(apiSetName, "api-ms-win-crt-", 15) == 0 ||
        _strnicmp(apiSetName, "api-ms-win-apds-", 16) == 0) {
        RtlStringCbCopyA(resolvedName, resolvedMaxLen, "ucrtbase.dll");
        return TRUE;
    }
    if (_strnicmp(apiSetName, "api-ms-win-core-", 16) == 0) {
        // Most core APIs redirect to kernelbase.dll on Win10+
        RtlStringCbCopyA(resolvedName, resolvedMaxLen, "kernelbase.dll");
        return TRUE;
    }
    if (_strnicmp(apiSetName, "api-ms-win-", 11) == 0) {
        // Generic catch-all for other api-ms-win-* -> kernelbase.dll
        RtlStringCbCopyA(resolvedName, resolvedMaxLen, "kernelbase.dll");
        return TRUE;
    }
    if (_strnicmp(apiSetName, "ext-ms-", 7) == 0) {
        // Extended API sets usually resolve to actual DLL
        RtlStringCbCopyA(resolvedName, resolvedMaxLen, "kernelbase.dll");
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// FORWARDED EXPORT RESOLUTION — resolve forwarded exports (e.g. kernel32 -> ntdll)
// ============================================================================
static PVOID ResolveForwardedExport(
    PEPROCESS Process, PVOID ModuleBase, 
    ULONG exportDirRva, ULONG exportDirSize, ULONG funcRva
) {
    // Forwarded exports look like "NTDLL.RtlAllocateHeap" or "api-ms-win-crt-stdio-l1-1-0._acrt_iob_func"
    char forwardStr[256] = {0};
    __try {
        RtlCopyMemory(forwardStr, (PUCHAR)ModuleBase + funcRva, min((ULONG)255, exportDirSize));
        forwardStr[255] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    // Split "MODULE.Function" at the dot
    char* dot = NULL;
    for (int i = 0; forwardStr[i]; i++) {
        if (forwardStr[i] == '.') { dot = &forwardStr[i]; break; }
    }
    if (!dot) return NULL;
    *dot = 0; // null-terminate module name
    char* fwdModule = forwardStr;
    char* fwdFunc = dot + 1;

    // Build full DLL name
    char dllName[280] = {0};
    RtlStringCbCopyA(dllName, sizeof(dllName), fwdModule);
    RtlStringCbCatA(dllName, sizeof(dllName), ".dll");

    // Handle API set redirection in forwarded exports
    char resolved[256] = {0};
    if (ResolveApiSetName(dllName, resolved, sizeof(resolved))) {
        RtlStringCbCopyA(dllName, sizeof(dllName), resolved);
    }

    // Find the forwarded-to module
    PVOID fwdBase = FindModuleInProcess(Process, dllName);
    if (!fwdBase) {
        // Try uppercase
        for (int i = 0; dllName[i]; i++) {
            if (dllName[i] >= 'a' && dllName[i] <= 'z') dllName[i] -= 32;
        }
        fwdBase = FindModuleInProcess(Process, dllName);
    }
    if (!fwdBase) return NULL;

    // Check if it's an ordinal forward (starts with #)
    if (fwdFunc[0] == '#') {
        USHORT ord = 0;
        for (int i = 1; fwdFunc[i]; i++) {
            ord = ord * 10 + (fwdFunc[i] - '0');
        }
        return GetModuleExportByOrdinal(Process, fwdBase, ord);
    }

    return GetModuleExport(Process, fwdBase, fwdFunc);
}

// ============================================================================
// TLS CALLBACK EXECUTION — execute TLS callbacks before DllMain
// ============================================================================
static void ExecuteTlsCallbacks(
    PEPROCESS TargetProc, PVOID RemoteBase, PVOID LocalImage, ULONG ImageSize,
    HANDLE ProcHandle, PSARAB_SHARED_DATA Shm
) {
    if (!g_pZwCreateThreadEx && !g_pRtlCreateUserThread) {
        TRACE("No thread execution method available — skipping TLS callbacks");
        return;
    }

    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(LocalImage);
    ULONG tlsDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    ULONG tlsDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (!tlsDirRva || !tlsDirSize) {
        TRACE("No TLS directory — skipping TLS callbacks");
        return;
    }

    // TLS directory is in the locally-built image
    PIMAGE_TLS_DIRECTORY64 tlsDir = (PIMAGE_TLS_DIRECTORY64)((PUCHAR)LocalImage + tlsDirRva);

    // The AddressOfCallBacks points into the IMAGE as loaded (at remote base)
    // We need to read the callback array from the local image
    if (!tlsDir->AddressOfCallBacks) {
        TRACE("TLS directory exists but no callbacks");
        return;
    }

    // Calculate offset of callback array from image base
    ULONGLONG preferredBase = nt->OptionalHeader.ImageBase;
    
    // After relocations, AddressOfCallBacks contains relocated address.
    // We need to convert it back to RVA to read from local image.
    // Try both interpretations: as RVA directly, or as relocated VA
    ULONGLONG callbackArrayRva = 0;
    
    TRACE("TLS AddressOfCallBacks=0x%llX, PreferredBase=0x%llX, RemoteBase=0x%p, ImageSize=0x%X",
        tlsDir->AddressOfCallBacks, preferredBase, RemoteBase, ImageSize);
    
    // First check if it looks like an RVA (small value)
    if (tlsDir->AddressOfCallBacks < ImageSize) {
        callbackArrayRva = tlsDir->AddressOfCallBacks;
        TRACE("Interpreted as RVA: 0x%llX", callbackArrayRva);
    } 
    // Otherwise assume it's a relocated VA (subtract preferred base to get RVA)
    else if (tlsDir->AddressOfCallBacks >= preferredBase) {
        callbackArrayRva = tlsDir->AddressOfCallBacks - preferredBase;
        TRACE("Subtracted preferred base, RVA=0x%llX", callbackArrayRva);
        if (callbackArrayRva >= ImageSize) {
            // Try subtracting remote base instead
            callbackArrayRva = tlsDir->AddressOfCallBacks - (ULONGLONG)RemoteBase;
            TRACE("Out of bounds, tried remote base, RVA=0x%llX", callbackArrayRva);
        }
    }
    
    if (callbackArrayRva >= ImageSize) {
        TRACE("TLS callback array RVA 0x%llX out of bounds (AddressOfCallBacks=0x%llX)", 
            callbackArrayRva, tlsDir->AddressOfCallBacks);
        return;
    }

    PULONGLONG callbacks = (PULONGLONG)((PUCHAR)LocalImage + callbackArrayRva);
    int numCallbacks = 0;

    TRACE("TLS callback array at local offset 0x%llX, first 4 pointers: [0]=0x%llX [1]=0x%llX [2]=0x%llX [3]=0x%llX", 
        callbackArrayRva, callbacks[0], callbacks[1], callbacks[2], callbacks[3]);

    ULONGLONG remoteStart = (ULONGLONG)RemoteBase;
    ULONGLONG remoteEnd = remoteStart + ImageSize;

    // Each callback is a function pointer (in remote address space)
    // Some DLLs have padding/NULLs at the start, so check all 64 slots
    for (int i = 0; i < 64; i++) { // safety limit
        ULONGLONG cbAddr = callbacks[i];
        
        // Skip NULLs (padding) but continue scanning
        if (!cbAddr) continue;
        
        // Validate callback is within module range (relocated address)
        if (cbAddr < remoteStart || cbAddr >= remoteEnd) {
            TRACE("TLS callback #%d at 0x%llX is outside module range, stopping scan", i, cbAddr);
            break;
        }

        // cbAddr is already relocated to remote address space
        TRACE("Executing TLS callback #%d at 0x%llX", i, cbAddr);

        // TLS callback signature is same as DllMain:
        // void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
        // We need shellcode: rcx=remoteBase, edx=DLL_PROCESS_ATTACH(1), r8=NULL

        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);

        PVOID shellcodeAddr = NULL;
        SIZE_T shellcodeSize = PAGE_SIZE;
        NTSTATUS st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &shellcodeAddr, 0, &shellcodeSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (NT_SUCCESS(st) && shellcodeAddr) {
            // TLS callback shellcode — proper stack alignment with clean ret
            // Same pattern as GuidedHacking: call callback, then ret.
            // No need for NtTerminateThread/RtlExitUserThread.
            UCHAR tlsShellcode[] = {
                // Prologue — align stack (entry RSP is misaligned by 8 due to call)
                0x48, 0x83, 0xEC, 0x28,             // [0..3]   sub rsp, 0x28 (0x20 shadow + 0x8 align)
                // TLS callback signature: void NTAPI callback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
                0x48, 0xB9, 0,0,0,0,0,0,0,0,       // [4..13]  mov rcx, imm64     → patch at [6]
                0xBA, 0x01, 0x00, 0x00, 0x00,       // [14..18] mov edx, 1 (DLL_PROCESS_ATTACH)
                0x4D, 0x31, 0xC0,                   // [19..21] xor r8, r8 (NULL)
                0x48, 0xB8, 0,0,0,0,0,0,0,0,       // [22..31] mov rax, imm64     → patch at [24]
                0xFF, 0xD0,                         // [32..33] call rax
                // Epilogue — clean return
                0x48, 0x83, 0xC4, 0x28,             // [34..37] add rsp, 0x28
                0x48, 0x31, 0xC0,                   // [38..40] xor rax, rax (return 0)
                0xC3                                // [41]     ret
            };

            *(PULONGLONG)&tlsShellcode[6]  = (ULONGLONG)RemoteBase;   // rcx = hModule
            *(PULONGLONG)&tlsShellcode[24] = cbAddr;                  // rax = callback address

            __try {
                RtlCopyMemory(shellcodeAddr, tlsShellcode, sizeof(tlsShellcode));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                KeUnstackDetachProcess(&apcState);
                continue;
            }
        }
        KeUnstackDetachProcess(&apcState);

        if (!shellcodeAddr) continue;

        // Execute the TLS callback — use wrapper with automatic fallback
        HANDLE hThread = NULL;
        NTSTATUS tlsSt = CreateUserThreadWrapper(ProcHandle, shellcodeAddr, NULL, &hThread);

        if (NT_SUCCESS(tlsSt) && hThread) {
            PVOID threadObj = NULL;
            tlsSt = ObReferenceObjectByHandle(hThread, SYNCHRONIZE, *PsThreadType, KernelMode, &threadObj, NULL);
            if (NT_SUCCESS(tlsSt) && threadObj) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -100000000LL; // 10 seconds
                KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, &timeout);
                ObDereferenceObject(threadObj);
            }
            ZwClose(hThread);
            numCallbacks++;
            TRACE("TLS callback #%d completed", i);
        } else {
            TRACE("TLS callback #%d thread failed: 0x%X, stopping TLS callbacks to preserve process state", i, tlsSt);
            // If a callback fails, stop trying more callbacks - the process may be terminating
            break;
        }

        // Free shellcode
        KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);
        SIZE_T freeSz = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcodeAddr, &freeSz, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
    }

    TRACE("%d TLS callbacks executed", numCallbacks);
}

// ============================================================================
// EXCEPTION HANDLER REGISTRATION — now integrated into DllMain shellcode
// ============================================================================
// NOTE: Exception registration is now handled directly in the DllMain shellcode
// (see DllMain execution below). This matches the pattern used by TTKKO_Injector
// and BlackBone — calling RtlAddFunctionTable in the same shellcode/context as
// DllMain, NOT in a separate thread. This eliminates thread exit crashes and
// race conditions.
// ============================================================================

// Function removed — replaced by integrated shellcode in DllMain execution
// (see lines 1460+ for new implementation)


// ============================================================================
// THREAD CREATION WRAPPER — ZwCreateThreadEx fallback to RtlCreateUserThread
// ============================================================================
static NTSTATUS CreateUserThreadWrapper(
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    PHANDLE ThreadHandle
) {
    // Try ZwCreateThreadEx first if available (Vista+)
    if (g_pZwCreateThreadEx) {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        
        return g_pZwCreateThreadEx(
            ThreadHandle,
            THREAD_ALL_ACCESS,
            &oa,
            ProcessHandle,
            StartAddress,
            Parameter,
            FALSE,  // CreateSuspended
            0,      // ZeroBits
            0,      // StackSize
            0,      // MaximumStackSize
            NULL    // AttributeList
        );
    }
    
    // Fallback to RtlCreateUserThread (XP+, always available)
    else if (g_pRtlCreateUserThread) {
        CLIENT_ID clientId = {0};
        
        // Note: Cannot pass kernel-mode pointers for stack parameters to user-mode function
        // Must pass NULL to use default stack sizes
        return g_pRtlCreateUserThread(
            ProcessHandle,
            NULL,               // SecurityDescriptor
            FALSE,              // CreateSuspended
            0,                  // StackZeroBits
            NULL,               // StackReserved - use default (NULL from kernel mode)
            NULL,               // StackCommit - use default (NULL from kernel mode)
            StartAddress,
            Parameter,
            ThreadHandle,
            &clientId
        );
    }
    
    TRACE("CreateUserThreadWrapper: No thread creation APIs available");
    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// DEPENDENCY PRELOADER — load missing DLLs into target via LoadLibraryA
// ============================================================================
static void PreloadDependencies(
    ULONG       TargetPID,
    PEPROCESS   TargetProc,
    PVOID       LocalImage,
    ULONG       ImageSize,
    PSARAB_SHARED_DATA Shm
) {
    if (!g_pZwCreateThreadEx && !g_pRtlCreateUserThread) {
        TRACE("PreloadDependencies: No thread creation method available, skipping");
        return;
    }

    // Get import directory from the locally-built image
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)LocalImage +
        ((PIMAGE_DOS_HEADER)LocalImage)->e_lfanew);
    ULONG importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (!importRva || !importSize) return;

    // Collect missing module names (max 64)
    char* missingNames[64];
    int numMissing = 0;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)LocalImage + importRva);

    // Scan import table while attached to read PEB
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);
    __try {
        while (importDesc->Name && numMissing < 64) {
            if (importDesc->Name >= ImageSize) { importDesc++; continue; }
            char* name = (char*)((PUCHAR)LocalImage + importDesc->Name);
            // Skip api-ms-win-* virtual DLLs — they redirect to already-loaded real DLLs
            char resolvedName[256] = {0};
            BOOLEAN isApiSet = ResolveApiSetName(name, resolvedName, sizeof(resolvedName));

            PVOID base = FindModuleInProcess(TargetProc, name);
            if (!base && isApiSet) {
                // Try the resolved real DLL name
                base = FindModuleInProcess(TargetProc, resolvedName);
                if (base) {
                    TRACE("Dependency %s resolved via API set to %s (already loaded)", name, resolvedName);
                }
            }
            if (!base) {
                // For api-ms-* that still aren't found, don't try to LoadLibrary them
                // (they're virtual DLLs, LoadLibrary may hang or fail)
                if (isApiSet) {
                    TRACE("API set %s -> %s not loaded, will try to load %s", name, resolvedName, resolvedName);
                    // Store the REAL dll name instead of the api-ms-* name
                    // We need to write it somewhere stable — use static buffer approach
                    // Actually, LoadLibrary handles api-ms-* redirection itself on Win10+
                }
                missingNames[numMissing++] = name;
                TRACE("Dependency missing: %s", name);
            }
            importDesc++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception scanning imports: 0x%X", GetExceptionCode());
    }
    KeUnstackDetachProcess(&apcState);

    if (numMissing == 0) {
        TRACE("All dependencies already loaded");
        return;
    }

    TRACE("Need to load %d dependencies", numMissing);
    SetStatus(Shm, 25, "Loading dependencies...");

    // Open process handle for ZwCreateThreadEx
    HANDLE hProc = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPID;
    cid.UniqueThread = NULL;
    NTSTATUS st = ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(st) || !hProc) {
        TRACE("PreloadDependencies: ZwOpenProcess failed 0x%X", st);
        return;
    }

    // Find LoadLibraryA in kernel32.dll (always loaded in any Win32 process)
    KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);
    PVOID k32 = FindModuleInProcess(TargetProc, "kernel32.dll");
    if (!k32) k32 = FindModuleInProcess(TargetProc, "KERNEL32.DLL");
    PVOID pLoadLibA = k32 ? GetModuleExport(TargetProc, k32, "LoadLibraryA") : NULL;
    KeUnstackDetachProcess(&apcState);

    if (!pLoadLibA) {
        TRACE("PreloadDependencies: LoadLibraryA not found");
        ZwClose(hProc);
        return;
    }
    TRACE("LoadLibraryA at %p", pLoadLibA);

    // Load each missing dependency
    for (int i = 0; i < numMissing; i++) {
        SIZE_T nameLen = 0;
        const char* p = missingNames[i];
        while (*p++) nameLen++;
        nameLen++; // include null terminator

        // Allocate string in target process
        PVOID remoteName = NULL;
        SIZE_T allocSz = nameLen;
        KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);
        st = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteName, 0, &allocSz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(st) && remoteName) {
            __try {
                RtlCopyMemory(remoteName, missingNames[i], nameLen);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                remoteName = NULL;
            }
        }
        KeUnstackDetachProcess(&apcState);

        if (!remoteName) {
            TRACE("Failed to allocate string for %s", missingNames[i]);
            continue;
        }

        // Create thread at LoadLibraryA(remoteName) — use wrapper with automatic fallback
        HANDLE hThread = NULL;
        st = CreateUserThreadWrapper(hProc, pLoadLibA, remoteName, &hThread);

        if (NT_SUCCESS(st) && hThread) {
            // Wait for LoadLibrary to complete (max 10 seconds)
            PVOID threadObj = NULL;
            st = ObReferenceObjectByHandle(hThread, SYNCHRONIZE, *PsThreadType, KernelMode, &threadObj, NULL);
            if (NT_SUCCESS(st) && threadObj) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -100000000LL; // 10 seconds
                KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, &timeout);
                ObDereferenceObject(threadObj);
            }
            ZwClose(hThread);
            TRACE("Loaded dependency: %s", missingNames[i]);
        } else {
            TRACE("Failed to create thread for %s: 0x%X", missingNames[i], st);
        }

        // Free the string allocation in target
        KeStackAttachProcess((PRKPROCESS)TargetProc, &apcState);
        SIZE_T freeSz = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteName, &freeSz, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
    }

    ZwClose(hProc);
    TRACE("Dependency preloading complete");
}

// ============================================================================
// CORE: Full kernel-mode manual map injection
// ============================================================================
static NTSTATUS KernelManualMap(
    ULONG       TargetPID,
    PVOID       RawDll,
    ULONG       DllSize,
    PSARAB_SHARED_DATA Shm
) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS targetProc = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    HANDLE procHandle = NULL;
    PVOID remoteBase = NULL;
    SIZE_T remoteSize = 0;
    PVOID localImage = NULL;

    // ---- Step 1: Validate PE ----
    SetStatus(Shm, SARAB_STAGE_PARSING, "Validating PE image...");

    if (!ValidatePE(RawDll, DllSize)) {
        TRACE("Invalid PE image");
        Shm->Result = SARAB_ERR_INVALID_PE;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = GetNtHeaders(RawDll);
    ULONG imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    ULONG headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    ULONG numSections = ntHeaders->FileHeader.NumberOfSections;
    ULONGLONG preferredBase = ntHeaders->OptionalHeader.ImageBase;
    ULONG entryPointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    TRACE("PE: ImageSize=0x%X, Headers=0x%X, Sections=%d, Entry=0x%X, PreferredBase=0x%llX",
          imageSize, headerSize, numSections, entryPointRva, preferredBase);

    // ---- Step 2: Get target process ----
    SetStatus(Shm, SARAB_STAGE_ALLOCATING, "Looking up target process...");

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPID, &targetProc);
    if (!NT_SUCCESS(status) || !targetProc) {
        TRACE("PsLookupProcessByProcessId failed: 0x%X", status);
        Shm->Result = SARAB_ERR_PROCESS_NOT_FOUND;
        return status;
    }

    // Determine target process image name for logging
    const char* imageName = (const char*)PsGetProcessImageFileName(targetProc);
    TRACE("Target image: %s (exception handlers auto-registered if present in mapped DLL)", imageName ? imageName : "<unknown>");

    // ---- Step 3: Build local image (apply PE layout) ----
    SetStatus(Shm, SARAB_STAGE_MAPPING, "Building mapped image locally...");

    localImage = ExAllocatePoolWithTag(NonPagedPool, imageSize, SARAB_POOL_TAG);
    if (!localImage) {
        TRACE("Failed to allocate local image buffer");
        ObDereferenceObject(targetProc);
        Shm->Result = SARAB_ERR_ALLOC_FAILED;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(localImage, imageSize);

    // Copy headers
    RtlCopyMemory(localImage, RawDll, min(headerSize, DllSize));

    // Copy sections
    PIMAGE_SECTION_HEADER sections = GetFirstSection(ntHeaders);
    for (ULONG i = 0; i < numSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        if (sections[i].PointerToRawData + sections[i].SizeOfRawData > DllSize) {
            TRACE("Section %d exceeds file size", i);
            continue;
        }
        if (sections[i].VirtualAddress + sections[i].SizeOfRawData > imageSize) {
            TRACE("Section %d exceeds image size", i);
            continue;
        }

        RtlCopyMemory(
            (PUCHAR)localImage + sections[i].VirtualAddress,
            (PUCHAR)RawDll + sections[i].PointerToRawData,
            sections[i].SizeOfRawData
        );
    }

    TRACE("Local image built: %d sections mapped", numSections);

    // ---- Step 3.5: Pre-load missing dependencies ----
    PreloadDependencies(TargetPID, targetProc, localImage, imageSize, Shm);

    // ---- Step 4: Attach to target process and allocate ----
    SetStatus(Shm, SARAB_STAGE_ALLOCATING, "Allocating memory in target...");

    __try {
        KeStackAttachProcess((PRKPROCESS)targetProc, &apcState);
        attached = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception attaching to process: 0x%X", GetExceptionCode());
        ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
        ObDereferenceObject(targetProc);
        Shm->Result = SARAB_ERR_EXCEPTION;
        return STATUS_UNSUCCESSFUL;
    }

    // Allocate in target process
    remoteSize = imageSize;
    remoteBase = NULL;

    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &remoteBase, 0, &remoteSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status) || !remoteBase) {
        TRACE("ZwAllocateVirtualMemory failed: 0x%X", status);
        KeUnstackDetachProcess(&apcState);
        ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
        ObDereferenceObject(targetProc);
        Shm->Result = SARAB_ERR_ALLOC_FAILED;
        return status;
    }

    TRACE("Allocated 0x%llX bytes at 0x%p in target", (ULONGLONG)remoteSize, remoteBase);

    // ---- Step 5: Apply relocations ----
    SetStatus(Shm, SARAB_STAGE_RELOCATING, "Applying relocations...");

    LONGLONG delta = (LONGLONG)((ULONGLONG)remoteBase - preferredBase);
    if (delta != 0) {
        ULONG relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ULONG relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (relocRva && relocSize) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)localImage + relocRva);
            PUCHAR relocEnd = (PUCHAR)reloc + relocSize;

            while ((PUCHAR)reloc < relocEnd && reloc->SizeOfBlock > 0) {
                ULONG numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                PUSHORT entries = (PUSHORT)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (ULONG i = 0; i < numEntries; i++) {
                    USHORT type = entries[i] >> 12;
                    USHORT offset = entries[i] & 0xFFF;
                    PUCHAR target = (PUCHAR)localImage + reloc->VirtualAddress + offset;

                    if ((ULONG)(reloc->VirtualAddress + offset + sizeof(ULONGLONG)) > imageSize)
                        continue;

                    switch (type) {
                        case IMAGE_REL_BASED_DIR64:
                            *(PULONGLONG)target += delta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(PULONG)target += (ULONG)delta;
                            break;
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break; // padding, skip
                        default:
                            TRACE("Unknown relocation type: %d", type);
                            break;
                    }
                }

                reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
            }

            TRACE("Relocations applied (delta=0x%llX)", (ULONGLONG)delta);
        } else {
            // No relocations available and image not at preferred base
            if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
                TRACE("Warning: No relocation data but image not at preferred base");
            } else {
                TRACE("ERROR: Image requires preferred base but relocs are stripped");
                KeUnstackDetachProcess(&apcState);
                ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
                ObDereferenceObject(targetProc);
                Shm->Result = SARAB_ERR_RELOC_FAILED;
                return STATUS_CONFLICTING_ADDRESSES;
            }
        }
    } else {
        TRACE("No relocation needed (loaded at preferred base)");
    }

    // ---- Step 6: Resolve imports ----
    SetStatus(Shm, SARAB_STAGE_IMPORTS, "Resolving imports...");

    ULONG importRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG importSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importRva && importSize) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)localImage + importRva);

        while (importDesc->Name) {
            char* dllName = (char*)((PUCHAR)localImage + importDesc->Name);
            TRACE("Resolving imports from: %s", dllName);

            // Find this module in the target process
            PVOID moduleBase = FindModuleInProcess(targetProc, dllName);
            if (!moduleBase) {
                // Try API set redirection (api-ms-win-* -> real DLL)
                char resolvedDll[256] = {0};
                if (ResolveApiSetName(dllName, resolvedDll, sizeof(resolvedDll))) {
                    TRACE("API set redirect: %s -> %s", dllName, resolvedDll);
                    moduleBase = FindModuleInProcess(targetProc, resolvedDll);
                }
                if (!moduleBase) {
                    // Try uppercase name
                    char upperName[256] = {0};
                    RtlStringCbCopyA(upperName, sizeof(upperName), dllName);
                    for (int j = 0; upperName[j]; j++) {
                        if (upperName[j] >= 'a' && upperName[j] <= 'z') upperName[j] -= 32;
                    }
                    moduleBase = FindModuleInProcess(targetProc, upperName);
                }
                if (!moduleBase) {
                    TRACE("Module %s not found in target - imports will fail", dllName);
                    importDesc++;
                    continue;
                }
            }

            // Walk the thunks
            PIMAGE_THUNK_DATA64 origThunk = (importDesc->OriginalFirstThunk)
                ? (PIMAGE_THUNK_DATA64)((PUCHAR)localImage + importDesc->OriginalFirstThunk)
                : (PIMAGE_THUNK_DATA64)((PUCHAR)localImage + importDesc->FirstThunk);
            
            PIMAGE_THUNK_DATA64 firstThunk = (PIMAGE_THUNK_DATA64)((PUCHAR)localImage + importDesc->FirstThunk);

            while (origThunk->u1.AddressOfData) {
                PVOID funcAddr = NULL;

                if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                    // Import by ordinal
                    USHORT ordinal = (USHORT)IMAGE_ORDINAL64(origThunk->u1.Ordinal);
                    funcAddr = GetModuleExportByOrdinal(targetProc, moduleBase, ordinal);
                    if (!funcAddr) {
                        TRACE("  Failed ordinal import #%d from %s", ordinal, dllName);
                    }
                } else {
                    // Import by name
                    if (origThunk->u1.AddressOfData < imageSize) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)localImage + origThunk->u1.AddressOfData);
                        funcAddr = GetModuleExport(targetProc, moduleBase, (char*)importByName->Name);
                        
                        if (!funcAddr) {
                            TRACE("  Failed to resolve: %s!%s", dllName, importByName->Name);
                        }
                    }
                }

                if (funcAddr) {
                    firstThunk->u1.Function = (ULONGLONG)funcAddr;
                }

                origThunk++;
                firstThunk++;
            }

            importDesc++;
        }

        TRACE("Import resolution complete");
    }

    // ---- Step 7: Write mapped image to target process ----
    SetStatus(Shm, SARAB_STAGE_PROTECTING, "Writing image to target process...");

    __try {
        RtlCopyMemory(remoteBase, localImage, imageSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception writing to target: 0x%X", GetExceptionCode());
        // Try to free allocated memory
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
        ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
        ObDereferenceObject(targetProc);
        Shm->Result = SARAB_ERR_MAP_FAILED;
        return STATUS_UNSUCCESSFUL;
    }

    TRACE("Image written to target at 0x%p", remoteBase);

    // ---- Step 8: Set section protections ----
    SetStatus(Shm, SARAB_STAGE_PROTECTING, "Setting memory protections...");

    // Update the NT headers pointer in local copy to point to correct location
    PIMAGE_NT_HEADERS64 localNt = GetNtHeaders(localImage);
    PIMAGE_SECTION_HEADER localSections = GetFirstSection(localNt);

    for (ULONG i = 0; i < numSections; i++) {
        if (localSections[i].Misc.VirtualSize == 0) continue;

        ULONG protect = PAGE_READONLY;
        ULONG chars = localSections[i].Characteristics;

        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            if (chars & IMAGE_SCN_MEM_READ)
                protect = PAGE_READWRITE;
            else
                protect = PAGE_WRITECOPY;
        } else if (chars & IMAGE_SCN_MEM_READ) {
            protect = PAGE_READONLY;
        } else {
            protect = PAGE_NOACCESS;
        }

        PVOID sectionBase = (PUCHAR)remoteBase + localSections[i].VirtualAddress;
        SIZE_T sectionSize = localSections[i].Misc.VirtualSize;
        ULONG oldProtect = 0;

        __try {
            ZwProtectVirtualMemory(ZwCurrentProcess(), &sectionBase, &sectionSize, protect, &oldProtect);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TRACE("Exception setting protection for section %d: 0x%X", i, GetExceptionCode());
        }
    }

    // ---- Step 9: PE header erasure DEFERRED until after DllMain ----
    // CRT startup (__DllMainCRTStartup) reads PE headers to initialize the runtime.
    // Headers must be intact when DllMain is called. We erase them AFTER DllMain completes.
    // (See Step 11 below)

    // Detach before thread creation (ZwCreateThreadEx needs detached context)
    KeUnstackDetachProcess(&apcState);
    attached = FALSE;

    TRACE("Detached from target. Ready for post-mapping setup.");

    // Open process handle for ZwCreateThreadEx (used by TLS, exception reg, and DllMain)
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID cid;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPID;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (!NT_SUCCESS(status) || !procHandle) {
        TRACE("ZwOpenProcess failed for post-map setup: 0x%X", status);
        ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
        ObDereferenceObject(targetProc);
        Shm->Result = SARAB_ERR_ENTRY_FAILED;
        return status;
    }

    // Check process liveness after dependency loading
    {
        NTSTATUS procExitStatus = PsGetProcessExitStatus(targetProc);
        if (procExitStatus != STATUS_PENDING) {
            TRACE("ABORT: Target process died during dependency loading! Exit: 0x%X", procExitStatus);
            ZwClose(procHandle);
            ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
            ObDereferenceObject(targetProc);
            Shm->Result = SARAB_ERR_ENTRY_FAILED;
            return STATUS_PROCESS_IS_TERMINATING;
        }
        TRACE("Process alive after dependency loading, continuing...");
    }

    // ---- Step 9.5: Exception handlers now integrated into DllMain shellcode ----
    // NOTE: Exception registration (RtlAddFunctionTable) is now called directly
    // in the DllMain shellcode, eliminating the need for a separate thread.
    // This matches the pattern used by TTKKO_Injector and BlackBone.
    TRACE("Exception handlers will be registered in DllMain shellcode (if exception directory exists)");

    // Check process liveness before DllMain
    {
        NTSTATUS procExitStatus = PsGetProcessExitStatus(targetProc);
        if (procExitStatus != STATUS_PENDING) {
            TRACE("ABORT: Target process died during earlier injection steps! Exit: 0x%X", procExitStatus);
            ZwClose(procHandle);
            ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
            ObDereferenceObject(targetProc);
            Shm->Result = SARAB_ERR_ENTRY_FAILED;
            return STATUS_PROCESS_IS_TERMINATING;
        }
        TRACE("Process alive after exception handler registration, continuing...");
    }

    // ---- Step 9.6: TLS callbacks SKIPPED ----
    // TLS callbacks require LdrpHandleTlsData to be called first to register the
    // module's TLS with the OS. Without it, TLS callbacks crash because TLS slots
    // aren't allocated. The CRT entry point (__DllMainCRTStartup) handles its own
    // TLS initialization internally, so DllMain still works without manual TLS setup.
    // BlackBone confirms: LdrpHandleTlsData must be called before TLS callbacks.
    TRACE("TLS callbacks skipped (requires LdrpHandleTlsData which is not implemented)");

    // ---- Step 9.7: Initialize security cookie ----
    // MSVC CRT uses __security_cookie for buffer overflow protection.
    // If the cookie is left as the default value (0x2B992DDFA232 / 0xBB40E64E),
    // any function that checks it will trigger __security_check_cookie → fast_fail.
    // BlackBone's InitializeCookie does the same thing.
    {
        ULONG loadConfigRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
        ULONG loadConfigSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
        
        if (loadConfigRva && loadConfigSize) {
            PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfig = 
                (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PUCHAR)localImage + loadConfigRva);
            
            if (pLoadConfig->SecurityCookie) {
                // Calculate the cookie's offset in the mapped image
                // SecurityCookie field contains a VA. After relocations applied to localImage,
                // this VA = remoteBase + originalRVA. Subtract remoteBase to get the RVA.
                // (NOT preferredBase — that only works if no relocations were applied)
                ULONGLONG cookieRva = pLoadConfig->SecurityCookie - (ULONGLONG)remoteBase;
                
                if (cookieRva < imageSize) {
                    // Generate a random cookie value (mimic CRT behavior)
                    LARGE_INTEGER perfCount, sysTime;
                    KeQueryPerformanceCounter(&perfCount);
                    KeQuerySystemTime(&sysTime);
                    
                    ULONGLONG cookie = (ULONGLONG)TargetPID;
                    cookie ^= (ULONGLONG)&cookie;  // stack address entropy
                    cookie ^= sysTime.QuadPart;
                    cookie ^= (perfCount.QuadPart << 32) ^ perfCount.QuadPart;
                    cookie &= 0xFFFFFFFFFFFFULL;  // 48-bit mask like CRT
                    
                    // Make sure it's not the default value
                    if (cookie == 0x2B992DDFA232ULL) cookie++;
                    
                    // Write cookie to the local image (will be copied to remote)
                    // But the image is already written, so write directly to target
                    KAPC_STATE cookieApc;
                    KeStackAttachProcess((PRKPROCESS)targetProc, &cookieApc);
                    
                    __try {
                        PVOID cookieAddr = (PUCHAR)remoteBase + cookieRva;
                        // Change protection to writable
                        PVOID protBase = cookieAddr;
                        SIZE_T protSize = sizeof(ULONGLONG);
                        ULONG oldProt = 0;
                        NTSTATUS protSt = ZwProtectVirtualMemory(
                            ZwCurrentProcess(), &protBase, &protSize, PAGE_READWRITE, &oldProt);
                        
                        if (NT_SUCCESS(protSt)) {
                            *(PULONGLONG)cookieAddr = cookie;
                            // Also write the complement (__security_cookie_complement = ~cookie)
                            // Located right after __security_cookie in most MSVC binaries
                            if (cookieRva + 16 < imageSize) {
                                *((PULONGLONG)cookieAddr + 1) = ~cookie;
                            }
                            ZwProtectVirtualMemory(
                                ZwCurrentProcess(), &protBase, &protSize, oldProt, &oldProt);
                            TRACE("Security cookie initialized at RVA 0x%llX (value 0x%llX)", cookieRva, cookie);
                        } else {
                            TRACE("Could not change protection for security cookie: 0x%X", protSt);
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        TRACE("Exception writing security cookie: 0x%X", GetExceptionCode());
                    }
                    
                    KeUnstackDetachProcess(&cookieApc);
                } else {
                    TRACE("Security cookie RVA 0x%llX out of bounds", cookieRva);
                }
            }
        }
    }

    // ---- Step 10: Execute DllMain via ZwCreateThreadEx or APC ----
    SetStatus(Shm, SARAB_STAGE_EXECUTING, "Executing DllMain...");

    // Check if process is still alive before attempting DllMain
    {
        NTSTATUS procExitStatus = PsGetProcessExitStatus(targetProc);
        if (procExitStatus != STATUS_PENDING) {
            TRACE("ABORT: Target process is terminating (exit status 0x%X) — cannot execute DllMain", procExitStatus);
            TRACE("Process died during earlier injection steps (deps/exception reg/cookie)");
            if (procHandle) { ZwClose(procHandle); procHandle = NULL; }
            ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
            ObDereferenceObject(targetProc);
            Shm->Result = SARAB_ERR_ENTRY_FAILED;
            return STATUS_PROCESS_IS_TERMINATING;
        }
    }

    if (entryPointRva && (g_pZwCreateThreadEx || g_pRtlCreateUserThread)) {
        PVOID entryPoint = (PUCHAR)remoteBase + entryPointRva;
        TRACE("DllMain at 0x%p (RVA 0x%X)", entryPoint, entryPointRva);

        {
            HANDLE threadHandle = NULL;

            __try {
                // DllMain(hinstDLL=remoteBase, fdwReason=DLL_PROCESS_ATTACH(1), lpvReserved=NULL)
                // We use shellcode to call DllMain with proper arguments
                // For simplicity, create thread at entry point with hModule as argument
                // DllMain signature: BOOL DllMain(HINSTANCE, DWORD, LPVOID)
                // Thread start routine signature: DWORD WINAPI ThreadProc(LPVOID)
                // These don't match, but many DLLs handle it gracefully
                // For proper calling, we allocate a small shellcode stub

                // Allocate shellcode in target
                PVOID shellcodeAddr = NULL;
                SIZE_T shellcodeSize = PAGE_SIZE;
                
                // Re-attach for shellcode allocation
                KeStackAttachProcess((PRKPROCESS)targetProc, &apcState);
                attached = TRUE;
                
                status = ZwAllocateVirtualMemory(
                    ZwCurrentProcess(), &shellcodeAddr, 0, &shellcodeSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
                );

                if (NT_SUCCESS(status) && shellcodeAddr) {
                    // Resolve ntdll for RtlAddFunctionTable (exception registration)
                    PVOID ntdllBase2 = FindModuleInProcess(targetProc, "ntdll.dll");
                    if (!ntdllBase2) ntdllBase2 = FindModuleInProcess(targetProc, "NTDLL.DLL");
                    
                    TRACE("DllMain shellcode: ntdll=%p", ntdllBase2);

                    // Get exception directory info (if present)
                    PIMAGE_NT_HEADERS64 ntHeaders2 = GetNtHeaders(localImage);
                    ULONG exceptionDirRva = ntHeaders2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
                    ULONG exceptionDirSize = ntHeaders2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
                    ULONG exceptionEntryCount = exceptionDirSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
                    PVOID pExceptionDir = exceptionDirRva ? (PUCHAR)remoteBase + exceptionDirRva : NULL;

                    // Find RtlAddFunctionTable for exception registration
                    PVOID pRtlAddFuncTable = ntdllBase2 ? GetModuleExport(targetProc, ntdllBase2, "RtlAddFunctionTable") : NULL;
                    
                    BOOLEAN hasExceptions = (pExceptionDir && pRtlAddFuncTable && exceptionEntryCount > 0);
                    TRACE("DllMain shellcode: RtlAddFunctionTable=%p, ExceptionDir=%p, entries=%lu, enabled=%d",
                        pRtlAddFuncTable, pExceptionDir, exceptionEntryCount, hasExceptions);

                    // ================================================================
                    // UNIFIED SHELLCODE — Exception Registration + DllMain + Exit
                    // ================================================================
                    // Architecture validated against 8 reference implementations:
                    //   - GuidedHacking-Injector: compiler-generated shellcode, ret at end
                    //   - TTKKO_Injector: inline RtlAddFunctionTable before DllMain
                    //   - BlackBone: APC-based, no separate thread for exceptions
                    //   - fumo_loader, KMInjector, etc: all skip exception reg entirely
                    //
                    // KEY INSIGHT from GuidedHacking:
                    //   Thread entry does push rbp → sets frame → calls all steps → ret
                    //   NO NtTerminateThread needed. Just ret with exit code 0.
                    //   RtlCreateUserThread handles thread cleanup automatically.
                    //
                    // x64 ABI requirements:
                    //   - RSP must be 16-byte aligned BEFORE call instruction
                    //   - 0x20 shadow space for callees
                    //   - RtlCreateUserThread enters with RSP = 16-byte aligned
                    //     (thread entry is a normal function call target)
                    //
                    // We build TWO shellcode variants:
                    //   A) With exception registration (if .pdata exists)
                    //   B) Without (just DllMain)
                    // ================================================================

                    if (hasExceptions) {
                        // Variant A: RtlAddFunctionTable + DllMain + ret
                        // Thread entry: RSP is 16-byte aligned (pushed by call from OS)
                        // Actually RtlCreateUserThread enters at the start address like
                        // a function call — so we have return address on stack already.
                        // RSP is misaligned by 8 at entry (return addr pushed).
                        UCHAR shellcode[] = {
                            // Prologue — align stack
                            0x48, 0x83, 0xEC, 0x38,             // [0..3]   sub rsp, 0x38 (0x20 shadow + 0x8 align + 0x10 spare)
                            
                            // === RtlAddFunctionTable(pExceptionDir, entryCount, RemoteBase) ===
                            0x48, 0xB9, 0,0,0,0,0,0,0,0,       // [4..13]  mov rcx, imm64     → patch at [6]
                            0xBA, 0,0,0,0,                       // [14..18] mov edx, imm32     → patch at [15]
                            0x49, 0xB8, 0,0,0,0,0,0,0,0,       // [19..28] mov r8, imm64      → patch at [21]
                            0x48, 0xB8, 0,0,0,0,0,0,0,0,       // [29..38] mov rax, imm64     → patch at [31]
                            0xFF, 0xD0,                         // [39..40] call rax

                            // === DllMain(hModule, DLL_PROCESS_ATTACH, NULL) ===
                            0x48, 0xB9, 0,0,0,0,0,0,0,0,       // [41..50] mov rcx, imm64     → patch at [43]
                            0xBA, 0x01, 0x00, 0x00, 0x00,       // [51..55] mov edx, 1
                            0x4D, 0x31, 0xC0,                   // [56..58] xor r8, r8
                            0x48, 0xB8, 0,0,0,0,0,0,0,0,       // [59..68] mov rax, imm64     → patch at [61]
                            0xFF, 0xD0,                         // [69..70] call rax

                            // Epilogue — clean return (OS handles thread cleanup)
                            0x48, 0x83, 0xC4, 0x38,             // [71..74] add rsp, 0x38
                            0x48, 0x31, 0xC0,                   // [75..77] xor rax, rax
                            0xC3                                // [78]     ret
                        };

                        // Patch addresses (offsets verified by manual byte counting above)
                        *(PULONGLONG)&shellcode[6]  = (ULONGLONG)pExceptionDir;        // rcx = pExceptionDir
                        *(PULONG)&shellcode[15]     = exceptionEntryCount;              // edx = entryCount
                        *(PULONGLONG)&shellcode[21] = (ULONGLONG)remoteBase;            // r8  = RemoteBase
                        *(PULONGLONG)&shellcode[31] = (ULONGLONG)pRtlAddFuncTable;     // rax = RtlAddFunctionTable
                        *(PULONGLONG)&shellcode[43] = (ULONGLONG)remoteBase;            // rcx = hModule
                        *(PULONGLONG)&shellcode[61] = (ULONGLONG)entryPoint;            // rax = DllMain

                        TRACE("Shellcode variant A (exceptions+DllMain): %d bytes", (int)sizeof(shellcode));

                        __try {
                            RtlCopyMemory(shellcodeAddr, shellcode, sizeof(shellcode));
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            TRACE("Exception writing shellcode: 0x%X", GetExceptionCode());
                        }
                    } else {
                        // Variant B: DllMain only (no exception directory)
                        UCHAR shellcode[] = {
                            // Prologue
                            0x48, 0x83, 0xEC, 0x28,             // [0..3]   sub rsp, 0x28 (0x20 shadow + 0x8 align)

                            // === DllMain(hModule, DLL_PROCESS_ATTACH, NULL) ===
                            0x48, 0xB9, 0,0,0,0,0,0,0,0,       // [4..13]  mov rcx, imm64     → patch at [6]
                            0xBA, 0x01, 0x00, 0x00, 0x00,       // [14..18] mov edx, 1
                            0x4D, 0x31, 0xC0,                   // [19..21] xor r8, r8
                            0x48, 0xB8, 0,0,0,0,0,0,0,0,       // [22..31] mov rax, imm64     → patch at [24]
                            0xFF, 0xD0,                         // [32..33] call rax

                            // Epilogue
                            0x48, 0x83, 0xC4, 0x28,             // [34..37] add rsp, 0x28
                            0x48, 0x31, 0xC0,                   // [38..40] xor rax, rax
                            0xC3                                // [41]     ret
                        };

                        // Patch addresses (offsets verified by manual byte counting above)
                        *(PULONGLONG)&shellcode[6]  = (ULONGLONG)remoteBase;    // rcx = hModule
                        *(PULONGLONG)&shellcode[24] = (ULONGLONG)entryPoint;    // rax = DllMain

                        TRACE("Shellcode variant B (DllMain only): %d bytes", (int)sizeof(shellcode));

                        __try {
                            RtlCopyMemory(shellcodeAddr, shellcode, sizeof(shellcode));
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            TRACE("Exception writing shellcode: 0x%X", GetExceptionCode());
                        }
                    }

                    KeUnstackDetachProcess(&apcState);
                    attached = FALSE;

                    // Create thread to run shellcode — use wrapper with automatic fallback
                    TRACE("Creating thread at shellcode 0x%p", shellcodeAddr);

                    NTSTATUS threadSt = CreateUserThreadWrapper(procHandle, shellcodeAddr, NULL, &threadHandle);

                    if (NT_SUCCESS(threadSt) && threadHandle) {
                        TRACE("Thread created successfully, waiting for DllMain...");

                        // Wait for thread to complete properly (max 30 seconds)
                        PVOID threadObj = NULL;
                        NTSTATUS waitSt = ObReferenceObjectByHandle(
                            threadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, &threadObj, NULL);
                        if (NT_SUCCESS(waitSt) && threadObj) {
                            LARGE_INTEGER waitTimeout;
                            waitTimeout.QuadPart = -300000000LL; // 30 seconds
                            waitSt = KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, &waitTimeout);
                            ObDereferenceObject(threadObj);
                            if (waitSt == STATUS_TIMEOUT) {
                                TRACE("DllMain timed out after 30s (may still be running)");
                            } else {
                                TRACE("DllMain thread completed (status 0x%X)", waitSt);
                            }
                        } else {
                            // Fallback: just wait 5 seconds
                            LARGE_INTEGER delay;
                            delay.QuadPart = -50000000LL;
                            KeDelayExecutionThread(KernelMode, FALSE, &delay);
                        }

                        ZwClose(threadHandle);
                        TRACE("DllMain execution initiated");

                        // Free the shellcode memory in target process
                        {
                            KAPC_STATE scApc;
                            KeStackAttachProcess((PRKPROCESS)targetProc, &scApc);
                            SIZE_T freeSz = 0;
                            ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcodeAddr, &freeSz, MEM_RELEASE);
                            KeUnstackDetachProcess(&scApc);
                            TRACE("DllMain shellcode freed from target");
                        }

                        // Success
                        Shm->MappedBase = (ULONGLONG)remoteBase;
                        Shm->Result = SARAB_OK;
                    } else if (threadHandle) {
                        // Thread created but wait/execution tracking failed
                        ZwClose(threadHandle);
                        Shm->MappedBase = (ULONGLONG)remoteBase;
                        Shm->Result = SARAB_OK;
                    } else {
                        // Thread creation failed entirely
                        TRACE("Thread creation failed: 0x%X (ZwCreateThreadEx=%p, RtlCreateUserThread=%p)",
                            threadSt, g_pZwCreateThreadEx, g_pRtlCreateUserThread);
                        Shm->Result = SARAB_ERR_ENTRY_FAILED;
                    }
                } else {
                    TRACE("Failed to allocate shellcode: 0x%X", status);
                    if (attached) {
                        KeUnstackDetachProcess(&apcState);
                        attached = FALSE;
                    }
                    Shm->Result = SARAB_ERR_ENTRY_FAILED;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                TRACE("Exception during thread creation: 0x%X", GetExceptionCode());
                if (attached) {
                    KeUnstackDetachProcess(&apcState);
                    attached = FALSE;
                }
                Shm->Result = SARAB_ERR_EXCEPTION;
            }

        }
    } else {
        // No entry point - just map without executing
        TRACE("No entry point or ZwCreateThreadEx unavailable - mapped without execution");
        Shm->MappedBase = (ULONGLONG)remoteBase;
        Shm->Result = SARAB_OK;
    }

    if (procHandle) {
        ZwClose(procHandle);
        procHandle = NULL;
    }

    // ---- Step 11: Erase PE headers AFTER DllMain has completed ----
    // Now that CRT is initialized and DllMain has run, we can safely erase headers
    SetStatus(Shm, SARAB_STAGE_CLEANUP, "Erasing PE headers...");
    {
        KAPC_STATE headerApc;
        KeStackAttachProcess((PRKPROCESS)targetProc, &headerApc);
        
        // Change protection to RW so we can zero the memory
        PVOID headerBase = remoteBase;
        SIZE_T headerRegion = min(headerSize, (ULONG)PAGE_SIZE);
        ULONG oldProtect = 0;
        
        NTSTATUS protSt = ZwProtectVirtualMemory(
            ZwCurrentProcess(), &headerBase, &headerRegion, PAGE_READWRITE, &oldProtect);
        
        if (NT_SUCCESS(protSt)) {
            __try {
                RtlZeroMemory(remoteBase, min(headerSize, (ULONG)PAGE_SIZE));
                TRACE("PE headers erased from target (post-DllMain)");
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                TRACE("Exception erasing headers: 0x%X", GetExceptionCode());
            }
            
            // Set to PAGE_NOACCESS to hide the headers completely
            ZwProtectVirtualMemory(
                ZwCurrentProcess(), &headerBase, &headerRegion, PAGE_NOACCESS, &oldProtect);
        } else {
            TRACE("Could not change header protection for erasure: 0x%X", protSt);
        }
        
        KeUnstackDetachProcess(&headerApc);
    }

    // Cleanup
    if (attached) {
        KeUnstackDetachProcess(&apcState);
    }

    ExFreePoolWithTag(localImage, SARAB_POOL_TAG);
    ObDereferenceObject(targetProc);

    if (Shm->Result == SARAB_OK) {
        SetStatus(Shm, SARAB_STAGE_DONE, "Injection complete!");
    }

    return (Shm->Result == SARAB_OK) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


// ============================================================================
// WORKER THREAD — Polls shared memory for commands
// ============================================================================
static void WorkerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    TRACE("Worker thread started — entering command poll loop");

    while (TRUE) {
        // Check stop event
        if (KeReadStateEvent(&g_StopEvent)) {
            TRACE("Stop event signaled, exiting");
            break;
        }

        // Verify shared memory pointer
        if (!g_SharedMem) {
            LARGE_INTEGER interval;
            interval.QuadPart = -100000; // 10ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            continue;
        }

        __try {
            PSARAB_SHARED_DATA shm = (PSARAB_SHARED_DATA)g_SharedMem;

            // Check for command (interlocked provides full memory barrier)
            long state = InterlockedCompareExchange(&shm->CmdState, SARAB_CMD_READY, SARAB_CMD_READY);
            if (state != SARAB_CMD_READY) {
                LARGE_INTEGER interval;
                interval.QuadPart = -100000; // 10ms
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
                continue;
            }

            // Read command fields (barrier from InterlockedCompareExchange above)
            int opType = shm->OpType;
            int targetPid = shm->TargetPID;
            int dllSize = shm->DllSize;

            TRACE("Command received: OpType=%d PID=%d DllSize=%d", opType, targetPid, dllSize);

            switch (opType) {
                case SARAB_OP_PING:
                    TRACE("Ping received");
                    shm->Result = SARAB_OK;
                    RtlStringCbCopyA(shm->StatusMsg, sizeof(shm->StatusMsg), "Driver alive");
                    break;

                case SARAB_OP_INJECT: {
                    TRACE("Injection command: PID=%d, DllSize=%d", targetPid, dllSize);

                    if (targetPid <= 0 || targetPid > 0xFFFF) {
                        shm->Result = SARAB_ERR_INVALID_PID;
                        SetStatus(shm, 0, "Invalid PID");
                        break;
                    }

                    if (dllSize <= 0 || dllSize > SARAB_MAX_DLL_SIZE) {
                        shm->Result = SARAB_ERR_INVALID_PE;
                        SetStatus(shm, 0, "Invalid DLL size");
                        break;
                    }

                    // Copy DLL to non-paged kernel buffer
                    PVOID dllCopy = ExAllocatePoolWithTag(NonPagedPool, dllSize, SARAB_POOL_TAG);
                    if (!dllCopy) {
                        shm->Result = SARAB_ERR_ALLOC_FAILED;
                        SetStatus(shm, 0, "Kernel allocation failed");
                        break;
                    }

                    RtlCopyMemory(dllCopy, shm->DllData, dllSize);

                    // Execute kernel manual map
                    KernelManualMap(targetPid, dllCopy, dllSize, shm);

                    ExFreePoolWithTag(dllCopy, SARAB_POOL_TAG);
                    break;
                }

                case SARAB_OP_STATUS:
                    break;

                default:
                    TRACE("Unknown OpType: %d", opType);
                    shm->Result = SARAB_ERR_EXCEPTION;
                    break;
            }

            // Signal completion
            InterlockedExchange(&shm->CmdState, SARAB_CMD_DONE);
            TRACE("Command complete, result=%d", shm->Result);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TRACE("Exception in worker thread: 0x%X", GetExceptionCode());
            // Sleep longer after exception to avoid tight crash loop
            LARGE_INTEGER interval;
            interval.QuadPart = -10000000; // 1 second
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
    }

    TRACE("Worker thread exiting");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// SHARED MEMORY SETUP
// ============================================================================
static NTSTATUS CreateSharedMemory() {
    UNICODE_STRING sectionName;
    RtlInitUnicodeString(&sectionName, SARAB_SHM_NAME);

    // NULL DACL — allows any process (including non-admin) full access
    SECURITY_DESCRIPTOR sd;
    RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);

    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = SARAB_SHM_SIZE;

    NTSTATUS status = ZwCreateSection(
        &g_SectionHandle,
        SECTION_ALL_ACCESS,
        &objAttr,
        &sectionSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    // Handle stale section from a previous driver load that wasn't cleaned up
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        TRACE("Section already exists — opening stale section");
        status = ZwOpenSection(&g_SectionHandle, SECTION_ALL_ACCESS, &objAttr);
    }

    if (!NT_SUCCESS(status)) {
        TRACE("ZwCreateSection/ZwOpenSection failed: 0x%X", status);
        return status;
    }

    // Convert section handle to object pointer for MmMapViewInSystemSpace
    status = ObReferenceObjectByHandle(
        g_SectionHandle, SECTION_ALL_ACCESS, NULL, KernelMode, &g_SectionObject, NULL);
    if (!NT_SUCCESS(status)) {
        TRACE("ObReferenceObjectByHandle failed: 0x%X", status);
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    // Map into KERNEL (system) address space — NOT user space!
    // ZwMapViewOfSection maps into user space of current process (System) and
    // system threads BSOD when accessing user-space addresses (bugcheck 0x1a/4477).
    // MmMapViewInSystemSpace maps into the high kernel VA range (0xFFFF...) which
    // is accessible from any thread context without page faults.
    SIZE_T viewSize = SARAB_SHM_SIZE;
    status = MmMapViewInSystemSpace(g_SectionObject, &g_SharedMem, &viewSize);

    if (!NT_SUCCESS(status)) {
        TRACE("MmMapViewInSystemSpace failed: 0x%X", status);
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    // Initialize and stamp magic — usermode checks this to verify driver is live
    __try {
        RtlZeroMemory(g_SharedMem, SARAB_SHM_SIZE);
        PSARAB_SHARED_DATA shm = (PSARAB_SHARED_DATA)g_SharedMem;
        shm->Magic = SARAB_MAGIC;
        shm->CmdState = SARAB_CMD_NONE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("Exception initializing shared memory: 0x%X", GetExceptionCode());
    }

    TRACE("Shared memory ready: %p (kernel VA), size=0x%llX, magic=0x%X",
          g_SharedMem, (ULONGLONG)viewSize, SARAB_MAGIC);
    return STATUS_SUCCESS;
}

// ============================================================================
// MANUAL KERNEL EXPORT RESOLUTION — fallback when MmGetSystemRoutineAddress fails
// ============================================================================
static PVOID FindKernelExport(const char* FuncName) {
    // Get ntoskrnl base address by passing a known exported function to RtlPcToFileHeader
    PVOID ntBase = NULL;
    RtlPcToFileHeader((PVOID)IoGetCurrentProcess, &ntBase);
    if (!ntBase) {
        TRACE("FindKernelExport: RtlPcToFileHeader failed, trying PsGetProcessId...");
        RtlPcToFileHeader((PVOID)PsGetProcessId, &ntBase);
    }
    if (!ntBase) {
        TRACE("FindKernelExport: Cannot determine ntoskrnl base!");
        return NULL;
    }

    TRACE("FindKernelExport: ntoskrnl base = %p, searching for '%s'", ntBase, FuncName);

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            TRACE("FindKernelExport: Bad DOS signature");
            return NULL;
        }

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ntBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            TRACE("FindKernelExport: Bad NT signature");
            return NULL;
        }

        ULONG exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportRva || !exportSize) {
            TRACE("FindKernelExport: No export directory");
            return NULL;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntBase + exportRva);
        PULONG nameRvas = (PULONG)((PUCHAR)ntBase + exportDir->AddressOfNames);
        PUSHORT ordinals = (PUSHORT)((PUCHAR)ntBase + exportDir->AddressOfNameOrdinals);
        PULONG funcRvas = (PULONG)((PUCHAR)ntBase + exportDir->AddressOfFunctions);

        TRACE("FindKernelExport: Export directory has %u named exports", exportDir->NumberOfNames);

        BOOLEAN foundNearby = FALSE;
        for (ULONG i = 0; i < exportDir->NumberOfNames; i++) {
            const char* name = (const char*)((PUCHAR)ntBase + nameRvas[i]);

            if (strcmp(name, FuncName) == 0) {
                ULONG funcRva = funcRvas[ordinals[i]];
                PVOID func = (PVOID)((PUCHAR)ntBase + funcRva);
                TRACE("FindKernelExport: FOUND %s at %p (RVA 0x%X)", FuncName, func, funcRva);
                return func;
            }

            // Log nearby Zw* exports for diagnostics (only first time)
            if (!foundNearby && name[0] == 'Z' && name[1] == 'w' && name[2] == 'C' && name[3] == 'r') {
                TRACE("FindKernelExport: Nearby export: %s", name);
                foundNearby = TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TRACE("FindKernelExport: Exception: 0x%X", GetExceptionCode());
    }

    TRACE("FindKernelExport: '%s' NOT found in %u exports", FuncName,
        ((PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntBase +
        ((PIMAGE_NT_HEADERS64)((PUCHAR)ntBase +
        ((PIMAGE_DOS_HEADER)ntBase)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))->NumberOfNames);
    return NULL;
}

// ============================================================================
// DRIVER ENTRY & UNLOAD
// ============================================================================
extern "C" NTSTATUS DriverEntry(PVOID lpBaseAddress, PVOID lpDbgBuffer) {
    UNREFERENCED_PARAMETER(lpBaseAddress);
    UNREFERENCED_PARAMETER(lpDbgBuffer);

    TRACE("=== SARAB Kernel Driver v3.0 ===");

    // Initialize synchronization
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);

    // Resolve ZwCreateThreadEx — try multiple methods
    UNICODE_STRING routineName;

    // Method 1: MmGetSystemRoutineAddress (standard API)
    RtlInitUnicodeString(&routineName, L"ZwCreateThreadEx");
    g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&routineName);
    if (g_pZwCreateThreadEx) {
        TRACE("ZwCreateThreadEx resolved via MmGetSystemRoutineAddress at %p", g_pZwCreateThreadEx);
    } else {
        RtlInitUnicodeString(&routineName, L"NtCreateThreadEx");
        g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&routineName);
        if (g_pZwCreateThreadEx) {
            TRACE("NtCreateThreadEx resolved via MmGetSystemRoutineAddress at %p", g_pZwCreateThreadEx);
        } else {
            TRACE("MmGetSystemRoutineAddress failed for both Zw/NtCreateThreadEx");
        }
    }

    // Method 2: Manual ntoskrnl PE export table walk (bypasses MmGetSystemRoutineAddress)
    if (!g_pZwCreateThreadEx) {
        TRACE("Trying manual ntoskrnl export table walk...");
        g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)FindKernelExport("ZwCreateThreadEx");
        if (!g_pZwCreateThreadEx) {
            g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)FindKernelExport("NtCreateThreadEx");
        }
        if (g_pZwCreateThreadEx) {
            TRACE("ZwCreateThreadEx resolved via manual export walk at %p", g_pZwCreateThreadEx);
        }
    }

    if (!g_pZwCreateThreadEx) {
        TRACE("CRITICAL: All methods failed to find ZwCreateThreadEx!");
        TRACE("Will try RtlCreateUserThread fallback for DllMain/TLS execution");

        // Try RtlCreateUserThread as final fallback (ntdll export, always available)
        g_pRtlCreateUserThread = (fn_RtlCreateUserThread)FindKernelExport("RtlCreateUserThread");
        if (g_pRtlCreateUserThread) {
            TRACE("RtlCreateUserThread resolved at %p (fallback)", g_pRtlCreateUserThread);
        } else {
            TRACE("CRITICAL: RtlCreateUserThread also not found!");
            TRACE("DllMain execution will be unavailable");
        }
    }

    // Try to resolve RtlInsertInvertedFunctionTable (used for exception registration)
    RtlInitUnicodeString(&routineName, L"RtlInsertInvertedFunctionTable");
    g_pRtlInsertInvFuncTable = (fn_RtlInsertInvertedFunctionTable)MmGetSystemRoutineAddress(&routineName);
    if (g_pRtlInsertInvFuncTable) {
        TRACE("RtlInsertInvertedFunctionTable resolved at %p", g_pRtlInsertInvFuncTable);
    } else {
        TRACE("RtlInsertInvertedFunctionTable not found (will use RtlAddFunctionTable fallback)");
    }

    // Create shared memory
    NTSTATUS status = CreateSharedMemory();
    if (!NT_SUCCESS(status)) {
        TRACE("Failed to create shared memory: 0x%X", status);
        return STATUS_SUCCESS; // Return success so driver stays loaded for debugging
    }

    // Launch worker thread
    HANDLE threadHandle = NULL;
    status = PsCreateSystemThread(
        &threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL,
        WorkerThread, NULL
    );

    if (NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        TRACE("Worker thread launched");
    } else {
        TRACE("Failed to create worker thread: 0x%X", status);
    }

    TRACE("Driver initialization complete");
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverUnload(PVOID lpBaseAddress, PVOID lpDbgBuffer) {
    UNREFERENCED_PARAMETER(lpBaseAddress);
    UNREFERENCED_PARAMETER(lpDbgBuffer);

    TRACE("Driver unloading...");

    // Signal worker thread to stop
    KeSetEvent(&g_StopEvent, 0, FALSE);

    // Wait for thread to exit
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30000000; // 3 seconds
    KeDelayExecutionThread(KernelMode, FALSE, &timeout);

    // Cleanup shared memory
    if (g_SharedMem) {
        MmUnmapViewInSystemSpace(g_SharedMem);
        g_SharedMem = NULL;
    }
    if (g_SectionObject) {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
    }
    if (g_SectionHandle) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }

    TRACE("Driver unloaded");
    return STATUS_SUCCESS;
}
