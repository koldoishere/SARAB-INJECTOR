#pragma once

// ============================================================================
// SARAB Kernel Driver — Shared Protocol Header
// Used by BOTH kernel driver and usermode controller
// ============================================================================

#define SARAB_SHM_NAME      L"\\BaseNamedObjects\\Global\\SarabShm"
#define SARAB_SHM_NAME_UM   "Global\\SarabShm"
#define SARAB_SHM_SIZE      0x1000000  // 16MB shared memory (for DLL transfer)
#define SARAB_MAX_DLL_SIZE  0xFF0000   // Max DLL size (~16MB minus header)
#define SARAB_POOL_TAG      'barS'
#define SARAB_MAGIC         0x53415242   // "SARB" — driver writes this, usermode verifies

// Command IDs
#define SARAB_CMD_NONE      0
#define SARAB_CMD_READY     1    // Usermode has written a command
#define SARAB_CMD_DONE      2    // Kernel has finished processing

// Operation types
#define SARAB_OP_PING       0    // Liveness check
#define SARAB_OP_INJECT     1    // Full kernel manual-map injection
#define SARAB_OP_STATUS     2    // Query injection status

// Injection result codes
#define SARAB_OK                    0
#define SARAB_ERR_INVALID_PID       1
#define SARAB_ERR_PROCESS_NOT_FOUND 2
#define SARAB_ERR_INVALID_PE        3
#define SARAB_ERR_ALLOC_FAILED      4
#define SARAB_ERR_RELOC_FAILED      5
#define SARAB_ERR_IMPORT_FAILED     6
#define SARAB_ERR_MAP_FAILED        7
#define SARAB_ERR_ENTRY_FAILED      8
#define SARAB_ERR_EXCEPTION         9
#define SARAB_ERR_TIMEOUT           10
#define SARAB_ERR_MODULE_NOT_FOUND  11

// Progress stages (written to Status.Progress as injection proceeds)
#define SARAB_STAGE_IDLE            0
#define SARAB_STAGE_PARSING         10
#define SARAB_STAGE_ALLOCATING      20
#define SARAB_STAGE_MAPPING         40
#define SARAB_STAGE_RELOCATING      60
#define SARAB_STAGE_IMPORTS         70
#define SARAB_STAGE_PROTECTING      80
#define SARAB_STAGE_EXECUTING       90
#define SARAB_STAGE_CLEANUP         95
#define SARAB_STAGE_DONE            100

#pragma pack(push, 1)
typedef struct _SARAB_SHARED_DATA {
    unsigned int   Magic;          // Must be SARAB_MAGIC when driver is live
    volatile long  CmdState;       // SARAB_CMD_*
    int            OpType;         // SARAB_OP_*
    int            TargetPID;      // Target process ID
    int            DllSize;        // Size of DLL data in DllData[]
    int            Result;         // SARAB_OK or SARAB_ERR_*
    int            Progress;       // 0-100 progress percentage
    unsigned long long MappedBase; // Base address where DLL was mapped
    char           StatusMsg[256]; // Human-readable status message
    unsigned char  DllData[1];     // Variable-length DLL file data (up to SARAB_MAX_DLL_SIZE)
} SARAB_SHARED_DATA, *PSARAB_SHARED_DATA;
#pragma pack(pop)
