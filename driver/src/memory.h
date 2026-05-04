/* безликий */
#pragma once

#include <ntifs.h>

// Forward declaration for MmCopyVirtualMemory (not in standard headers)
typedef NTSTATUS(NTAPI *PMmCopyVirtualMemory)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T,
                                              KPROCESSOR_MODE, PSIZE_T);

// Global pointer to MmCopyVirtualMemory, resolved at runtime
extern PMmCopyVirtualMemory g_MmCopy;

// Define a pool tag for allocations
#define POOL_TAG_SCAN 'SCAN'

NTSTATUS Vx_Init(void);

NTSTATUS Vx_Attach(HANDLE pid, PEPROCESS *proc, KAPC_STATE *apc);
void Vx_Detach(PEPROCESS proc, KAPC_STATE *apc);

NTSTATUS Vx_Read(HANDLE pid, UINT64 address, PVOID buffer, ULONG length);
NTSTATUS Vx_Write(HANDLE pid, UINT64 address, PVOID buffer, ULONG length);
NTSTATUS Vx_Translate(HANDLE pid, UINT64 va, UINT64 *pa);
UINT64 Vx_GetCr3(PEPROCESS proc);
