/* безликий */
#include "dispatch.h"
#include "globals.h"
#include <stddef.h>
#include "memory.h"
#include "dkom.h"
#include "sysinfo.h"
#include "ntdefs.h"

// g_MmCopy is declared in memory.h and defined in memory.c
extern PMmCopyVirtualMemory g_MmCopy;

static void write_response(PVOID buffer, UINT32 status_code, UINT64 value)
{
    DX_RSP *resp = (DX_RSP *)buffer;
    resp->magic  = NX_MAGIC;
    resp->status = status_code;
    resp->value  = value;
}

static NTSTATUS handle_ping(PVOID buffer)
{
    write_response(buffer, 0, (UINT64)NX_SEED);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_read_memory(PVOID buffer, ULONG size)
{
    DX_READ *req = (DX_READ *)buffer;
    if (size < sizeof(DX_READ)) return STATUS_INVALID_PARAMETER;
    if (req->length > DX_BUF_SIZE - offsetof(DX_RSP, data))
        return STATUS_INVALID_PARAMETER;

    DX_RSP *resp    = (DX_RSP *)buffer;
    NTSTATUS status = Vx_Read((HANDLE)(ULONG_PTR)req->pid, req->address, resp->data,
                              req->length);

    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, req->length);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_write_memory(PVOID buffer, ULONG size)
{
    DX_WRITE *req = (DX_WRITE *)buffer;
    if (size < offsetof(DX_WRITE, data)) return STATUS_INVALID_PARAMETER;
    if (req->length > size - offsetof(DX_WRITE, data)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Vx_Write((HANDLE)(ULONG_PTR)req->pid, req->address, req->data,
                               req->length);

    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, req->length);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_get_module_base(PVOID buffer, ULONG size)
{
    DX_MODBASE *req = (DX_MODBASE *)buffer;
    if (size < sizeof(DX_MODBASE)) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc;
    KAPC_STATE apc;
    if (!NT_SUCCESS(Vx_Attach((HANDLE)(ULONG_PTR)req->pid, &proc, &apc))) {
        write_response(buffer, 1, 0);
        return STATUS_SUCCESS;
    }

    UINT64 result = 0;

    __try {
        // Detect if process is WOW64 (32-bit on 64-bit OS)
        PVOID wow64_peb = PsGetProcessWow64Process(proc);
        UINT64 peb_addr = 0;

        if (wow64_peb) {
            // Use the 32-bit PEB for WOW64 processes (HL.EXE)
            // In WOW64, the PEB32 pointer is stored directly in the Wow64Process slot
            peb_addr = (UINT64)wow64_peb;
        } else {
            // Standard 64-bit PEB
            peb_addr = *(UINT64 *)((UCHAR *)proc + g_Offsets.eprocess_peb);
        }

        if (!peb_addr) goto done;

        // For WOW64, we need to handle PEB32 structures or simply use the fact 
        // that the Ldr logic is similar. However, for hl.exe, 
        // the easiest way is to use the ImageBase directly from EPROCESS for the main module.
        if (req->module_name[0] == L'\0' || _wcsicmp(req->module_name, L"hl.exe") == 0) {
            result = (UINT64)PsGetProcessSectionBaseAddress(proc);
            goto done;
        }

        // Fallback to list traversal (Simplified for 64-bit list)
        PEB64 peb;
        if (!NT_SUCCESS(Vx_Read((HANDLE)(ULONG_PTR)req->pid, peb_addr, &peb, sizeof(peb)))) goto done;
        if (!peb.Ldr) goto done;

        PEB_LDR_DATA ldr;
        if (!NT_SUCCESS(Vx_Read((HANDLE)(ULONG_PTR)req->pid, peb.Ldr, &ldr, sizeof(ldr)))) goto done;

        UINT64 head_addr = peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList);
        UINT64 cur_addr  = (UINT64)(ULONG_PTR)ldr.InLoadOrderModuleList.Flink;

        for (ULONG i = 0; i < 256 && cur_addr != head_addr; i++) {
            LDR_DATA_TABLE_ENTRY64 entry;
            if (!NT_SUCCESS(Vx_Read((HANDLE)(ULONG_PTR)req->pid, cur_addr, &entry, sizeof(entry)))) goto done;

            if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
                WCHAR name[128];
                RtlZeroMemory(name, sizeof(name));
                USHORT copy_len = min(entry.BaseDllName.Length, sizeof(name) - 2);
                Vx_Read((HANDLE)(ULONG_PTR)req->pid, (UINT64)(ULONG_PTR)entry.BaseDllName.Buffer, name, copy_len);

                UNICODE_STRING us_name, us_target;
                RtlInitUnicodeString(&us_name, name);
                RtlInitUnicodeString(&us_target, req->module_name);
                if (RtlEqualUnicodeString(&us_name, &us_target, TRUE)) {
                    result = entry.DllBase;
                    goto done;
                }
            }
            cur_addr = (UINT64)(ULONG_PTR)entry.InLoadOrderLinks.Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

done:
    Vx_Detach(proc, &apc);
    write_response(buffer, result ? 0 : 1, result);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_get_peb(PVOID buffer, ULONG size)
{
    DX_PEB *req = (DX_PEB *)buffer;
    if (size < sizeof(DX_PEB)) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = Sx_FindProcess((HANDLE)(ULONG_PTR)req->pid);
    if (!proc) {
        write_response(buffer, 1, 0);
        return STATUS_SUCCESS;
    }

    UINT64 peb = *(UINT64 *)((UCHAR *)proc + g_Offsets.eprocess_peb);
    ObDereferenceObject(proc);

    write_response(buffer, peb ? 0 : 1, peb);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_hide_process(PVOID buffer, ULONG size)
{
    DX_HIDE *req = (DX_HIDE *)buffer;
    if (size < sizeof(DX_HIDE)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Ox_HideProcess((HANDLE)(ULONG_PTR)req->pid);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_unhide_process(PVOID buffer, ULONG size)
{
    DX_HIDE *req = (DX_HIDE *)buffer;
    if (size < sizeof(DX_HIDE)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Ox_UnhideProcess((HANDLE)(ULONG_PTR)req->pid);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_translate_va(PVOID buffer, ULONG size)
{
    DX_XLATE *req = (DX_XLATE *)buffer;
    if (size < sizeof(DX_XLATE)) return STATUS_INVALID_PARAMETER;

    UINT64 pa       = 0;
    NTSTATUS status = Vx_Translate((HANDLE)(ULONG_PTR)req->pid, req->address, &pa);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, pa);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_query_state(PVOID buffer)
{
    write_response(buffer, 0, (UINT64)InterlockedOr(&g_Initialized, 0));
    return STATUS_SUCCESS;
}

// Helper function for pattern matching
static BOOLEAN pattern_compare(const UCHAR *data, const UCHAR *pattern, const UCHAR *mask, ULONG length) {
    for (ULONG i = 0; i < length; i++) {
        if ((data[i] & mask[i]) != (pattern[i] & mask[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

static NTSTATUS handle_pattern_scan(PVOID buffer, ULONG size)
{
    DX_PATTERN_SCAN *req = (DX_PATTERN_SCAN *)buffer;
    if (size < sizeof(DX_PATTERN_SCAN) || req->pattern_length == 0 || req->pattern_length > 256) {
        write_response(buffer, 1, 0);
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS proc;
    KAPC_STATE apc;
    if (!NT_SUCCESS(Vx_Attach((HANDLE)(ULONG_PTR)req->pid, &proc, &apc))) {
        write_response(buffer, 1, 0);
        return STATUS_SUCCESS;
    }

    UINT64 found_address = 0;
    UINT64 current_address = req->start_address;
    UINT64 end_address = req->start_address + req->scan_length;
    PEPROCESS current_proc = PsGetCurrentProcess();

    // Read in chunks to avoid reading too much at once and handle page boundaries
    const ULONG CHUNK_SIZE = 0x1000; // 4KB
    PUCHAR chunk_buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, CHUNK_SIZE, POOL_TAG_SCAN);
    if (!chunk_buffer) {
        Vx_Detach(proc, &apc); // Use the wrapper function
        write_response(buffer, 1, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        while (current_address < end_address) {
            ULONG bytes_to_read = (ULONG)min(CHUNK_SIZE, end_address - current_address);
            SIZE_T bytes_moved = 0;
            
            NTSTATUS status = g_MmCopy(proc, (PVOID)(ULONG_PTR)current_address, current_proc,
                                     chunk_buffer, (SIZE_T)bytes_to_read, KernelMode, &bytes_moved);
            
            if (!NT_SUCCESS(status)) {
                // Could be a non-readable page, skip this chunk
                current_address += bytes_to_read;
                continue;
            }

            // Scan within the chunk
            for (ULONG i = 0; i < bytes_to_read; i++) {
                if (i + req->pattern_length <= bytes_to_read) { // Ensure enough bytes for full pattern
                    if (pattern_compare(chunk_buffer + i, req->pattern, req->mask, req->pattern_length)) {
                        found_address = current_address + i;
                        goto done;
                    }
                }
            }
            current_address += bytes_to_read;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

done:
    ExFreePoolWithTag(chunk_buffer, POOL_TAG_SCAN); // Use the defined POOL_TAG_SCAN
    Vx_Detach(proc, &apc); // Use the wrapper function
    write_response(buffer, found_address ? 0 : 1, found_address);
    return STATUS_SUCCESS;
}

NTSTATUS Dx_Route(PVOID user_buffer, ULONG size)
{
    if (size < sizeof(DX_HDR) || size > DX_BUF_SIZE) return STATUS_INVALID_PARAMETER;

    // 1. Reservar un buffer seguro en el NonPagedPool del Kernel
    PVOID kernel_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, POOL_TAG_COMMS); // Corrected tag
    if (!kernel_buffer) return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T bytes_moved = 0;
    PEPROCESS current_proc = PsGetCurrentProcess();

    // 2. Copiar de forma segura la petición de Usuario -> Kernel
    NTSTATUS status = g_MmCopy( // Use the function pointer
        current_proc, user_buffer,
        current_proc, kernel_buffer,
        size, KernelMode, &bytes_moved
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(kernel_buffer, POOL_TAG_COMMS);
        return status;
    }

    DX_HDR *hdr = (DX_HDR *)kernel_buffer;
    if (hdr->magic != NX_MAGIC) {
        ExFreePoolWithTag(kernel_buffer, POOL_TAG_COMMS);
        return STATUS_ACCESS_DENIED;
    }

    if (hdr->cmd >= CMD_MAX) {
        write_response(kernel_buffer, 1, 0);
        goto copy_out;
    }

    // 3. Procesar el comando usando el buffer de Kernel
    switch (hdr->cmd) {
    case CMD_PING: status = handle_ping(kernel_buffer); break;
    case CMD_READ_MEMORY: status = handle_read_memory(kernel_buffer, size); break;
    case CMD_WRITE_MEMORY: status = handle_write_memory(kernel_buffer, size); break;
    case CMD_GET_MODULE_BASE: status = handle_get_module_base(kernel_buffer, size); break;
    case CMD_GET_PEB: status = handle_get_peb(kernel_buffer, size); break;
    case CMD_HIDE_PROCESS: status = handle_hide_process(kernel_buffer, size); break;
    case CMD_UNHIDE_PROCESS: status = handle_unhide_process(kernel_buffer, size); break;
    case CMD_HIDE_DRIVER: write_response(kernel_buffer, 1, 0); status = STATUS_SUCCESS; break;
    case CMD_TRANSLATE_VA: status = handle_translate_va(kernel_buffer, size); break;
    case CMD_QUERY_STATE: status = handle_query_state(kernel_buffer); break;
    case CMD_PATTERN_SCAN: status = handle_pattern_scan(kernel_buffer, size); break;
    default: write_response(kernel_buffer, 1, 0); status = STATUS_SUCCESS; break;
    }

copy_out:
    // 4. Copiar de forma segura la respuesta de Kernel -> Usuario
    g_MmCopy( // Use the function pointer
        current_proc, kernel_buffer,
        current_proc, user_buffer,
        size, KernelMode, &bytes_moved
    );

    ExFreePoolWithTag(kernel_buffer, POOL_TAG_COMMS);
    return status;
}
