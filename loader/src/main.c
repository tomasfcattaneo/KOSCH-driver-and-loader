/* безликий */
#include "types.h"
#include "log.h"
#include "constants.h"
#include "nt_defs.h"
#include "tbt.h"
#include "sysinfo.h"
#include "krw.h"
#include "gate.h"
#include "pe.h"
#include "mapper.h"
#include "cleanup.h"
#include "xor.h"
#include "peb.h"
#include "crypt.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <tlhelp32.h>

#include "koshchei_drv.h"
#include "../../shared_protocol.h" // Include the new shared header

static void secure_free(void *ptr, size_t len)
{
    if (ptr) {
        memset(ptr, 0, len);
        free(ptr);
    }
}

static Result enable_privileges(void)
{
    void *ntdll = Peb_FindModule(H_ntdll_dll);
    PRtlAdjustPrivilege adjust =
        (PRtlAdjustPrivilege)Peb_FindExport(ntdll, H_RtlAdjustPrivilege);
    if (!adjust) return ERR(STATUS_ERR_PRIVILEGE, EMSG("privilege adjust failed"));

    BOOLEAN prev;
    adjust(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &prev);
    adjust(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &prev);
    return OK_VOID;
}

static Result driver_read_memory(NkCtx *gate, void *cmd_buf, uint64_t dispatch_va, uint32_t pid, uint64_t address, void *out_buffer, uint32_t size)
{
    if (size > (DX_BUF_SIZE - sizeof(DX_RSP))) return ERR(STATUS_ERR_IOCTL_FAILED, "Read size too large");

    memset(cmd_buf, 0, DX_BUF_SIZE);
    
    DX_READ *req = (DX_READ *)cmd_buf;
    req->hdr.magic = NX_MAGIC;
    req->hdr.cmd   = CMD_READ_MEMORY;
    req->hdr.size  = sizeof(DX_READ);
    req->pid       = pid;
    req->address   = address;
    req->length    = size;

    uint64_t call_ret = 0;
    TRY(Nk_Call(gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &call_ret));

    DX_RSP *resp = (DX_RSP *)cmd_buf;
    if (resp->magic != NX_MAGIC || resp->status != 0) {
        return ERR(STATUS_ERR_IOCTL_FAILED, "Driver read failed");
    }

    memcpy(out_buffer, resp->data, size);
    return OK_VOID;
}

static Result driver_get_peb_address(NkCtx *gate, void *cmd_buf, uint64_t dispatch_va, uint32_t pid, uint64_t *out_peb_addr)
{
    memset(cmd_buf, 0, DX_BUF_SIZE);

    DX_PEB *req = (DX_PEB *)cmd_buf;
    req->hdr.magic = NX_MAGIC;
    req->hdr.cmd   = CMD_GET_PEB;
    req->hdr.size  = sizeof(DX_PEB);
    req->pid       = pid;

    uint64_t call_ret = 0;
    TRY(Nk_Call(gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &call_ret));

    DX_RSP *resp = (DX_RSP *)cmd_buf;
    if (resp->magic != NX_MAGIC || resp->status != 0) {
        return ERR(STATUS_ERR_IOCTL_FAILED, "Get PEB address failed");
    }

    *out_peb_addr = resp->value;
    return OK_VOID;
}

static Result driver_get_module_base(NkCtx *gate, void *cmd_buf, uint64_t dispatch_va, uint32_t pid, const wchar_t *module_name, uint64_t *out_base)
{
    if (!module_name || !out_base) return ERR(STATUS_ERR_IOCTL_FAILED, "Invalid params");

    memset(cmd_buf, 0, DX_BUF_SIZE);

    DX_MODBASE *req = (DX_MODBASE *)cmd_buf;
    req->hdr.magic = NX_MAGIC;
    req->hdr.cmd   = CMD_GET_MODULE_BASE;
    req->hdr.size  = sizeof(DX_MODBASE);
    req->pid       = pid;
    wcscpy_s(req->module_name, 64, module_name);

    uint64_t call_ret = 0;
    TRY(Nk_Call(gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &call_ret));

    DX_RSP *resp = (DX_RSP *)cmd_buf;
    if (resp->magic != NX_MAGIC || resp->status != 0) {
        return ERR(STATUS_ERR_IOCTL_FAILED, "Get module base failed");
    }

    *out_base = resp->value;
    return OK_VOID;
}

static Result driver_hide_process(NkCtx *gate, void *cmd_buf, uint64_t dispatch_va, uint32_t pid)
{
    memset(cmd_buf, 0, DX_BUF_SIZE);

    DX_HIDE *req = (DX_HIDE *)cmd_buf;
    req->hdr.magic = NX_MAGIC;
    req->hdr.cmd   = CMD_HIDE_PROCESS;
    req->hdr.size  = sizeof(DX_HIDE);
    req->pid       = pid;

    uint64_t call_ret = 0;
    TRY(Nk_Call(gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &call_ret));

    DX_RSP *resp = (DX_RSP *)cmd_buf;
    if (resp->magic != NX_MAGIC || resp->status != 0) {
        return ERR(STATUS_ERR_IOCTL_FAILED, "Driver hide failed");
    }

    return OK_VOID;
}

static Result driver_pattern_scan(NkCtx *gate, void *cmd_buf, uint64_t dispatch_va, uint32_t pid, uint64_t start_address, uint64_t scan_length, const uint8_t *pattern, const uint8_t *mask, uint32_t pattern_length, uint64_t *out_found_address)
{
    if (pattern_length == 0 || pattern_length > 256) return ERR(STATUS_ERR_IOCTL_FAILED, "Invalid pattern length");
    // Ensure the entire request fits within the shared buffer
    if (sizeof(DX_PATTERN_SCAN) > DX_BUF_SIZE) return ERR(STATUS_ERR_IOCTL_FAILED, "Pattern scan request too large for buffer");

    memset(cmd_buf, 0, DX_BUF_SIZE);

    DX_PATTERN_SCAN *req = (DX_PATTERN_SCAN *)cmd_buf;
    req->hdr.magic = NX_MAGIC;
    req->hdr.cmd   = CMD_PATTERN_SCAN;
    req->hdr.size  = sizeof(DX_PATTERN_SCAN); // Size of the fixed struct
    req->pid       = pid;
    req->start_address = start_address;
    req->scan_length = scan_length;
    req->pattern_length = pattern_length;
    memcpy(req->pattern, pattern, pattern_length);
    memcpy(req->mask, mask, pattern_length);

    uint64_t call_ret = 0;
    TRY(Nk_Call(gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &call_ret));

    DX_RSP *resp = (DX_RSP *)cmd_buf;
    if (resp->magic != NX_MAGIC || resp->status != 0) {
        return ERR(STATUS_ERR_IOCTL_FAILED, "Driver pattern scan failed");
    }
    *out_found_address = resp->value;
    return OK_VOID;
}

static Result check_hypervisor(void)
{
    int info[4] = {0};
    __cpuid(info, 1);
    if ((info[2] >> 31) & 1)
        return ERR(STATUS_ERR_HYPERVISOR, EMSG("hypervisor present"));
    return OK_VOID;
}

static Result prefill_bootstrap(ZvCtx *tbt, MxImage *img, LxImage *pe, const uint8_t *raw,
                                void *cmd_buf)
{
    uint32_t data_raw = 0, data_rva = 0, data_size = 0;
    for (uint32_t i = 0; i < pe->section_count; i++) {
        if (memcmp(pe->sections[i].name, ".data", 5) == 0) {
            data_raw  = pe->sections[i].raw_offset;
            data_rva  = pe->sections[i].va;
            data_size = pe->sections[i].raw_size;
            break;
        }
    }
    if (!data_size)
        return ERR(STATUS_ERR_BOOTSTRAP_NOT_FOUND, EMSG("data section missing"));

    uint32_t offset = 0;
    bool found      = false;
    for (uint32_t i = 0; i + 16 <= data_size; i += 8) {
        const uint64_t *p = (const uint64_t *)(raw + data_raw + i);
        if (p[0] == NX_SENTINEL1 && p[1] == NX_SENTINEL2) {
            offset = i;
            found  = true;
            break;
        }
    }
    if (!found) return ERR(STATUS_ERR_BOOTSTRAP_NOT_FOUND, EMSG("sentinel missing"));

    VirtAddr bootstrap_va = img->base + data_rva + offset;

    uint8_t payload[32];
    uint64_t s1  = NX_SENTINEL1;
    uint64_t s2  = NX_SENTINEL2;
    uint64_t va  = (uint64_t)(uintptr_t)cmd_buf;
    uint32_t pid = GetCurrentProcessId();
    uint32_t flg = 1;

    memcpy(payload + 0, &s1, 8);
    memcpy(payload + 8, &s2, 8);
    memcpy(payload + 16, &va, 8);
    memcpy(payload + 24, &pid, 4);
    memcpy(payload + 28, &flg, 4);

    TRY(Px_Write(tbt, bootstrap_va, payload, 32));
    LOG_INF("  bootstrap written at 0x%llX (pid=%u)", bootstrap_va, pid);
    return OK_VAL(bootstrap_va);
}

int main(void)
{
#ifndef KOSHCHEI_RELEASE
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif
    void *cmd_buf  = NULL;
    bool driver_ok = false;
    LOG_INF("=== init ===");

    LOG_INF("[Step 0] privilege + environment checks");
    Result r = enable_privileges();
    if (IS_ERR(r)) {
        LOG_ERR("privileges: %s", r.msg);
        return 1;
    }

    r = check_hypervisor();
    if (IS_ERR(r)) LOG_WRN("hypervisor detected");

    LOG_INF("[Step 1] enumerating kernel modules");
    SxInfo ki;
    r = Sx_Init(&ki);
    if (IS_ERR(r)) {
        LOG_ERR("sysinfo: %s", r.msg);
        return 1;
    }

    LOG_INF("[Step 2] loading driver");
    ZvCtx tbt;
    r = Zv_Init(&tbt);
    if (IS_ERR(r)) {
        LOG_ERR("Zv_Init: %s", r.msg);
        Sx_Free(&ki);
        return 1;
    }

    LOG_INF("[Step 3] discovering ntoskrnl physical base");
    r = Sx_ResolveNtosPhys(&ki, &tbt);
    if (IS_ERR(r)) {
        LOG_ERR("ntos phys: %s", r.msg);
        goto cleanup;
    }

    LOG_INF("[Step 4] verifying kernel R/W");
    {
        uint16_t mz = 0;
        r           = Px_ReadU16(&tbt, ki.ntos_base, &mz);
        if (IS_ERR(r) || mz != 0x5A4D) {
            LOG_ERR("kernel R/W verification failed (mz=0x%04X)", mz);
            goto cleanup;
        }
        LOG_INF("  ntoskrnl MZ verified via VA read");
    }

    LOG_INF("[Step 5] installing NtClose gate");
    NkCtx gate;
    r = Nk_Init(&gate, &tbt, &ki);
    if (IS_ERR(r)) {
        LOG_ERR("Nk_Init: %s", r.msg);
        goto cleanup;
    }

    LOG_INF("[Step 6] parsing driver PE");
    uint8_t *driver_raw = xor_decrypt(koshchei_drv_data, koshchei_drv_size);
    if (!driver_raw) {
        LOG_ERR("driver decrypt failed");
        goto cleanup_gate;
    }

    LxImage pe;
    r = Lx_Parse(driver_raw, koshchei_drv_size, &pe);
    if (IS_ERR(r)) {
        LOG_ERR("Lx_Parse: %s", r.msg);
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    LOG_INF("[Step 7] mapping driver into kernel");
    MxImage img;
    r = Mx_Map(&tbt, &ki, driver_raw, koshchei_drv_size, &pe, &img);
    if (IS_ERR(r)) {
        LOG_ERR("mapper: %s", r.msg);
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    LOG_INF("[Step 8] pre-filling NX_BRIDGE");
    cmd_buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!cmd_buf) {
        LOG_ERR("cmd buffer alloc failed");
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    r = prefill_bootstrap(&tbt, &img, &pe, driver_raw, cmd_buf);
    secure_free(driver_raw, koshchei_drv_size);
    if (IS_ERR(r)) {
        LOG_ERR("bootstrap: %s", r.msg);
        goto cleanup_gate;
    }
    VirtAddr bootstrap_va = r.value;

    uint64_t dispatch_va = 0; // Declarar dispatch_va aquí para un ámbito más amplio
    LOG_INF("[Step 9] calling DriverEntry");
    {
        uint64_t entry_ret = 0;
        r                  = Nk_Call(&gate, img.entry, 0, 0, 0, &entry_ret);
        if (IS_ERR(r)) {
            LOG_ERR("Nk_Call DriverEntry: %s", r.msg);
            goto cleanup_gate;
        }
        LOG_INF("  DriverEntry returned 0x%llX", entry_ret);
        if ((int64_t)entry_ret < 0) {
            LOG_ERR("  DriverEntry failed with NTSTATUS 0x%08X", (uint32_t)entry_ret);
            goto cleanup_gate;
        }
    }

    {
        r                    = Px_ReadU64(&tbt, bootstrap_va + 32, &dispatch_va);
        if (IS_ERR(r) || dispatch_va == 0) {
            LOG_ERR("dispatch_va not found");
            goto cleanup_gate;
        }
        LOG_INF("[Step 10] dispatch_va=0x%llX", (unsigned long long)dispatch_va);

        uint64_t ping_ret = 0;
        memset(cmd_buf, 0, 4096);
        uint32_t magic = NX_MAGIC;
        uint32_t cmd   = 0;
        uint32_t size  = 12;
        memcpy((uint8_t *)cmd_buf + 0, &magic, 4);
        memcpy((uint8_t *)cmd_buf + 4, &cmd, 4);
        memcpy((uint8_t *)cmd_buf + 8, &size, 4);

        r = Nk_Call(&gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &ping_ret);
        if (IS_ERR(r)) {
            LOG_ERR("ping failed: %s", r.msg);
            goto cleanup_gate;
        }

        uint32_t resp_magic = 0, resp_status = 0;
        uint64_t resp_value = 0;
        memcpy(&resp_magic, (uint8_t *)cmd_buf + 0, 4);
        memcpy(&resp_status, (uint8_t *)cmd_buf + 4, 4);
        memcpy(&resp_value, (uint8_t *)cmd_buf + 8, 8);

        if (resp_magic == NX_MAGIC && resp_status == 0 &&
            resp_value == (uint64_t)NX_SEED) {
            LOG_INF("  ping OK");
        }
        else {
            LOG_ERR("  ping mismatch");
            goto cleanup_gate;
        }

        // Ejemplo de uso: Leer el MZ del propio ntoskrnl desde el Kernel
        uint16_t test_mz = 0;
        LOG_INF("[Step 10.1] Testing memory read via shared memory...");
        r = driver_read_memory(&gate, cmd_buf, dispatch_va, 4, ki.ntos_base, &test_mz, sizeof(test_mz));
        if (IS_OK(r) && test_mz == 0x5A4D) {
            LOG_INF("  Read via Shared Memory: OK (found MZ at ntoskrnl)");
        } else {
            LOG_ERR("  Read via Shared Memory: FAILED");
        }

        // Omitting Notepad tests to focus on HL.EXE

        // Test for pattern scanning (e.g., searching for ntoskrnl MZ header)
        LOG_INF("[Step 10.3] Testing pattern scan for ntoskrnl MZ header...");
        uint8_t mz_pattern[] = {0x4D, 0x5A}; // MZ in little-endian
        uint8_t mz_mask[]    = {0xFF, 0xFF};
        uint64_t found_mz_addr = 0;
        r = driver_pattern_scan(&gate, cmd_buf, dispatch_va, 4, ki.ntos_base, 0x1000, mz_pattern, mz_mask, sizeof(mz_pattern), &found_mz_addr);
        if (IS_OK(r)) {
            if (found_mz_addr == ki.ntos_base) {
                LOG_INF("  Pattern Scan: OK (found MZ at 0x%llX)", found_mz_addr);
            } else {
                LOG_ERR("  Pattern Scan: FAILED (found 0x%llX, expected 0x%llX)", found_mz_addr, ki.ntos_base);
            }
        } else {
            LOG_ERR("  Pattern Scan: FAILED: %s", r.msg);
        }
    }

    // --- NUEVO: Interacción con HL.EXE ---
    LOG_INF("[Step 10.4] Interacting with HL.EXE...");
    DWORD hl_pid = 0;
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snapshot, &entry)) {
                do {
                    if (_wcsicmp(entry.szExeFile, L"hl.exe") == 0) {
                        hl_pid = entry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
    }

    if (hl_pid == 0) {
        LOG_WRN("  HL.EXE process not found, skipping game interaction tests.");
    } else {
        LOG_INF("  Found HL.EXE with PID: %u", hl_pid);

        uint64_t hl_base_address = 0;
        r = driver_get_module_base(&gate, cmd_buf, dispatch_va, hl_pid, L"hl.exe", &hl_base_address);
        
        if (IS_OK(r) && hl_base_address != 0) {
            LOG_INF("  HL.EXE Base Address: 0x%llX", hl_base_address);
            
            // Intentar leer el MZ header de hl.exe
            uint16_t game_mz = 0;
            r = driver_read_memory(&gate, cmd_buf, dispatch_va, hl_pid, hl_base_address, &game_mz, 2);
            if (IS_OK(r) && game_mz == 0x5A4D) {
                LOG_INF("  Successfully read Game MZ Header!");
                
                // Ejemplo de Pattern Scan en un rango de 1MB desde la base
                LOG_INF("  Scanning for HL function pattern...");
                uint8_t hl_pat[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC }; // Típico prólogo de función x86
                uint8_t hl_msk[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                uint64_t found_at = 0;
                
                r = driver_pattern_scan(&gate, cmd_buf, dispatch_va, hl_pid, hl_base_address, 0x100000, 
                                        hl_pat, hl_msk, 5, &found_at);
                
                if (IS_OK(r) && found_at != 0) {
                    LOG_INF("  Pattern found in game at: 0x%llX", found_at);
                } else {
                    LOG_WRN("  Pattern not found in game memory.");
                }
            } else {
                LOG_ERR("  Failed to read game memory header.");
            }
        } else {
            LOG_ERR("  Could not resolve HL.EXE module base.");
        }
    }
    // --- FIN: Interacción con HL.EXE ---

    driver_ok = true;
    LOG_INF("[Step 11] cleaning traces");

    static const wchar_t drv_name[] = L"TBT_Force_Power_Control_Access64.sys";
    Cx_All(&tbt, &ki, drv_name);

    LOG_INF("[Step 12] cleanup, hold");

cleanup_gate:
    Nk_Cleanup(&gate);

cleanup:
    Zv_Cleanup(&tbt);
    Sx_Free(&ki);

    if (driver_ok && cmd_buf) {
        while (1) Sleep(60000);
    }

    return IS_OK(r) ? 0 : 1;
}
