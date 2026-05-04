/* безликий */
#pragma once

#include <stdint.h>

#pragma warning(push)
#pragma warning(disable : 4200) // Disable warning for zero-sized array in struct

#define DX_BUF_SIZE 4096

enum
{
    CMD_PING = 0,
    CMD_READ_MEMORY,
    CMD_WRITE_MEMORY,
    CMD_GET_MODULE_BASE,
    CMD_GET_PEB,
    CMD_HIDE_PROCESS,
    CMD_UNHIDE_PROCESS,
    CMD_HIDE_DRIVER,
    CMD_TRANSLATE_VA,
    CMD_QUERY_STATE,
    CMD_PATTERN_SCAN,
    CMD_MAX
};

typedef struct
{
    uint32_t magic;
    uint32_t cmd;
    uint32_t size;
} DX_HDR;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} DX_READ;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t data[];
} DX_WRITE;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    wchar_t module_name[64];
} DX_MODBASE;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
} DX_PEB, DX_HIDE;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    uint64_t address;
} DX_XLATE;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    uint64_t start_address;
    uint64_t scan_length;
    uint32_t pattern_length;
    uint8_t pattern[256]; // Max pattern length
    uint8_t mask[256];    // Max mask length
} DX_PATTERN_SCAN;

typedef struct
{
    uint32_t magic;
    uint32_t status;
    uint64_t value;
    uint8_t data[];
} DX_RSP;

#pragma warning(pop)