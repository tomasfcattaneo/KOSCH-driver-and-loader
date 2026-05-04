/* безликий */
#pragma once

#include <ntifs.h>
#include "../../shared_protocol.h" // Include the new shared header

NTSTATUS Dx_Route(PVOID buffer, ULONG size);
