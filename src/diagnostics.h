#pragma once

#include "../include/MinHook.h"

// Internal helpers. All are called while MinHook's existing spin lock is held.
VOID MemoryDiagnosticsRange(ULONG_PTR minAddress, ULONG_PTR maxAddress, SIZE_T blockSize, DWORD granularity);
VOID MemoryDiagnosticsQuery(LPVOID address, BOOL success, DWORD error);
VOID MemoryDiagnosticsAllocation(LPVOID address, SIZE_T size, LPVOID result, DWORD error);
VOID MemoryDiagnosticsFallback(SIZE_T minimumBlockSize);
VOID MemoryDiagnosticsBufferFailure(VOID);
