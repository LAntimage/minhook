/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include "buffer.h"
#include "diagnostics.h"

// x64 trampolines must stay near their targets. Windows reservations start
// at 64 KiB boundaries, so 4 KiB blocks strand the remaining 60 KiB and can
// exhaust every usable address before a large hook set has been installed.
// Prefer the full allocation granule. Only after that search is exhausted,
// use a smaller page-aligned block that fits an available reservation base.
#if defined(_M_X64) || defined(__x86_64__)
    #define MEMORY_BLOCK_SIZE 0x10000
#else
    #define MEMORY_BLOCK_SIZE 0x1000
#endif

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        UINT8 buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First element of the free slot list.
    UINT usedCount;
    SIZE_T size;               // Actual allocation size, including the header.
    BOOL reserved;             // Keep early reservations until Uninitialize.
} MEMORY_BLOCK, *PMEMORY_BLOCK;

typedef char MEMORY_BLOCK_HEADER_FITS_SLOT[(sizeof(MEMORY_BLOCK) <= sizeof(MEMORY_SLOT)) ? 1 : -1];

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
PMEMORY_BLOCK g_pMemoryBlocks;

static SIZE_T QueryAllocationRegion(LPVOID address, MEMORY_BASIC_INFORMATION* info)
{
    SIZE_T result = VirtualQuery(address, info, sizeof(*info));
    DWORD error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    MemoryDiagnosticsQuery(address, result != 0, error);
    return result;
}

static PMEMORY_BLOCK AllocateMemoryBlock(LPVOID address, SIZE_T size)
{
    PMEMORY_BLOCK result = (PMEMORY_BLOCK)VirtualAlloc(
        address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD error = result == NULL ? GetLastError() : ERROR_SUCCESS;
    MemoryDiagnosticsAllocation(address, size, result, error);
    if (result != NULL) result->size = size;
    return result;
}

//-------------------------------------------------------------------------
VOID InitializeBuffer(VOID)
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
VOID UninitializeBuffer(VOID)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        VirtualFree(pBlock, 0, MEM_RELEASE);
        pBlock = pNext;
    }
}

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the previous allocation granularity multiply.
    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (QueryAllocationRegion((LPVOID)tryAddr, &mbi) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
            break;

        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (QueryAllocationRegion((LPVOID)tryAddr, &mbi) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static PMEMORY_BLOCK AllocateSmallerBlock(LPVOID address, ULONG_PTR maxAddress, DWORD pageSize)
{
    MEMORY_BASIC_INFORMATION info;
    SIZE_T available, size;
    ULONG_PTR start = (ULONG_PTR)address;
    PMEMORY_BLOCK block;

    // Re-query after the 64 KiB pass: another thread may have claimed this
    // address. Never commit into, split, or release another allocation.
    if (!QueryAllocationRegion(address, &info) || info.State != MEM_FREE ||
        start < (ULONG_PTR)info.BaseAddress || start > maxAddress)
        return NULL;
    available = info.RegionSize - (start - (ULONG_PTR)info.BaseAddress);
    if (available > maxAddress - start + 1) available = maxAddress - start + 1;
    size = MEMORY_BLOCK_SIZE - pageSize;
    if (size > available) size = available;
    size -= size % pageSize;

    // Prefer the largest useful block (e.g. the 60 KiB hole in the client log),
    // rather than stranding its remaining pages with an immediate 4 KiB retry.
    for (; size >= pageSize; size -= pageSize)
    {
        block = AllocateMemoryBlock(address, size);
        if (block != NULL) return block;
    }
    return NULL;
}

static PMEMORY_BLOCK FindAndAllocateBlock(LPVOID origin, ULONG_PTR minAddress, ULONG_PTR maxAddress,
    const SYSTEM_INFO* system, BOOL fallback)
{
    LPVOID candidate = origin;
    PMEMORY_BLOCK block;
    SIZE_T minimumSize = fallback ? system->dwPageSize : MEMORY_BLOCK_SIZE;
    ULONG_PTR maxBase = maxAddress - (minimumSize - 1);

    if (maxAddress < minimumSize - 1 || maxBase < minAddress) return NULL;

    while ((ULONG_PTR)candidate >= minAddress)
    {
        candidate = FindPrevFreeRegion(candidate, (LPVOID)minAddress, system->dwAllocationGranularity);
        if (candidate == NULL) break;
        block = fallback ? AllocateSmallerBlock(candidate, maxAddress, system->dwPageSize) :
            AllocateMemoryBlock(candidate, MEMORY_BLOCK_SIZE);
        if (block != NULL) return block;
    }
    candidate = origin;
    while ((ULONG_PTR)candidate <= maxBase)
    {
        candidate = FindNextFreeRegion(candidate, (LPVOID)maxBase, system->dwAllocationGranularity);
        if (candidate == NULL) break;
        block = fallback ? AllocateSmallerBlock(candidate, maxAddress, system->dwPageSize) :
            AllocateMemoryBlock(candidate, MEMORY_BLOCK_SIZE);
        if (block != NULL) return block;
    }
    return NULL;
}
#endif

//-------------------------------------------------------------------------
static VOID RegisterMemoryBlock(PMEMORY_BLOCK pBlock, BOOL reserved)
{
    PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
    pBlock->pFree = NULL;
    pBlock->usedCount = 0;
    pBlock->reserved = reserved;
    do
    {
        pSlot->pNext = pBlock->pFree;
        pBlock->pFree = pSlot;
        pSlot++;
    } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= pBlock->size - MEMORY_SLOT_SIZE);

    pBlock->pNext = g_pMemoryBlocks;
    g_pMemoryBlocks = pBlock;
}

static BOOL BlockInRange(PMEMORY_BLOCK block, ULONG_PTR minAddress, ULONG_PTR maxAddress)
{
    ULONG_PTR base = (ULONG_PTR)block;
    return base >= minAddress && base <= maxAddress && block->size - 1 <= maxAddress - base;
}

static VOID DescribeReservation(ULONG_PTR minAddress, ULONG_PTR maxAddress, MH_BUFFER_RESERVATION* result)
{
    PMEMORY_BLOCK block;
    ZeroMemory(result, sizeof(*result));
    for (block = g_pMemoryBlocks; block != NULL; block = block->pNext)
    {
        if (!block->reserved || !BlockInRange(block, minAddress, maxAddress)) continue;
        if (result->firstBlock == NULL)
        {
            result->firstBlock = block;
            result->firstBlockSize = block->size;
        }
        ++result->blockCount;
        result->totalBytes += block->size;
        result->capacity += block->size / MEMORY_SLOT_SIZE - 1;
        result->usedSlots += block->usedCount;
    }
}

BOOL ReserveHookBuffers(LPVOID firstTarget, LPVOID lastTarget, SIZE_T minimumSlots, MH_BUFFER_RESERVATION* result)
{
    SYSTEM_INFO system;
    ULONG_PTR minAddress, maxAddress;
    PMEMORY_BLOCK block;
    GetSystemInfo(&system);
    minAddress = (ULONG_PTR)system.lpMinimumApplicationAddress;
    maxAddress = (ULONG_PTR)system.lpMaximumApplicationAddress;
#if defined(_M_X64) || defined(__x86_64__)
    // Intersection of all targets' existing +/- 1 GiB windows. Every slot in
    // this pool must be reachable by every target, not just the first hook.
    if ((ULONG_PTR)lastTarget > MAX_MEMORY_RANGE && minAddress < (ULONG_PTR)lastTarget - MAX_MEMORY_RANGE)
        minAddress = (ULONG_PTR)lastTarget - MAX_MEMORY_RANGE;
    if ((ULONG_PTR)firstTarget <= maxAddress && maxAddress - (ULONG_PTR)firstTarget > MAX_MEMORY_RANGE)
        maxAddress = (ULONG_PTR)firstTarget + MAX_MEMORY_RANGE;
#else
    (void)firstTarget;
    (void)lastTarget;
#endif
    DescribeReservation(minAddress, maxAddress, result);
    if (maxAddress < minAddress || maxAddress - minAddress < system.dwPageSize - 1)
    {
        MemoryDiagnosticsBufferFailure();
        return FALSE;
    }
    MemoryDiagnosticsRange(minAddress, maxAddress - (MEMORY_BLOCK_SIZE - 1), MEMORY_BLOCK_SIZE, system.dwAllocationGranularity);
    while (result->capacity < minimumSlots)
    {
#if defined(_M_X64) || defined(__x86_64__)
        LPVOID origin = (LPVOID)((ULONG_PTR)firstTarget + ((ULONG_PTR)lastTarget - (ULONG_PTR)firstTarget) / 2);
        block = FindAndAllocateBlock(origin, minAddress, maxAddress, &system, FALSE);
        if (block == NULL && system.dwPageSize < MEMORY_BLOCK_SIZE)
        {
            MemoryDiagnosticsFallback(system.dwPageSize);
            block = FindAndAllocateBlock(origin, minAddress, maxAddress, &system, TRUE);
        }
#else
        block = AllocateMemoryBlock(NULL, MEMORY_BLOCK_SIZE);
#endif
        if (block == NULL)
        {
            MemoryDiagnosticsBufferFailure();
            return FALSE;
        }
        RegisterMemoryBlock(block, TRUE);
        DescribeReservation(minAddress, maxAddress, result);
    }
    return TRUE;
}

//-------------------------------------------------------------------------
static PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
    PMEMORY_BLOCK pBlock = NULL;
#if defined(_M_X64) || defined(__x86_64__)
    ULONG_PTR minAddr;
    ULONG_PTR maxAddr;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

    // pOrigin ± 1024MB
    if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE)
        minAddr = (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE;

    if (maxAddr > (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE)
        maxAddr = (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE;

    // Keep the original address window for both passes; smaller blocks may
    // also fit near its upper edge. Diagnostics retain the preferred size.
    MemoryDiagnosticsRange(minAddr, maxAddr - (MEMORY_BLOCK_SIZE - 1), MEMORY_BLOCK_SIZE, si.dwAllocationGranularity);
#else
    MemoryDiagnosticsRange(0, 0, MEMORY_BLOCK_SIZE, 0);
#endif

    // Look the registered blocks for a reachable one.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#if defined(_M_X64) || defined(__x86_64__)
        // Ignore the blocks too far.
        if (!BlockInRange(pBlock, minAddr, maxAddr))
            continue;
#endif
        // The block has at least one unused slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Exhaust the normal 64 KiB search in both directions before falling back.
    pBlock = FindAndAllocateBlock(pOrigin, minAddr, maxAddr, &si, FALSE);
    if (pBlock == NULL && si.dwPageSize < MEMORY_BLOCK_SIZE)
    {
        MemoryDiagnosticsFallback(si.dwPageSize);
        pBlock = FindAndAllocateBlock(pOrigin, minAddr, maxAddr, &si, TRUE);
    }
#else
    // In x86 mode, a memory block can be placed anywhere.
    pBlock = AllocateMemoryBlock(NULL, MEMORY_BLOCK_SIZE);
#endif

    if (pBlock != NULL)
    {
        RegisterMemoryBlock(pBlock, FALSE);
    }

    return pBlock;
}

//-------------------------------------------------------------------------
LPVOID AllocateBuffer(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
    {
        MemoryDiagnosticsBufferFailure();
        return NULL;
    }

    // Remove an unused slot from the list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
    return pSlot;
}

//-------------------------------------------------------------------------
VOID FreeBuffer(LPVOID pBuffer)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;

    while (pBlock != NULL)
    {
        // Blocks can have different sizes. Find the actual owner rather than
        // inferring it from a fixed-size block boundary.
        if ((ULONG_PTR)pBuffer >= (ULONG_PTR)pBlock + MEMORY_SLOT_SIZE &&
            (ULONG_PTR)pBuffer - (ULONG_PTR)pBlock < pBlock->size)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;
#ifdef _DEBUG
            // Clear the released slot for debugging.
            memset(pSlot, 0x00, sizeof(MEMORY_SLOT));
#endif
            // Restore the released slot to the list.
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            // Free if unused.
            if (pBlock->usedCount == 0 && !pBlock->reserved)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                VirtualFree(pBlock, 0, MEM_RELEASE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }
}

//-------------------------------------------------------------------------
BOOL IsExecutableAddress(LPVOID pAddress)
{
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(mi));

    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
